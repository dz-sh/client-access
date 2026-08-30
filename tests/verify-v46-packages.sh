#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

artifact_root=${1:?usage: verify-v46-packages.sh ARTIFACT_ROOT EVIDENCE_DIR}
evidence_dir=${2:?usage: verify-v46-packages.sh ARTIFACT_ROOT EVIDENCE_DIR}
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$evidence_dir" "$work_dir/container" "$work_dir/control" "$work_dir/root"

sh "$(dirname "$0")/verify-v45-packages.sh" "$artifact_root" \
	"$evidence_dir/v45-package-evidence"
grep -Eq '^/usr/share/ucode/client_access/sfo_runtime\.uc$' \
	"$evidence_dir/v45-package-evidence/client-access-core.files"
grep -Eq '^/usr/share/ucode/client_access/sfo_manager\.uc$' \
	"$evidence_dir/v45-package-evidence/client-access-core.files"

package=$(find "$artifact_root" -type f -name 'client-access-sfo_*.ipk' -print -quit)
test -n "$package" || {
	echo 'missing package: client-access-sfo' >&2
	exit 1
}

if tar -tf "$package" >/dev/null 2>&1; then
	tar -xf "$package" -C "$work_dir/container"
elif ar t "$package" >/dev/null 2>&1; then
	(
		cd "$work_dir/container"
		ar x "$package"
	)
else
	echo "unsupported IPK container format: $package" >&2
	exit 1
fi

extract_archive() {
	archive=$1
	destination=$2
	case "$archive" in
	*.gz) tar -xzf "$archive" -C "$destination" ;;
	*.zst) zstd -dc "$archive" | tar -x -C "$destination" ;;
	*.xz) tar -xJf "$archive" -C "$destination" ;;
	*) tar -xf "$archive" -C "$destination" ;;
	esac
}

control_archive=$(find "$work_dir/container" -maxdepth 1 -type f \
	-name 'control.tar*' -print -quit)
data_archive=$(find "$work_dir/container" -maxdepth 1 -type f \
	-name 'data.tar*' -print -quit)
test -n "$control_archive"
test -n "$data_archive"
extract_archive "$control_archive" "$work_dir/control"
extract_archive "$data_archive" "$work_dir/root"

(
	cd "$work_dir/root"
	find . \( -type f -o -type l \) -print | sed 's#^\./#/#' | sort
) >"$evidence_dir/client-access-sfo.files"
cp "$work_dir/control/control" "$evidence_dir/client-access-sfo.control"
for script in postinst postinst-pkg prerm prerm-pkg postrm; do
	if [ -f "$work_dir/control/$script" ]; then
		cp "$work_dir/control/$script" "$evidence_dir/client-access-sfo.$script"
	fi
done

test "$(wc -l <"$evidence_dir/client-access-sfo.files" | tr -d ' ')" -eq 1
grep -Eq '^/usr/sbin/client-access-sfoctl$' \
	"$evidence_dir/client-access-sfo.files"
dependencies=$(sed -n 's/^Depends:[[:space:]]*//p' \
	"$evidence_dir/client-access-sfo.control")
printf '%s\n' "$dependencies" | grep -Eq '(^|, )client-access-core(,|$)'
printf '%s\n' "$dependencies" | grep -Eq '(^|, )client-access-bpf(,|$)'
printf '%s\n' "$dependencies" | grep -Eq '(^|, )libnetfilter-conntrack3(,|$)'
grep -Eq 'client-access-sfoctl baseline [0-9]+' \
	"$evidence_dir/client-access-sfo.prerm-pkg"
! grep -Eq '/etc/config|uci |flow_offloading|flow_offloading_hw' \
	"$evidence_dir/client-access-sfo.postinst-pkg" \
	"$evidence_dir/client-access-sfo.prerm-pkg" \
	"$evidence_dir/client-access-sfo.postrm"

printf '%s\n' 'V4.6 optional SFO package ownership and lifecycle checks passed.' \
	>"$evidence_dir/result.txt"
