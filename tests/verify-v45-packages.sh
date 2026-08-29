#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

artifact_root=${1:?usage: verify-v45-packages.sh ARTIFACT_ROOT EVIDENCE_DIR}
evidence_dir=${2:?usage: verify-v45-packages.sh ARTIFACT_ROOT EVIDENCE_DIR}
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$evidence_dir"

find_package() {
	name=$1
	package=$(find "$artifact_root" -type f -name "${name}_*.ipk" -print -quit)
	if [ -z "$package" ]; then
		echo "missing package: $name" >&2
		exit 1
	fi
	printf '%s\n' "$package"
}

extract_member() {
	package=$1
	member=$2
	destination=$3
	case "$member" in
		*.gz) ar p "$package" "$member" | tar -xz -C "$destination" ;;
		*.zst) ar p "$package" "$member" | zstd -dc | tar -x -C "$destination" ;;
		*) ar p "$package" "$member" | tar -x -C "$destination" ;;
	esac
}

extract_package() {
	name=$1
	package=$2
	directory="$work_dir/$name"
	mkdir -p "$directory/control" "$directory/root"
	control_member=$(ar t "$package" | sed -n '/^control\.tar/{p;q;}')
	data_member=$(ar t "$package" | sed -n '/^data\.tar/{p;q;}')
	test -n "$control_member"
	test -n "$data_member"
	extract_member "$package" "$control_member" "$directory/control"
	extract_member "$package" "$data_member" "$directory/root"
	(
		cd "$directory/root"
		find . \( -type f -o -type l \) -print | sed 's#^\.#/#' | sort
	) >"$evidence_dir/$name.files"
	cp "$directory/control/control" "$evidence_dir/$name.control"
	bytes=$(wc -c <"$package" | tr -d ' ')
	installed_kib=$(du -sk "$directory/root" | awk '{print $1}')
	printf '%s\t%s\t%s\t%s\n' "$name" "$bytes" "$installed_kib" "$package" \
		>>"$evidence_dir/packages.tsv"
}

assert_contains() {
	file=$1
	pattern=$2
	grep -Eq "$pattern" "$file" || {
		echo "$file does not contain required pattern: $pattern" >&2
		exit 1
	}
}

assert_excludes() {
	file=$1
	pattern=$2
	if grep -Eq "$pattern" "$file"; then
		echo "$file contains forbidden pattern: $pattern" >&2
		exit 1
	fi
}

core_package=$(find_package client-access-core)
luci_package=$(find_package luci-app-client-access)
bpf_package=$(find_package client-access-bpf)
: >"$evidence_dir/packages.tsv"
extract_package client-access-core "$core_package"
extract_package luci-app-client-access "$luci_package"
extract_package client-access-bpf "$bpf_package"

core_files="$evidence_dir/client-access-core.files"
luci_files="$evidence_dir/luci-app-client-access.files"
bpf_files="$evidence_dir/client-access-bpf.files"
core_control="$evidence_dir/client-access-core.control"
luci_control="$evidence_dir/luci-app-client-access.control"
bpf_control="$evidence_dir/client-access-bpf.control"

assert_contains "$core_files" '^/etc/config/client_access$'
assert_contains "$core_files" '^/usr/sbin/client-accessd$'
assert_contains "$core_files" '^/usr/share/ucode/client_access/classification_ir\.uc$'
assert_contains "$core_files" '^/usr/share/ucode/client_access/application_reconcile\.uc$'
assert_contains "$core_files" '^/usr/share/nftables\.d/'
assert_excludes "$core_files" '^/www/'
assert_excludes "$core_files" '^/usr/(lib/bpf|sbin/client-access-bpfctl)'

assert_contains "$luci_files" '^/www/luci-static/resources/view/client-access/policies\.js$'
assert_contains "$luci_files" '^/www/luci-static/resources/client-access/status\.js$'
assert_contains "$luci_files" '^/usr/share/(luci/menu\.d|rpcd/acl\.d)/'
assert_excludes "$luci_files" '^/etc/config/'
assert_excludes "$luci_files" '^/usr/(sbin/client-accessd|share/ucode|share/nftables\.d|lib/bpf)'

assert_contains "$bpf_files" '^/usr/sbin/client-access-bpfctl$'
assert_contains "$bpf_files" '^/usr/lib/bpf/client-access-bpf\.o$'
assert_excludes "$bpf_files" '^/(etc/config|www|usr/share/ucode|usr/share/nftables\.d)'

assert_contains "$luci_control" '^Depends:.*client-access-core'
assert_contains "$bpf_control" '^Depends:.*client-access-core'
assert_excludes "$bpf_control" 'luci-app-client-access'
assert_excludes "$core_control" 'luci-|libbpf|kmod-sched-bpf'

for left in client-access-core luci-app-client-access client-access-bpf; do
	for right in client-access-core luci-app-client-access client-access-bpf; do
		[ "$left" = "$right" ] && continue
		overlap="$work_dir/${left}-${right}.overlap"
		comm -12 "$evidence_dir/$left.files" "$evidence_dir/$right.files" >"$overlap"
		test ! -s "$overlap" || {
			echo "file ownership overlaps between $left and $right" >&2
			cat "$overlap" >&2
			exit 1
		}
	done
done

assert_excludes "$work_dir/luci-app-client-access/control/postinst" \
	'client-access|firewall|bpfctl'
assert_excludes "$work_dir/luci-app-client-access/control/postrm" \
	'client-access|firewall|bpfctl'
assert_contains "$work_dir/client-access-bpf/control/prerm" \
	'client-access-bpfctl disable'
assert_contains "$work_dir/client-access-bpf/control/prerm" \
	'client-access-bpfctl unload'

compose() {
	name=$1
	shift
	directory="$work_dir/composition-$name"
	mkdir -p "$directory"
	for package in "$@"; do
		cp -a "$work_dir/$package/root/." "$directory/"
	done
	(
		cd "$directory"
		find . \( -type f -o -type l \) -print | sed 's#^\.#/#' | sort
	) >"$evidence_dir/composition-$name.files"
}

compose core-only client-access-core
compose luci-no-bpf client-access-core luci-app-client-access
compose headless-bpf client-access-core client-access-bpf
compose full client-access-core luci-app-client-access client-access-bpf

assert_excludes "$evidence_dir/composition-core-only.files" '^/www/|client-access-bpf'
assert_contains "$evidence_dir/composition-luci-no-bpf.files" '^/usr/sbin/client-accessd$'
assert_contains "$evidence_dir/composition-luci-no-bpf.files" '^/www/'
assert_excludes "$evidence_dir/composition-luci-no-bpf.files" 'client-access-bpf'
assert_contains "$evidence_dir/composition-headless-bpf.files" '^/usr/sbin/client-accessd$'
assert_contains "$evidence_dir/composition-headless-bpf.files" '^/usr/sbin/client-access-bpfctl$'
assert_excludes "$evidence_dir/composition-headless-bpf.files" '^/www/'

printf '%s\n' 'V4.5 package ownership and composition checks passed.' \
	>"$evidence_dir/result.txt"
