#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_dir=${1:?repository path is required}
openwrt_artifacts=${2:?OpenWrt artifact directory is required}
immortalwrt_artifacts=${3:?ImmortalWrt artifact directory is required}
output_dir=${4:?output directory is required}
tag=${5:?release tag is required}
commit=${6:?git commit is required}

version=$(sed -n 's/^CLIENT_ACCESS_VERSION:=//p' "${repo_dir}/version.mk")
package_release=$(sed -n 's/^CLIENT_ACCESS_RELEASE:=//p' "${repo_dir}/version.mk")
if [[ ${tag} != "v${version}" ]]; then
	echo "bundle tag ${tag} does not match source version ${version}" >&2
	exit 1
fi

mkdir -p "${output_dir}"
if find "${output_dir}" -mindepth 1 -print -quit | read -r _; then
	echo "release output directory must be empty: ${output_dir}" >&2
	exit 1
fi

work_dir=$(mktemp -d)
trap 'rm -rf "${work_dir}"' EXIT

packages=(
	client-access-core
	client-access-bpf
	client-access-sfo
	luci-app-client-access
	luci-i18n-client-access-zh-cn
)

assemble_platform() {
	local source_dir=$1
	local platform=$2
	local sdk_version=$3
	local target=$4
	local bundle_id=$5
	local package_dir=${work_dir}/${bundle_id}
	local package_name
	local package_path
	local package_file
	local bundle=${output_dir}/client-access-${tag}-${bundle_id}.tar.gz
	local -a matches

	mkdir -p "${package_dir}"
	for package_name in "${packages[@]}"; do
		mapfile -t matches < <(find "${source_dir}" -type f \
			-name "${package_name}_${version}*.ipk" -print | sort)
		if (( ${#matches[@]} != 1 )); then
			echo "${bundle_id}: expected one ${package_name} ${version} package, found ${#matches[@]}" >&2
			exit 1
		fi
		package_path=${matches[0]}
		package_file=$(basename "${package_path}")
		if [[ -e ${package_dir}/${package_file} ]]; then
			echo "${bundle_id}: duplicate package filename ${package_file}" >&2
			exit 1
		fi
		cp "${package_path}" "${package_dir}/${package_file}"
	done

	{
		printf 'Client Access: %s\n' "${version}"
		printf 'Package release: %s\n' "${package_release}"
		printf 'Git tag: %s\n' "${tag}"
		printf 'Git commit: %s\n' "${commit}"
		printf 'Platform: %s\n' "${platform}"
		printf 'SDK: %s\n' "${sdk_version}"
		printf 'Target: %s\n' "${target}"
		printf '\nPackages (SHA-256):\n'
		(
			cd "${package_dir}"
			sha256sum -- *.ipk | LC_ALL=C sort -k2
		)
	} >"${package_dir}/MANIFEST"

	tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 \
		--numeric-owner -C "${package_dir}" -cf - . | gzip -n >"${bundle}"
}

assemble_platform "${openwrt_artifacts}" \
	'OpenWrt' '24.10.8' 'x86_64' 'openwrt-24.10.8-x86_64'
assemble_platform "${immortalwrt_artifacts}" \
	'ImmortalWrt' '24.10.6' 'x86_64' 'immortalwrt-24.10.6-x86_64'

(
	cd "${output_dir}"
	sha256sum -- client-access-*.tar.gz | LC_ALL=C sort -k2 >SHA256SUMS
)

printf 'release_bundle_count=2\n'
