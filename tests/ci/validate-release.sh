#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_dir=${1:?repository path is required}
requested_tag=${2-}
requested_commit=${3:?commit is required}

read_value() {
	local key=$1
	local file=$2
	local value

	value=$(sed -n "s/^${key}:=//p" "${file}")
	if [[ -z ${value} || ${value} == *$'\n'* ]]; then
		echo "${file} must declare ${key} exactly once" >&2
		exit 1
	fi
	printf '%s\n' "${value}"
}

version_file=${repo_dir}/version.mk
version=$(read_value CLIENT_ACCESS_VERSION "${version_file}")
package_release=$(read_value CLIENT_ACCESS_RELEASE "${version_file}")

release_version='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
if [[ ! ${version} =~ ^${release_version}$ ]]; then
	echo "invalid CLIENT_ACCESS_VERSION: ${version}" >&2
	exit 1
fi
if [[ ! ${package_release} =~ ^[1-9][0-9]*$ ]]; then
	echo "invalid CLIENT_ACCESS_RELEASE: ${package_release}" >&2
	exit 1
fi

tag=${requested_tag:-v${version}}
if [[ ! ${tag} =~ ^v${release_version}$ ]]; then
	echo "release tag must use vMAJOR.MINOR: ${tag}" >&2
	exit 1
fi
if [[ ${tag} != "v${version}" ]]; then
	echo "release tag ${tag} does not match source version ${version}" >&2
	exit 1
fi

commit=$(git -C "${repo_dir}" rev-parse "${requested_commit}^{commit}")
if ! git -C "${repo_dir}" merge-base --is-ancestor \
	"${commit}" refs/remotes/origin/main; then
	echo "release commit is not in the main branch history: ${commit}" >&2
	exit 1
fi

printf 'version=%s\n' "${version}"
printf 'package_release=%s\n' "${package_release}"
printf 'tag=%s\n' "${tag}"
printf 'commit=%s\n' "${commit}"
