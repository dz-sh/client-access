#!/bin/bash
set -euo pipefail

remote_url=${1:?remote URL is required}
revision=${2:?revision is required}
destination=${3:?destination path is required}

git init --quiet "${destination}"
git -C "${destination}" remote add origin "${remote_url}"
git -C "${destination}" fetch --quiet --depth=1 origin "${revision}"
git -C "${destination}" checkout --quiet --detach FETCH_HEAD
test "$(git -C "${destination}" rev-parse HEAD)" = "${revision}"
