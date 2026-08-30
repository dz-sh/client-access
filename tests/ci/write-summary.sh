#!/bin/bash
set -euo pipefail

title=${1:?summary title is required}
evidence=${2:?evidence description is required}
result=${3:-${JOB_STATUS:-unknown}}

{
  printf '### %s\n\n' "${title}"
  printf '| Field | Value |\n'
  printf '|---|---|\n'
  printf '| Commit | `%s` |\n' "${GITHUB_SHA}"
  printf '| Evidence | %s |\n' "${evidence}"
  printf '| Result | `%s` |\n' "${result}"
} >>"${GITHUB_STEP_SUMMARY}"
