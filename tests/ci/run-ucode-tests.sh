#!/bin/bash
set -euo pipefail

repo_dir=${1:?repository path is required}
ucode_bin=${2:?ucode binary is required}
module_dir=${repo_dir}/root/usr/share/ucode

for test_file in \
  policy.uc \
  app_policy.uc \
  classification.uc \
  runtime.uc \
  lease.uc \
  sfo_manager.uc \
  reconcile.uc \
  commit.uc \
  status.uc; do
  TZ=UTC "${ucode_bin}" -L "${module_dir}" "${repo_dir}/tests/${test_file}"
done

"${ucode_bin}" -c \
  -o "${RUNNER_TEMP}/client-accessd.ucb" \
  -L "${repo_dir}/tests/stubs" \
  -L "${module_dir}" \
  "${repo_dir}/root/usr/sbin/client-accessd"

for scenario in \
  restart_prune \
  fw4_restore \
  interface_add \
  interface_remove \
  interface_repair \
  projection_failure \
  generation_nonreuse \
  runtime_generation_floor \
  health_failure \
  status_health_failure \
  ensure_failure \
  attach_failure \
  sync_failure \
  nft_scope_failure \
  prune_failure \
  offload_software \
  sfo_tracking_only \
  sfo_capacity \
  sfo_health_failure \
  offload_missing \
  offload_hardware \
  offload_custom \
  sfo_access_revoke \
  sfo_application_revoke \
  sfo_deadline_failure \
  access_approval \
  access_revoke \
  application_approval \
  application_revoke \
  approval_journal_restart \
  router_reboot \
  journal_corruption \
  journal_write_failure \
  approval_noop; do
  output=${RUNNER_TEMP}/client-accessd-${scenario}.json
  CA_DAEMON_TEST_SCENARIO="${scenario}" \
    "${ucode_bin}" \
    -L "${repo_dir}/tests/stubs" \
    -L "${module_dir}" \
    "${repo_dir}/root/usr/sbin/client-accessd" >"${output}"
  jq -e --arg scenario "${scenario}" '.scenario == $scenario' "${output}"
done
