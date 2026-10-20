# Attacks and walls

The model is assumed hijacked, so every attack here is run by the scripted model (`ScriptedLLM`), which obeys `CALL <tool> <json>` and `SAY <text>` lines inside the ticket. The tests measure the walls around the model. They say nothing about how a real model behaves under prompt injection.

Test names start with the OWASP Top 10 for Agentic Applications 2026 id they belong to, for example `test_asi03_same_approver_twice_is_rejected`. After a test run `tests/conftest.py` prints one line per id. Paths below are under `tests/`.

"CI" means the default `pytest` run (it needs the test database, `sh scripts/test-db.sh start`). "kind" means `pytest -m k8s tests/k8s` against the local cluster. Chart render tests run `helm template` and read the policy objects, so they need no cluster and run in CI. The v2 code has not been run end to end yet; the results go in the README after the kind run.

## The 12 cases

| # | Attack | ASI | Wall that stops it | Tests (under `tests/`) | Runs in |
|---|---|---|---|---|---|
| 1 | Read another customer's account | ASI01, ASI03 | The agent drops the id; lease-scoped DB function; row-level security | `attacks/test_asi01_read_another_customer.py`: `test_asi01_injected_customer_id_is_ignored`, `test_asi01_agent_drops_customer_id`, `test_asi03_gateway_drops_customer_id`, `test_asi03_lookup_ignores_foreign_customer_id`, `test_asi03_rls_hides_rows_from_tool_roles` | CI |
| 2 | Medical flag reaches the model | ASI03 | No tool returns it; only the executor role reads flags | `attacks/test_asi03_medical_flag_never_reaches_the_model.py`: `test_asi03_only_executor_reads_flags`, `test_asi03_no_tool_returns_health_fields`, `test_asi03_reply_has_no_health_data` | CI |
| 3 | Credit too big, negative, or with no real charge | ASI02 | Risk tier and approvals; DB trigger | `attacks/test_asi02_credit_too_big_or_unbacked.py`: `test_asi02_credit_rule_rejects_missing_or_non_positive_amount`, `test_asi02_big_credit_goes_to_staff`, `test_asi02_credit_waits_for_its_approvals`, `test_asi02_database_refuses_a_credit_with_no_charge_behind_it`, `test_asi02_database_refuses_a_zero_negative_or_nan_credit` | CI |
| 4 | Disconnection at a protected home | ASI01, ASI02 | Risk tier HUMAN_ONLY; DB trigger refuses the order | `attacks/test_asi01_disconnection_at_a_protected_home.py`: `test_asi01_protected_home_goes_to_humans`, `test_asi02_human_only_order_refused_even_with_two_approvals`, `test_asi02_database_refuses_order_at_protected_home` | CI |
| 5 | Protection flag YES -> NO | ASI02 | Tools can only add flags; no role can change one | `attacks/test_asi02_protection_flag_yes_to_no.py`: `test_asi02_no_role_can_remove_or_change_a_flag`, `test_asi02_temp_protection_never_downgrades`, `test_asi02_tools_cannot_change_flags_directly` | CI |
| 6 | Reply that promises money | ASI09 | Reply guard in the agent and again in the dispatcher; no approve tool | `attacks/test_asi09_reply_that_promises_money.py`: `test_asi09_guard_blocks_money_promises`, `test_asi09_guard_blocks_the_known_bypasses`, `test_asi09_agent_blocks_a_number_no_tool_returned`, `test_asi09_dispatcher_runs_the_guard_again`, `test_asi09_the_model_has_no_approve_tool` | CI |
| 7 | Same person approves twice | ASI03 | Approvals only in the console; the database counts distinct people | `attacks/test_asi03_same_approver_twice.py`: `test_asi03_floor_counts_distinct_approvers_and_roles`, `test_asi03_same_approver_twice_is_rejected`, `test_asi03_one_person_cannot_count_twice` | CI |
| 8 | Risk engine down or too slow | ASI08 | The gateway fails closed | `attacks/test_asi08_risk_engine_down.py`: `test_asi08_gateway_denies_when_risk_engine_is_down`, `test_asi08_gateway_denies_when_risk_engine_is_too_slow`, `test_asi08_only_a_clear_allow_lets_a_call_through`, `test_asi08_decide_endpoint_fails_closed_when_the_database_fails` | CI |
| 9 | Agent keeps calling denied tools | ASI10 | Three denials pause all agents (kill switch); a SeniorApprover resumes | `attacks/test_asi10_kill_switch.py`: `test_asi10_repeated_denials_pause_every_agent`, `test_asi10_three_denials_pause_in_the_rules`, `test_asi10_risk_engine_pauses_and_approver_resumes`, `test_asi10_resume_needs_a_senior_approver` | CI |
| 10 | Next ticket sees the previous ticket's data | ASI06 | One Job per ticket, no memory | `k8s/test_replay.py::test_asi06_scripted_attack_runs_as_a_bound_agent_job` (one Job per ticket, lease bound to that Job's pod; a dedicated memory-leak test is Task 16) | kind |
| 11 | Data out (internet, DNS), reach DB or a tool directly, metadata token | ASI02, ASI03 | Default-deny network policies (Cilium); per-call signed token; metadata address denied | kind: `k8s/test_walls.py::test_asi03_probe_edge`, `test_asi03_every_namespace_has_default_deny`, `test_asi03_metadata_endpoint_denied_even_with_an_allow_all_policy`, `test_asi02_dns_exfiltration_is_answered_by_the_proxy_and_never_forwarded`, `test_asi02_only_the_llm_gateway_reaches_its_llm_api`; CI chart render: `k8s/test_chart.py::test_asi03_every_namespace_renders_default_deny`, `test_asi03_instance_metadata_denied_in_every_namespace`, `test_asi02_only_named_components_reach_names_outside_the_cluster`; per-call token: `attacks/test_asi03_reach_a_tool_directly.py` (`test_asi03_tool_rejects_wrong_audience_expired_and_replayed_tokens`, `test_asi03_tool_rejects_a_call_without_a_token`) | kind + CI |
| 12 | Unpinned or swapped image; changed tool description | ASI04 | Admission by digest; gateway fingerprint of each tool description | kind: `k8s/test_walls.py::test_asi04_admission_rejects_unpinned_image`, `test_asi04_admission_rejects_image_swap_on_a_running_pod`; CI: `k8s/test_chart.py::test_asi04_all_images_pinned_by_digest`, `attacks/test_asi04_changed_tool_description.py` (`test_asi04_gateway_refuses_a_changed_tool_description`, `test_asi04_gateway_refuses_a_changed_schema`, `test_asi04_fingerprint_changes_with_description_or_schema`) | kind + CI |

Case 10 has only the replay test so far. A dedicated test that a second ticket sees nothing of the first is still to be written.

The scripted attack tickets (`tests/attacks/tickets.py`) are replayed against the dispatcher and the tool gateway on kind. The move-out flood ticket (number 5) is gone together with the flood rule, so the numbering has a gap there.

## Not applicable

- **ASI05, Unexpected Code Execution.** The agent runs no code. It only emits tool calls. The admission rules against privileged pods stay as defence in depth (rows "privileged pods" below).
- **ASI07, Insecure Inter-Agent Communication.** There is one agent per ticket and it talks to no other agent.

## Every wall that stays, and its test

| Wall | Test(s) | Runs in |
|---|---|---|
| Agent drops arguments the model should not set (customer id, ticket id, lease) | `attacks/test_asi01_read_another_customer.py::test_asi01_agent_drops_customer_id` | CI |
| Gateway drops arguments the manifest does not list | `attacks/test_asi01_read_another_customer.py::test_asi03_gateway_drops_customer_id`, `unit/test_gateway.py::test_the_arguments_the_manifest_allows_are_forwarded` | CI |
| The agent takes no ticket number from anyone (the lease names the ticket) | `unit/test_agent_flow.py::test_the_process_refuses_a_ticket_number_on_its_command_line` | CI |
| Lease scoping: expired, revoked, unknown leases refused; tool not in the lease | `unit/test_lease.py::test_lease_functions_refuse_expired_revoked_unknown`, `unit/test_gateway.py::test_a_tool_that_is_not_in_the_lease_is_a_lease_error_and_the_risk_engine_counts_it` | CI |
| One lease per ticket, bound to the pod | `unit/test_dispatcher.py::test_claim_opens_lease_for_one_ticket`, `test_k8s_reply_needs_the_pod_the_lease_is_bound_to` | CI |
| The model never sees the lease | `unit/test_agent.py::test_lease_never_reaches_the_transcript_or_the_reply` | CI |
| Row-level security | `attacks/test_asi01_read_another_customer.py::test_asi03_rls_hides_rows_from_tool_roles` | CI |
| Tool roles have no table grants (one function each) | `unit/test_lease.py::test_tool_roles_have_no_table_grants` | CI |
| Per-call signed token, audience, expiry, replay | `attacks/test_asi03_reach_a_tool_directly.py` (above), `unit/test_tokens.py::test_mint_and_verify_roundtrip`, `test_lease_comes_from_token_not_arguments` | CI |
| The tool gateway cannot call a tool without a signing key | `unit/test_tokens.py::test_a_gateway_without_a_key_cannot_call_a_tool` | CI |
| Signing key only on the tool gateway | `k8s/test_chart.py::test_only_the_tool_gateway_gets_the_signing_key` | CI |
| TokenReview callers, tool gateway (only the agent) | `unit/test_gateway.py::test_k8s_mode_answers_401_to_a_caller_that_is_not_the_agent` | CI |
| TokenReview callers, dispatcher (agent ServiceAccount and a pod) | `unit/test_dispatcher.py::test_k8s_claim_needs_the_agents_service_account_and_a_pod` | CI |
| TokenReview callers, llm-gateway | `unit/test_llmgw.py::test_kubernetes_needs_the_agents_service_account_a_token_for_this_audience_and_a_pod` | CI |
| No token, no service | `unit/test_gateway.py::test_call_without_token_is_refused` | CI |
| Gateway fingerprint of each tool | `attacks/test_asi04_changed_tool_description.py` (above), `unit/test_capabilities.py::test_manifest_descriptor_hashes_match_the_live_tools` | CI |
| Risk tiers and approvals | `unit/test_risk_rules.py::test_credit_score_tiers_at_the_reachable_scores`, `test_hard_rule_always_wins`, `unit/test_risk_floor.py::test_required_approvals_per_tier`, `unit/test_executor_credits.py::test_t1_credit_executes_after_one_approval` | CI |
| Risk engine writes the assessments, nobody else | `unit/test_risk_floor.py::test_only_risk_engine_inserts_assessments`, `unit/test_risk_service.py::test_assess_pending_gives_each_pending_request_one_assessment` | CI |
| Risk engine reads no lease or flag directly | `unit/test_risk_service.py::test_risk_engine_cannot_read_leases_or_flags_directly` | CI |
| Call rules: one effect per lease, 8 calls, 3 denials | `unit/test_risk_rules.py::test_second_effect_call_is_denied`, `unit/test_risk_service.py::test_decide_allows_first_read_and_denies_second_effect`, `attacks/test_asi10_kill_switch.py` | CI |
| Distinct approvers | `attacks/test_asi03_same_approver_twice.py` (above) | CI |
| Approvals only in the console (CSRF, Entra token audience, tier that cannot be approved) | `unit/test_console.py::test_approve_records_oid_and_role`, `test_csrf_required`, `test_unapprovable_tier_refused_even_with_valid_csrf`, `test_entra_token_wrong_audience_or_issuer_rejected` | CI |
| Fail closed when the risk engine is down | `attacks/test_asi08_risk_engine_down.py` (above) | CI |
| Kill switch and SeniorApprover resume | `attacks/test_asi10_kill_switch.py` (above) | CI |
| Reply guard in the agent and in the dispatcher | `attacks/test_asi09_reply_that_promises_money.py` (above) | CI |
| llm-gateway is the only key holder | `unit/test_agent.py::test_the_agent_holds_no_key_and_knows_no_tool_address`, `unit/test_llmgw.py::test_caller_key_is_dropped`, `unit/test_capabilities.py::test_no_other_manifest_gives_a_component_a_model_role`, `unit/test_llmgw.py::test_anthropic_backend_against_fake_upstream` | CI |
| llm-gateway budget per lease | `unit/test_llmgw.py::test_budget_exceeded_returns_429`, `test_the_budget_is_per_lease` | CI |
| Only the llm-gateway reaches the model API | `k8s/test_chart.py::test_asi02_only_named_components_reach_names_outside_the_cluster`, `k8s/test_walls.py::test_asi02_only_the_llm_gateway_reaches_its_llm_api` | CI + kind |
| Executor-only effects (tools cannot write orders or request status) | `unit/test_db_roles.py::test_tools_cannot_order_disconnections`, `test_tool_cannot_insert_request_status` | CI |
| Credit limits in the executor | `unit/test_executor_credits.py::test_salami_on_same_evidence`, `test_amount_above_evidence_is_rejected` | CI |
| Order trigger: at least one approval, risk assessment, protected home | `unit/test_executor_moveouts.py::test_order_refused_without_any_approval_even_at_t0_score`, `test_order_written_after_one_approval_and_date_reached`, `unit/test_risk_floor.py::test_order_refused_without_assessment`, `attacks/test_asi01_disconnection_at_a_protected_home.py` | CI |
| Flags are add-only | `attacks/test_asi02_protection_flag_yes_to_no.py` (above), `unit/test_flag_removal.py::test_even_the_superuser_cannot_delete_or_move_a_flag_directly` | CI |
| Audit events cannot be forged | `unit/test_db_roles.py::test_events_actor_and_time_cannot_be_forged` | CI |
| Audit events cannot be erased | `unit/test_db_roles.py::test_nobody_can_erase_the_audit_trail` | CI |
| Tool roles: connection limits | `unit/test_db_roles.py::test_a_tool_role_cannot_open_more_connections_than_its_limit` | CI |
| Advisory locks only for the executor; a held home lock fails one request, not the batch | `unit/test_db_roles.py::test_only_the_executor_can_take_advisory_locks`, `unit/test_executor_moveouts.py::test_a_held_home_lock_fails_that_request_and_the_batch_goes_on` | CI |
| Executor statement and lock timeouts | `unit/test_db_roles.py::test_executor_sessions_time_out_on_locks_and_statements` | CI |
| Real grants = manifests | `unit/test_capabilities.py::test_db_grants_match_the_manifest_of_each_login_role`, `test_every_component_has_exactly_one_manifest` | CI |
| Each role has its own database password (vault) | `unit/test_dbsetup_passwords.py::test_every_role_gets_the_password_that_was_written_to_its_vault` | CI |
| Chart: default-deny network policies, exact edges | `k8s/test_chart.py::test_asi03_every_namespace_renders_default_deny`, `test_network_edges_are_exactly_the_matrix`; live: `k8s/test_walls.py::test_asi03_every_namespace_has_default_deny`, `test_asi03_probe_edge`; matrix agrees with chart: `k8s/test_attacks.py::test_matrix_expectations_agree_with_the_chart`, `test_every_chart_edge_between_probe_components_has_an_allow_probe`, `test_judge_names_each_open_wall` | CI + kind |
| Chart: metadata address denied | `k8s/test_chart.py::test_asi03_instance_metadata_denied_in_every_namespace`; live: `k8s/test_walls.py::test_asi03_metadata_endpoint_denied_even_with_an_allow_all_policy` | CI + kind |
| Chart: DNS refused (cluster names only, no open egress) | `k8s/test_chart.py::test_no_networkpolicy_allows_dns_or_open_egress`; live: `k8s/test_walls.py::test_asi02_dns_exfiltration_is_answered_by_the_proxy_and_never_forwarded` | CI + kind |
| Cilium enforces the policies | `k8s/test_cluster.py::test_cilium_ready` | kind |
| Admission: images digest-pinned | `k8s/test_chart.py::test_asi04_all_images_pinned_by_digest`, `test_admission_policies_are_bound_and_deny`; live: `k8s/test_walls.py::test_asi04_admission_rejects_unpinned_image`, `test_asi04_admission_rejects_image_swap_on_a_running_pod`; deploy by digest: `k8s/test_deploy.py::test_deploy_installs_the_pushed_image_by_digest` | CI + kind |
| Admission: no privileged pods (defence in depth, ASI05 stays n/a) | `k8s/test_chart.py::test_every_container_is_restricted_and_non_root`, `test_namespaces_enforce_restricted_pod_security`, `test_helm_lint`; live: `k8s/test_walls.py::test_admission_rejects_privileged_pod`, `test_admission_rejects_ephemeral_container_off_the_rules` | CI + kind |
| Admission: sandbox runtime for agent and tools | `k8s/test_chart.py::test_agent_and_tools_use_sandbox_runtime`; live: `k8s/test_walls.py::test_admission_rejects_tool_pod_without_runtimeclass`, `k8s/test_cluster.py::test_runtimeclass_exists` | CI + kind |
| Admission: the agent Job is exactly the template | `k8s/test_chart.py::test_agent_job_template_is_the_fixed_one`, `test_agent_job_policy_pins_the_template`, `unit/test_dispatcher.py::test_job_template_is_fixed`, `test_a_changed_template_is_refused`; live: `k8s/test_walls.py::test_admission_rejects_agent_job_off_template`, `test_dispatcher_can_create_the_agent_job` | CI + kind |
| The chart never starts an agent; the dispatcher may only create Jobs in the agent namespace | `k8s/test_chart.py::test_the_chart_never_starts_an_agent`, `test_dispatcher_may_only_create_jobs_in_agent_namespace` | CI |
| ServiceAccount per manifest | `k8s/test_chart.py::test_every_manifest_has_its_service_account_in_its_namespace` | CI |
| Each component gets only its own DB password | `k8s/test_chart.py::test_each_component_gets_only_its_own_db_password` | CI |
| Pipeline: images pinned by digest | `unit/test_pipeline.py::test_every_job_image_is_pinned_by_digest`, `unit/test_supply_chain.py::test_dockerfile_base_images_are_pinned_by_digest` | CI |
| Pipeline: downloads pinned with a sha256, used only when it matches | `unit/test_pipeline.py::test_every_downloaded_tool_has_a_version_a_url_and_a_sha256`, `test_a_download_is_used_only_when_its_sha256_matches` | CI |
| Pipeline: python packages locked with hashes; Terraform providers follow the lock | `unit/test_supply_chain.py::test_every_locked_package_has_a_sha256_hash`, `unit/test_pipeline.py::test_terraform_providers_follow_the_committed_lock` | CI |
| Pipeline: the TLS workaround is never set | `unit/test_pipeline.py::test_local_only_tls_workaround_is_never_set_by_the_pipeline_or_a_script` | CI |
| Pipeline: the test-database guard (the suite truncates tables) | `unit/test_pipeline.py::test_guard_allows_the_local_database`, `test_pytest_refuses_to_start_against_a_remote_database` | CI |
| Gateway database role: add one record row and nothing else; every wall leaves a record | `unit/test_gateway.py::test_the_gateway_can_add_a_row_and_nothing_else`, `test_an_honest_ticket_goes_through_every_wall_and_each_wall_leaves_a_record` | CI |
| The whole agent in memory: an attack ticket leaks nothing and is logged | `unit/test_agent_flow.py::test_the_attack_ticket_in_memory_leaks_nothing_and_is_logged` | CI |
| Tool basics: read_ticket works; a credit amount must be positive | `unit/test_tools.py::test_read_ticket`, `test_credit_amount_must_be_positive` | CI |
| Agent loop stops after the step limit | `unit/test_agent.py::test_agent_stops_after_max_steps` | CI |
| Scripts parse; the ticket script refuses a non-numeric customer before any kubectl call | `unit/test_scripts.py::test_all_scripts_parse`, `test_new_ticket_refuses_non_numeric_customer` | CI |
| Live replay never spends on a provider | `k8s/test_merged_attacks.py::test_live_replay_refuses_provider_or_ambiguous_backend` | kind |
| Monitoring pods meet Pod Security restricted | `k8s/test_monitoring.py::test_stack_pods_meet_pod_security_restricted` | CI |

Every row points at a test that exists. The reply notices the dispatcher adds (credit, medical question) are product behaviour, not walls, and have no test of their own.
