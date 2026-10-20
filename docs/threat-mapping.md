# Threat mapping

Each attack test is mapped to the OWASP Top 10 for LLM Applications 2025, the OWASP Top 10 for Agentic Applications 2026 (ASI), MITRE ATT&CK and MITRE ATLAS; each wall to MITRE D3FEND. The attacks themselves, and the full list of tests per attack, are in [attacks.md](attacks.md).

Two things are labelled separately:

- **The id.** Every id here was looked up in the official source on 2026-10-17 and is ✓: it exists, with the name given, in that release. The lists at the end give the release and the URL for each one.
- **The fit.** Which technique an attack or a wall belongs to is my judgement, so every mapping is ✎. Where nothing fits I wrote "none" instead of stretching an id, and where an id fits only loosely the row says so.

Releases: ATT&CK v20 (Enterprise), ATLAS 2026.09, D3FEND 1.6.0, OWASP LLM Top 10 2025, OWASP ASI 2026.

## Attacks and tests

Rows 1 to 12 are the rows of "Attacks and what stops them" in [attacks.md](attacks.md). Attack tickets 1 to 11 of the replay (`tests/attacks/tickets.py`, `python -m attacks.run replay`) are the same attacks run by a fully hijacked agent process against the real dispatcher and gateway, one ticket per row, so they map the same way.

| # | Attack | Main tests | OWASP LLM | OWASP ASI | ATT&CK | ATLAS |
|---|---|---|---|---|---|---|
| 1 | Hijacked agent asks for another customer's account | `test_injected_customer_id_is_ignored`, `test_lookup_ignores_foreign_customer_id_and_logs_it`, `test_attack_ticket_through_the_real_stack_leaks_nothing_and_is_logged` | LLM01, LLM02 | ASI01, ASI03 | T1213.006 | AML.T0051.001, AML.T0093, AML.T0053, AML.T0057 |
| 2 | Medical or vulnerability flag reaches the model | `test_only_executor_can_read_flags`, `test_reply_has_no_health_data`, `test_lookup_returns_owner_and_no_health_fields` | LLM02 | ASI03 | T1213.006 | AML.T0057, AML.T0085.001 |
| 3 | Flag changed from YES to NO | `test_tools_cannot_change_flags_directly`, `test_temp_protection_never_downgrades`, `test_sync_cannot_delete_flag`, `test_flag_removal_needs_two_distinct_seniors_and_alerts`, `test_the_requester_cannot_approve_their_own_removal` | LLM06 | ASI02 | T1565.001 | AML.T0053 |
| 4 | Many small credits, or a negative or zero amount | `test_salami_on_same_evidence`, `test_credit_amount_must_be_positive`, `test_database_refuses_a_credit_the_charges_do_not_back`, `test_credit_refused_without_assessment`, `test_t1_credit_needs_one_approval` | LLM05, LLM06 | ASI02 | T1657, T1565.001 | AML.T0053, AML.T0048.000 |
| 5 | Flood of move-out requests | `test_flood_is_rate_limited_and_alerts`, `test_forged_alert_does_not_silence_the_flood_alert` | LLM06, LLM10 | ASI08 | none: the requests are ordinary business requests, not a denial of service on a system | AML.T0053, AML.T0048.003 |
| 6 | Same member of staff approves twice | `test_same_approver_twice_is_rejected`, `test_floor_counts_distinct_approvers_and_roles` | LLM06 | ASI09 | T1684.001 (the ticket claims to be the supervisor) | AML.T0073 |
| 7 | Disconnection at a protected home | `test_protected_home_never_gets_order`, `test_database_refuses_order_at_protected_home`, `test_order_refused_for_human_only_even_with_two_seniors`, `test_order_approvals_count_only_after_the_notice` | LLM06 | ASI01, ASI02 | T1565.001 (the attack sends `protection: NO` as an argument) | AML.T0053, AML.T0048.003 |
| 8 | Reply that promises money | `test_guard_blocks_money_promises`, `test_guard_blocks_the_known_bypasses`, `test_agent_blocks_a_number_the_tools_never_returned` | LLM05, LLM09 | ASI09 | none | AML.T0048.000, AML.T0048.001 |
| 9 | A tool holds a home's lock or uses up connections | `test_only_the_executor_can_take_advisory_locks`, `test_a_tool_role_cannot_open_more_connections_than_its_limit`, `test_a_held_home_lock_fails_that_request_and_the_batch_goes_on` | LLM10 | ASI08 | T1499.003 (loose: the target is the executor's database session, not a network service) | AML.T0034.002 |
| 10 | A hijacked component sends data out or downloads something | `test_no_outbound_connection_from_the_walled_services`, `test_no_external_dns_from_the_walled_services` | LLM02, LLM06 | ASI02 | T1567, T1048, T1105 | AML.T0086, AML.T0025 |
| 11 | A tool reads columns or rows it does not need, or forges or erases audit events | `test_tool_roles_have_no_table_grants`, `test_lease_functions_refuse_expired_revoked_unknown`, `test_rls_backstop_hides_rows_from_tool_roles`, `test_events_actor_and_time_cannot_be_forged`, `test_nobody_can_erase_the_audit_trail` | LLM02, LLM06 | ASI03 | T1213.006, T1565.001, T1070 | AML.T0085.001 |
| 12 | Hijacked agent talks to the database, a tool calls another tool, the executor calls a tool | `test_agent_cannot_reach_db_on_any_ip`, `test_tool_cannot_reach_other_tools`, `test_executor_cannot_reach_tools` | LLM06 | ASI03 | T1046 | none |

The ticket text is written by the customer and read by the agent from the database, so the injection is indirect (AML.T0051.001: "via a separate data channel that the LLM or AI agent ingests"), and its way in is the ticket intake (AML.T0093). Rows 2 to 12 all start the same way; the table lists what the injected instructions then try to do.

## Runtime walls on Kubernetes

The probe matrix (`tests/attacks/probes.py`, live run `tests/k8s/test_walls.py`) and the admission dry runs prove these on the kind cluster; the same chart and policies go to AKS.

| Attack | Tests | OWASP LLM | OWASP ASI | ATT&CK | ATLAS |
|---|---|---|---|---|---|
| A pod calls a component it has no edge to (agent to a tool or the database, tool to tool, fakes to anything) | `test_probe_edge` (every row of the matrix), `test_every_namespace_has_default_deny` | LLM06 | ASI03 | T1046 | none |
| A pod in the agent's namespace carries the tool gateway's label | `test_probe_edge[spoof-tool-gateway -> tool-read-ticket:8000]` | none | ASI03 | T1036.005 | none |
| A pod asks the instance metadata endpoint for a managed identity token, even next to an allow-all policy | `test_probe_edge[agent -> imds:80]`, `test_metadata_endpoint_denied_even_with_an_allow_all_policy` | none | ASI03 | T1552.005 | AML.T0055 |
| A pod other than the three callers reaches the Kubernetes API | `test_probe_edge[agent -> kube-apiserver:443]` and the other API rows | none | ASI03 | T1613, T1552.007 | none |
| Data out through DNS (`<random>.exfil.example`) | `test_dns_exfiltration_is_answered_by_the_proxy_and_never_forwarded`, `test_probe_edge[agent dns {random}.exfil.example.]` | LLM02 | ASI02 | T1048, T1071.004 | AML.T0025 |
| Connections to the internet, or to an LLM API from anything but the llm-gateway | `test_probe_edge[... -> internet:443]`, `test_only_the_llm_gateway_reaches_its_llm_api` | LLM02, LLM10 | ASI02 | T1105, T1567 | AML.T0086 |
| An unpinned image, or an image swapped on a running pod | `test_admission_rejects_unpinned_image`, `test_admission_rejects_image_swap_on_a_running_pod` | LLM03 | ASI04 | T1525, T1610 | AML.T0010.004 |
| A privileged pod, host access, or an ephemeral debug container | `test_admission_rejects_privileged_pod`, `test_admission_rejects_ephemeral_container_off_the_rules` | none | ASI05 | T1611, T1610 | AML.T0105 |
| A tool or agent pod outside the sandbox runtime | `test_admission_rejects_tool_pod_without_runtimeclass` | none | ASI05 | T1611 | AML.T0105 |
| The dispatcher (which may create Jobs) creates an agent Job that runs as another ServiceAccount, mounts a Secret or asks for another token | `test_admission_rejects_agent_job_off_template`, control `test_dispatcher_can_create_the_agent_job` | LLM06 | ASI03 | T1610 | none |

## Service boundary tests

These application tests run with the merged service implementations.

| Wall | Tests | OWASP LLM | OWASP ASI | ATT&CK | ATLAS |
|---|---|---|---|---|---|
| Tool token audience, expiry and replay | `test_tool_rejects_wrong_audience_expired_and_replayed_tokens` | none | ASI03 | T1550.001 | AML.T0091.000 |
| Gateway refuses an unavailable or slow risk engine | `test_gateway_denies_when_risk_engine_unreachable`, `test_gateway_denies_when_risk_engine_is_too_slow_and_records_a_risk_timeout` | LLM06 | ASI08 | none | none |
| LLM gateway budget per lease | `test_budget_exceeded_returns_429`, `test_the_budget_is_per_lease` | LLM10 | ASI08 | T1496.004 (loose: model API cost) | AML.T0034.002 |

## Walls and D3FEND

| Wall | Where | D3FEND | Fit |
|---|---|---|---|
| `default-deny` in every namespace, two NetworkPolicies per allowed edge; one internal Compose network per edge | `templates/policies/networkpolicies.yaml`, `compose.yaml` | D3-NI, D3-ITF, D3-OTF | direct |
| DNS for `cluster.local` names only, each pod's own outside names; Azure DNS security policy per VNet | `templates/policies/cilium.yaml`, `infra/net/dns-policy.tf` | D3-DNSAL | direct |
| Metadata endpoint denied in every namespace; Firewall Basic application rules; NSG per subnet | `cilium.yaml`, `infra/lab/firewall.tf`, `infra/net/nsg.tf` | D3-OTF, D3-ITF | direct |
| Caller identity: projected ServiceAccount token per audience, checked with a TokenReview; staff Entra token checked by the console | gateway, dispatcher, llm-gateway, fakes, console | D3-TBA | direct |
| Call token per tool: ES256 signature, audience = that tool, 60 s, `jti` used once | gateway and tools | D3-MAN, D3-CTS, D3-TBA | direct |
| Lease: task-scoped, 15 minutes, lists the tools, stored only as a sha256, never shown to the model | `db/sql/05-lease.sql`, dispatcher | D3-AMED, D3-CH | direct |
| Gateway drops arguments the manifest does not list; strict schemas | tool-gateway | D3-CV | direct |
| No table grants for tool roles, one `SECURITY DEFINER` function each; column grants; RLS as a backstop; register sync may only add flags | `db/sql/03-grants.sql`, `05-lease.sql`, `07-register.sql`, `08-rls.sql` | D3-UAP | direct |
| Risk engine call rules: one effect per ticket, 8 calls per lease, pause after 3 denials | `app/risk/rules.py` | D3-AZET | loose: D3FEND compares with a baseline profile, these are fixed thresholds |
| Kill switch: `pause_agents()` by the risk engine, `resume_agents()` by a senior in the console | `db/sql/06-risk.sql` | D3-PS | loose: it stops the agents' tool calls, not an OS process |
| Effect floor: no credit or order without a risk tier and enough distinct approvers (SeniorApprovers for HOLD and for flag removal) | `db/sql/06-risk.sql`, `07-register.sql`, triggers in `01-schema.sql` | D3-DLV | direct |
| Amount checks: positive, not NaN, at most 500.00 | `db/sql/01-schema.sql` | D3-IRV | direct |
| Reply guard: numbers a tool did not return, currency and money words, mixed Latin and Greek letters; a blocked reply is replaced by a fixed text | `app/agent/guard.py`, dispatcher | D3-CF, D3-HD, D3-CNS | direct |
| Kata micro-VM for the agent and tools on AKS | `infra/lab/aks.tf`, `ah-sandbox-runtime` | D3-HBPI, D3-EI | D3-HBPI is memory isolation by hardware; a Kata VM gets that from the hypervisor |
| Pod Security `restricted`: non-root, read-only root, drop ALL, seccomp `RuntimeDefault` | chart, `ah-no-host-access` | D3-SCF, D3-KBPI | direct |
| Images only from the allowed registry, pinned by digest; trivy on the built image | `ah-images-pinned`, `ci/build-scan.sh` | D3-EAL, D3-CIA | D3-EAL: D3FEND describes a signature check; a digest pins the exact image but is not a signature |
| The agent Job is exactly the template | `ah-agent-job-template` | D3-ACH | loose |
| Permission assessment: declared against live grants, edges and role assignments | `secops/permassess`, CI job `permissions` | D3-AM, D3-CI | direct |
| Heartbeats and the dead-man alert | `heartbeats` table, `/healthz`, alert `heartbeat-missing` | D3-EHB | direct |
| Staff sign in with MFA (Entra security defaults) | Entra tenant | D3-MFA | direct, outside this repository |

## Ids

### OWASP Top 10 for LLM Applications 2025

✓ [genai.owasp.org/llm-top-10](https://genai.owasp.org/llm-top-10/), each id on its own page:

| Id | Name |
|---|---|
| [LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) | Prompt Injection |
| [LLM02](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/) | Sensitive Information Disclosure |
| [LLM03](https://genai.owasp.org/llmrisk/llm032025-supply-chain/) | Supply Chain |
| [LLM05](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) | Improper Output Handling |
| [LLM06](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) | Excessive Agency |
| [LLM09](https://genai.owasp.org/llmrisk/llm092025-misinformation/) | Misinformation |
| [LLM10](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/) | Unbounded Consumption |

### OWASP Top 10 for Agentic Applications 2026

✓ [the release page](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) and the PDF linked from it, read in full. The ids have no pages of their own.

| Id | Name |
|---|---|
| ASI01 | Agent Goal Hijack |
| ASI02 | Tool Misuse and Exploitation |
| ASI03 | Identity and Privilege Abuse |
| ASI04 | Agentic Supply Chain Vulnerabilities |
| ASI05 | Unexpected Code Execution (RCE) |
| ASI08 | Cascading Failures |
| ASI09 | Human-Agent Trust Exploitation |

ASI02's mitigations include a policy enforcement middleware it calls an "Intent Gate", which treats model output as untrusted and checks each call before it runs ✓. The tool gateway is that gate.

### MITRE ATT&CK (Enterprise, v20)

✓ each page on attack.mitre.org. One id changed: T1656 Impersonation now redirects to T1684.001, so this page uses the new id.

| Id | Name |
|---|---|
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Masquerading: Match Legitimate Resource Name or Location |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer |
| [T1213.006](https://attack.mitre.org/techniques/T1213/006/) | Data from Information Repositories: Databases |
| [T1496.004](https://attack.mitre.org/techniques/T1496/004/) | Resource Hijacking: Cloud Service Hijacking |
| [T1499.003](https://attack.mitre.org/techniques/T1499/003/) | Endpoint Denial of Service: Application Exhaustion Flood |
| [T1525](https://attack.mitre.org/techniques/T1525/) | Implant Internal Image |
| [T1550.001](https://attack.mitre.org/techniques/T1550/001/) | Use Alternate Authentication Material: Application Access Token |
| [T1552.005](https://attack.mitre.org/techniques/T1552/005/) | Unsecured Credentials: Cloud Instance Metadata API |
| [T1552.007](https://attack.mitre.org/techniques/T1552/007/) | Unsecured Credentials: Container API |
| [T1565.001](https://attack.mitre.org/techniques/T1565/001/) | Data Manipulation: Stored Data Manipulation |
| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service |
| [T1610](https://attack.mitre.org/techniques/T1610/) | Deploy Container |
| [T1611](https://attack.mitre.org/techniques/T1611/) | Escape to Host |
| [T1613](https://attack.mitre.org/techniques/T1613/) | Container and Resource Discovery |
| [T1657](https://attack.mitre.org/techniques/T1657/) | Financial Theft |
| [T1684.001](https://attack.mitre.org/techniques/T1684/001/) | Social Engineering: Impersonation |

### MITRE ATLAS (2026.09)

✓ in MITRE's published data, [ATLAS-2026.09.yaml](https://github.com/mitre-atlas/atlas-data/blob/main/dist/v6/ATLAS-2026.09.yaml) (the repository's `dist/ATLAS-latest.yaml` points to it). The pages on atlas.mitre.org answer a plain HTTP fetch with 404 (the site is rendered in the browser), so I could not open them; the links below follow the site's pattern and are ~ as links, not as ids.

| Id | Name |
|---|---|
| [AML.T0010.004](https://atlas.mitre.org/techniques/AML.T0010.004) | AI Supply Chain Compromise: Container Registry |
| [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025) | Exfiltration via Cyber Means |
| [AML.T0034.002](https://atlas.mitre.org/techniques/AML.T0034.002) | Cost Harvesting: Agentic Resource Consumption |
| [AML.T0048.000](https://atlas.mitre.org/techniques/AML.T0048.000) | External Harms: Financial Harm |
| [AML.T0048.001](https://atlas.mitre.org/techniques/AML.T0048.001) | External Harms: Reputational Harm |
| [AML.T0048.003](https://atlas.mitre.org/techniques/AML.T0048.003) | External Harms: User Harm |
| [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) | LLM Prompt Injection: Indirect |
| [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | AI Agent Tool Invocation |
| [AML.T0055](https://atlas.mitre.org/techniques/AML.T0055) | Unsecured Credentials |
| [AML.T0057](https://atlas.mitre.org/techniques/AML.T0057) | LLM Data Leakage |
| [AML.T0073](https://atlas.mitre.org/techniques/AML.T0073) | Impersonation |
| [AML.T0085.001](https://atlas.mitre.org/techniques/AML.T0085.001) | Data from AI Services: AI Agent Tools |
| [AML.T0086](https://atlas.mitre.org/techniques/AML.T0086) | Exfiltration via AI Agent Tool Invocation |
| [AML.T0091.000](https://atlas.mitre.org/techniques/AML.T0091.000) | Use Alternate Authentication Material: Application Access Token |
| [AML.T0093](https://atlas.mitre.org/techniques/AML.T0093) | Prompt Infiltration via Public-Facing Application |
| [AML.T0105](https://atlas.mitre.org/techniques/AML.T0105) | Escape to Host |

### MITRE D3FEND (1.6.0)

✓ each id and definition from the D3FEND API (`https://d3fend.mitre.org/api/technique/d3f:<name>.json`, version 1.6.0, released 2026-08-31); the technique pages below open.

| Id | Name |
|---|---|
| [D3-ACH](https://d3fend.mitre.org/technique/d3f:ApplicationConfigurationHardening/) | Application Configuration Hardening |
| [D3-AM](https://d3fend.mitre.org/technique/d3f:AccessModeling/) | Access Modeling |
| [D3-AMED](https://d3fend.mitre.org/technique/d3f:AccessMediation/) | Access Mediation |
| [D3-AZET](https://d3fend.mitre.org/technique/d3f:AuthorizationEventThresholding/) | Authorization Event Thresholding |
| [D3-CF](https://d3fend.mitre.org/technique/d3f:ContentFiltering/) | Content Filtering |
| [D3-CH](https://d3fend.mitre.org/technique/d3f:CredentialHardening/) | Credential Hardening |
| [D3-CI](https://d3fend.mitre.org/technique/d3f:ConfigurationInventory/) | Configuration Inventory |
| [D3-CIA](https://d3fend.mitre.org/technique/d3f:ContainerImageAnalysis/) | Container Image Analysis |
| [D3-CNS](https://d3fend.mitre.org/technique/d3f:ContentSubstitution/) | Content Substitution |
| [D3-CTS](https://d3fend.mitre.org/technique/d3f:CredentialTransmissionScoping/) | Credential Transmission Scoping |
| [D3-CV](https://d3fend.mitre.org/technique/d3f:ContentValidation/) | Content Validation |
| [D3-DLV](https://d3fend.mitre.org/technique/d3f:DomainLogicValidation/) | Domain Logic Validation |
| [D3-DNSAL](https://d3fend.mitre.org/technique/d3f:DNSAllowlisting/) | DNS Allowlisting |
| [D3-EAL](https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting/) | Executable Allowlisting |
| [D3-EHB](https://d3fend.mitre.org/technique/d3f:EndpointHealthBeacon/) | Endpoint Health Beacon |
| [D3-EI](https://d3fend.mitre.org/technique/d3f:ExecutionIsolation/) | Execution Isolation |
| [D3-HBPI](https://d3fend.mitre.org/technique/d3f:Hardware-basedProcessIsolation/) | Hardware-based Process Isolation |
| [D3-HD](https://d3fend.mitre.org/technique/d3f:HomoglyphDetection/) | Homoglyph Detection |
| [D3-IRV](https://d3fend.mitre.org/technique/d3f:IntegerRangeValidation/) | Integer Range Validation |
| [D3-ITF](https://d3fend.mitre.org/technique/d3f:InboundTrafficFiltering/) | Inbound Traffic Filtering |
| [D3-KBPI](https://d3fend.mitre.org/technique/d3f:Kernel-basedProcessIsolation/) | Kernel-based Process Isolation |
| [D3-MAN](https://d3fend.mitre.org/technique/d3f:MessageAuthentication/) | Message Authentication |
| [D3-MFA](https://d3fend.mitre.org/technique/d3f:Multi-factorAuthentication/) | Multi-factor Authentication |
| [D3-NI](https://d3fend.mitre.org/technique/d3f:NetworkIsolation/) | Network Isolation |
| [D3-OTF](https://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering/) | Outbound Traffic Filtering |
| [D3-PS](https://d3fend.mitre.org/technique/d3f:ProcessSuspension/) | Process Suspension |
| [D3-SCF](https://d3fend.mitre.org/technique/d3f:SystemCallFiltering/) | System Call Filtering |
| [D3-TBA](https://d3fend.mitre.org/technique/d3f:Token-basedAuthentication/) | Token-based Authentication |
| [D3-UAP](https://d3fend.mitre.org/technique/d3f:UserAccountPermissions/) | User Account Permissions |
