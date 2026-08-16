# The claims register

Every guarantee this project makes, and the thing that would fail if it stopped
being true.

## Why this exists

The dominant defect in this codebase is not a bug. It is **a stated guarantee
with no check behind it**, and there have been six:

| # | The claim | What was actually there |
|---|---|---|
| 1 | A comment said the path-segment regex prevented escaping the operations table | It did not. `caseId=".."` resolved to `/security/cases/searches` (SEC-H-02) |
| 2 | `app.js` opened by declaring *"textContent, never innerHTML"* | Nothing enforced it |
| 3 | CI asserted no package installer in the image | It asked the import system; pip was on disk. **Trivy found it, the check could not** |
| 4 | The Bicep said one replica gave the audit chain a single writer | `maxReplicas` bounds a *revision*. Every deploy ran two writers (SEC-H-01) |
| 5 | *"Both registrations hold zero credentials, asserted mechanically"* | Asserted for one, and the one it skipped was internet-facing (SEC-M-01) |
| 6 | `msal_client.py` says `doctor` reads `xms_cc` back off the token | `rg xms_cc src/` returns that comment and nothing else. **Still open** |
| 7 | INV-68 below: *"a tampered trail yields no trustworthy extract"* | True of the text output. `--json` emitted the whole extract anyway, and the test checked a dataclass property rather than an output (SEC-H-03) |

The seventh was written **in the same session as this register**, by the person
writing it. That is the point rather than an embarrassment: the defect is not
carelessness, it is that a check written beside a claim tends to test the thing
that was easy to reach rather than the thing the claim is about. INV-68's test
asked the object; the guarantee lives in what leaves the process.

Every one was found by accident — by deploying, by scanning, by trying to read
something. None was found by the thing that claimed to be checking it.

A check that has never been observed to fail is not evidence. This register
makes the mapping explicit so that **a claim with no enforcement is a CI
failure rather than a discovery**.

## How it is enforced

`tests/test_claims_register.py` parses this file and asserts:

1. Every name in **Enforced by** exists as a test — collected by walking the
   AST of `tests/*.py`, so a renamed or deleted test fails here.
2. Every structural test appears in this register — a new invariant cannot be
   added without a row, which is the drift guard in the other direction.
3. Every `open` row names a backlog item that exists in `BACKLOG.md`.

An empty cell is a defect. `open — B-nn` is a valid, visible answer: forcing
every row to name a test would fill this file with fictional names, which is
the failure it exists to prevent.

`INV-07` and `INV-10` keep the numbers they are cited by in `pyproject.toml`
and `identity/expand.py` — a numbering scheme carried over from the predecessor
whose table was never rebuilt. This is that table.

---

## No data plane

| # | Claim | Stated in | Enforced by | Kind |
|---|---|---|---|---|
| INV-01 | The eDiscovery download scope is never named in source | `README.md`, `THREAT-MODEL.md` | `test_no_download_permission_named` | test |
| INV-02 | The `MicrosoftPurviewEDiscovery` resource is never named, by name or app ID | `README.md` | `test_purview_download_resource_never_named` | test |
| INV-03 | No permitted operation downloads or previews item content | `README.md`, `THREAT-MODEL.md` | `test_no_download_or_preview_operation_exists` | test |
| INV-04 | Eleven operations, and adding one is a visible diff | `graph/operations.py` | `test_operations_table_is_the_documented_set` | test |
| INV-05 | Every request path comes from the table, never from an argument | `graph/operations.py` | `test_no_graph_path_is_caller_supplied` | test |
| INV-06 | A crafted identifier cannot reach an endpoint outside the table | SEC-H-02 | `test_path_segments_cannot_escape_the_operations_table` | test |
| INV-30 | The issued token carries no download scope | `README.md` | `doctor` — "no data plane" check | runtime |

## Dependencies and packaging

| # | Claim | Stated in | Enforced by | Kind |
|---|---|---|---|---|
| INV-07 | The dependency budget is four, read from what we declare | `pyproject.toml:11`, `SBOM.md` | `test_declared_dependencies_are_the_budget` | test |
| INV-11 | `msal-extensions` — which caused every observed portability failure — is never imported | `README.md`, `SBOM.md` | `test_msal_extensions_never_imported` | test |
| INV-12 | Exactly three modules may speak HTTP | `THREAT-MODEL.md`, `audit/blob.py` | `test_http_client_choke_point` | test |
| INV-13 | Only `dsar/auth/` may import MSAL | `auth/msal_client.py` | `test_msal_confined_to_auth_package` | test |
| INV-14 | There is no local database | `README.md`, `DESIGN.md` | `test_no_local_database` | test |
| INV-15 | `dsar` and `python -m dsar` are the same code | `README.md` | `test_both_entry_points_resolve` | test |
| INV-16 | Every documented invocation works on a fresh machine | `cli.py` | `test_docs_never_show_a_bare_dsar_command` | test |
| INV-17 | No source package is excluded by an ignore rule | — | `test_every_source_package_is_tracked_by_git` | test |
| INV-18 | Every allowlisted static asset exists in the installed package | `web/security.py` | `test_static_allowlist_files_exist_in_the_package` | test |
| INV-19 | Output belongs where a user is expected — two files may `print` | `doctor/report.py` | `test_no_print_outside_the_cli_surface` | test |

## Credentials

| # | Claim | Stated in | Enforced by | Kind |
|---|---|---|---|---|
| INV-08 | No source file carries a client-secret configuration path | `THREAT-MODEL.md`, `README.md` | `test_no_client_secret_anywhere` | test |
| INV-09 | Tokens are in memory only — `SerializableTokenCache` cannot appear | `README.md`, `DESIGN.md` | `test_no_serializable_token_cache` | test |
| INV-31 | Neither registration holds a password or certificate credential | `THREAT-MODEL.md` | `provision.sh` — `assert_no_credentials`, both registrations | CI |
| INV-32 | Adding a secret to either registration is refused | `add-fic.sh` | app management policy, verified by attempting it | manual |
| INV-33 | `doctor` fails if a secret-shaped variable is set | `README.md` | `test_a_real_client_secret_is_still_caught` | test |
| INV-34 | Proof-of-possession is unavailable, asserted rather than assumed | `THREAT-MODEL.md` | `doctor` — `assert_no_broker_pop` | runtime |
| INV-35 | CAE (`cp1`) is negotiated, not merely declared | `auth/msal_client.py:35` | **open — B-14** | open |

## The audit trail

| # | Claim | Stated in | Enforced by | Kind |
|---|---|---|---|---|
| INV-20 | The sink is append-only because there is no other verb | `audit/sink.py` | `test_the_audit_sink_has_no_mutating_method` | test |
| INV-21 | Nothing in the audit package can rewrite a file | `THREAT-MODEL.md` | `test_nothing_in_the_audit_package_can_rewrite_a_file` | test |
| INV-22 | The record has no field that could hold subject data | `THREAT-MODEL.md` | `test_the_audit_record_cannot_carry_subject_data` | test |
| INV-23 | Two writers cannot corrupt the chain | SEC-H-01, `audit/blob.py` | `test_two_writers_during_a_rollout_do_not_corrupt_the_trail` | test |
| INV-24 | The verifier reads the trail the deployment actually writes | SEC report, `audit/report.py` | `test_audit_verify_reads_the_blob_when_hosted` | test |
| INV-25 | Tampering is detected and the break is named by `seq` | `README.md`, `THREAT-MODEL.md` | `test_a_tampered_remote_record_is_still_caught` | test |
| INV-64 | A field added after the first record was written does not invalidate existing hashes | `audit/record.py` | `test_a_record_written_before_case_id_existed_still_verifies` | test |
| INV-65 | An added field is still covered by the hash once populated | `audit/record.py` | `test_a_populated_case_id_is_covered_by_the_hash` | test |
| INV-66 | The trail can answer "what happened to this case" | `audit/evidence.py` | `test_one_case_filter_returns_the_whole_story` | test |
| INV-67 | The evidence pack verifies the whole chain, never a subset | `audit/evidence.py` | `test_it_verifies_the_whole_chain_not_the_extract` | test |
| INV-68 | A tampered trail yields no trustworthy extract | `audit/evidence.py` | `test_a_tampered_trail_yields_no_trustworthy_extract` | test |
| INV-69 | The evidence pack carries no subject data | `audit/evidence.py` | `test_the_pack_never_carries_subject_data` | test |
| INV-70 | The refusal holds on **every** output path, not only the text one | SEC-H-03 | `test_the_json_output_refuses_a_tampered_trail_too` | test |
| INV-71 | Two searches sharing a name are two rows, never one merged row | SEC-H-04 | `test_two_searches_with_one_name_do_not_merge` | test |
| INV-72 | A received date cannot be out of range, in the future, or in a format the error disowns | SEC-H-05, SEC-M-10 | `test_a_received_date_out_of_range_is_refused_before_it_can_break_the_list` | test |
| INV-73 | A description cannot smuggle its own received-date marker | SEC-M-09 | `test_a_description_cannot_smuggle_its_own_marker` | test |
| INV-74 | The marker scan does not walk the whole description | SEC-M-08 | `test_the_marker_scan_does_not_walk_the_whole_description` | test |
| INV-75 | A malformed register row cannot be silently ignored | SEC-M-13 | `test_the_register_covers_the_claims_it_says_it_does` | test |

## The container and the deployment

| # | Claim | Stated in | Enforced by | Kind |
|---|---|---|---|---|
| INV-26 | Base images are pinned by digest, not tag | `SBOM.md` | `test_base_images_are_digest_pinned` | test |
| INV-27 | The bind address is not configurable | `web/app.py` | `test_bind_address_is_not_configurable` | test |
| INV-28 | The desktop launcher publishes to loopback only | `web/app.py`, `DESIGN.md` | `test_launchers_publish_to_loopback_only` | test |
| INV-29 | The launchers pass the runtime hardening flags | `README.md` | `test_launchers_harden_the_container` | test |
| INV-36 | Every GitHub Action is pinned to a commit SHA | `SBOM.md` | `test_every_action_is_pinned_to_a_commit_sha` | test |
| INV-37 | Docker being installed is not treated as the image being pullable | B-07 | `test_the_launcher_does_not_treat_docker_as_available_by_default` | test |
| INV-38 | The interpreter version is decided in one place | B-08 | `test_the_interpreter_version_is_decided_in_one_place` | test |
| INV-39 | The runtime image has no shell | B-08, `SBOM.md` | `test_the_runtime_image_has_no_shell` | test |
| INV-40 | The runtime image has no package installer | `SBOM.md` | CI — "No package installer in the runtime image" | CI |
| INV-41 | The image runs as uid 10001 | `README.md` | CI — "Runs as non-root" | CI |

## Hosted mode

| # | Claim | Stated in | Enforced by | Kind |
|---|---|---|---|---|
| INV-42 | The deployment declares no secrets | `THREAT-MODEL.md`, `DESIGN.md` | `test_the_hosted_deployment_declares_no_secrets` | test |
| INV-43 | The ingress refuses plaintext | `DESIGN.md` | `test_the_hosted_ingress_refuses_plaintext` | test |
| INV-44 | Deployment fails until a human decides the ingress exposure | `DESIGN.md` | `test_the_ip_restriction_parameter_has_no_default` | test |
| INV-45 | One replica per revision — a session control, **not** a single-writer guarantee | SEC-H-01 | `test_the_container_app_is_pinned_to_one_replica` | test |
| INV-46 | The audit container permits appends and refuses modification | `THREAT-MODEL.md` | `test_the_audit_container_is_append_protected` | test |
| INV-47 | The storage account allows no shared key, so no SAS exists | `THREAT-MODEL.md` | `test_the_storage_account_allows_no_shared_key` | test |
| INV-48 | The identity is user-assigned and dedicated | `THREAT-MODEL.md` | `test_the_identity_is_user_assigned_and_not_system` | test |
| INV-49 | The container image is pinned by digest | `DEPLOY-hosted.md` | `test_the_container_image_is_pinned_by_digest` | test |
| INV-50 | A hosted operator cannot evict a colleague's session | SEC report, B-06 | `test_one_operator_cannot_evict_another` | test |
| INV-51 | Token acquisition is bound to the audited actor | SEC-M-04 | `test_the_provider_refuses_an_account_that_is_not_the_principal` | test |
| INV-52 | Logout clears the session cookie in both modes | SEC-M-05 | `test_logout_clears_the_cookie_in_hosted_mode_too` | test |

## The front end and the request surface

| # | Claim | Stated in | Enforced by | Kind |
|---|---|---|---|---|
| INV-53 | `textContent`, never `innerHTML` | `web/static/app.js:11` | `test_the_front_end_never_assigns_html` | test |
| INV-54 | The front end parses — there is no build step to catch a syntax error | CI | `test_the_front_end_parses` | test |
| INV-55 | A request body is capped | `THREAT-MODEL.md` | `test_a_request_body_is_capped` | test |
| INV-56 | The delta is only the expansion's contribution, or the interface says so | `THREAT-MODEL.md` | `test_the_delta_says_when_it_has_stopped_meaning_what_it_looks_like` | test |
| INV-57 | A status cannot land on a page the operator has left | — | `test_a_status_cannot_land_on_a_page_the_operator_left` | test |

## Correctness with compliance consequences

| # | Claim | Stated in | Enforced by | Kind |
|---|---|---|---|---|
| INV-58 | The statutory deadline is one calendar month, not thirty days | `cases/deadline.py` | `test_one_calendar_month`, `test_it_is_not_thirty_days` | test |
| INV-59 | A deadline is never derived from the case creation date | `cases/received.py` | `test_a_case_without_a_marker_has_no_deadline` | test |
| INV-60 | The statutory arithmetic is pure and clock-free | `cases/deadline.py` | `test_the_statutory_arithmetic_is_pure` | test |
| INV-61 | Every query builder is documented, and every documented builder exists | `TEMPLATES.md` | `test_every_builder_is_documented`, `test_every_documented_builder_exists` | test |
| INV-62 | A value that cannot be expressed in KQL is refused, never escaped | `TEMPLATES.md`, `THREAT-MODEL.md` | `test_a_term_that_cannot_be_quoted_is_refused_not_escaped` | test |

## The repository

| # | Claim | Stated in | Enforced by | Kind |
|---|---|---|---|---|
| INV-10 | No test reaches the network | `tests/conftest.py`, `expand.py:132` | `conftest.py` — autouse socket guard | test-harness |
| INV-63 | No real tenant identifier is committed | `HANDOVER.md` | `test_no_tenant_specific_identifier_is_committed` | test |

---

## Kinds

| Kind | Meaning |
|---|---|
| `test` | A test in `tests/` fails when the claim stops being true |
| `test-harness` | A fixture, not an assertion — it prevents rather than detects |
| `CI` | A workflow step. Runs on every push; not reproduced locally |
| `runtime` | `doctor` reports it against the real deployment |
| `manual` | Verified by a person, with the method recorded in `verification/` |
| `open` | **No enforcement.** Must name a backlog item |
