# OpenGrep SAST integration
Objective: add versioned OpenGrep SAST evidence to Barad while preserving Trivy for SBOM, secrets, and misconfigurations only.
Branch: feat/barad-security-workflow · Test runner: `PYTHONPATH=cli:. .venv/bin/python -m unittest discover -s tests -q`.

## Specs
S1: "quiero integrar opengrep en la action de baradur"
S2: "trivy generar sobm para dependency trakcer, y despue s anivel seguridad nos data missconfigurations, secrets etc... (NO DUPLICAR EL TRABJO QUE YA GERSTIONO CON DEPENCNYTRACKER)"
S3: "No enviaria info a defect DOJO..... para seguridad usarmeos un sast Opengrep"
S4: "Reglas versionadas (recomendado)"
S5: "para la POC usaremos el  cli en local apuntando a un proyecto y debermos tner las 3 SOBM con trvy, missconfiguration secretes con trivi , sast con opencgrep" "opengrep debera ser como trivy es decir instalar baradur cli y tener todo.... no inventemos"
S6: "implemtamos eso entonces"
S7: "barad health" "Comprueba motores, versiones, integridad y conectividad, sin instalar nada"

## Tasks
- T1 · S2, S4-S7 · inline · done · Fixed the CLI health-surface test for the new read-only engine health contract; full suite passed (151 tests) · commit: pending (foreign pre-existing changes share `cli/barad/config.py`).
- T2 · S1, S3, S5-S6 · inline · done · Composite action and workflow reuse the CLI EngineManager; the duplicate installer is removed and documentation/contracts are updated; focused tests passed (36 tests) · commit: pending (foreign pre-existing changes share `cli/barad/config.py`).
- T3 · S1-S7 · inline · blocked · Wheel and full unit suite verified; independent security verification passed; local POC is explicitly postponed by the user · commit: pending.

## Log
- L1 · User request verbatim: "quiero integrar opengrep en la action de baradur, me di de cuenta que trivy esta muy bien p[ero me duplica cosas entonces trivy generar sobm para dependency trakcer, y despue s anivel seguridad nos data missconfigurations, secrets etc... (NO DUPLICAR EL TRABJO QUE YA GERSTIONO CON DEPENCNYTRACKER), No enviaria info a defect DOJO..... para seguridad usarmeos un sast Opengrep"
- L2 · User decision: "Reglas versionadas (recomendado)".
- L3 · Design evidence: OpenGrep supports versioned local rule files (`opengrep scan -f rules <target>`) and JSON/SARIF output; use only local, repository-versioned rules rather than `--config auto`.
- L4 · T1 evidence: `PYTHONPATH=cli:.:tests .venv/bin/python -m unittest test_opengrep_runner test_config.ConfigurationTests test_scan_contract.ScanContractTests -q` passed 26 tests. The initial RED test failed because `barad.scan.OpenGrepRunner` did not exist.
- L5 · Pre-existing uncommitted changes share `cli/barad/config.py` (`parent_name` support), so task commits must stage only Barad's SAST hunks and never include that unrelated work.
- L6 · T2 evidence: `bash -n action/install-opengrep.sh && PYTHONPATH=cli:.:tests .venv/bin/python -m unittest test_ci_workflow test_architecture_contract -v` passed 29 tests. The workflow has no `DOJO` or `defectdojo` runtime references and CI Trivy scanners exclude `vuln`.
- L7 · Independent verifier found an ARM64-only installer defect: `action/install-opengrep.sh` has a malformed checksum for OpenGrep v1.33.1 `opengrep_manylinux_aarch64`; upstream digest is `d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf`. Reopen T2 and reproduce with a contract test before correcting it.
- L8 · Fix evidence: the new exact-digest contract initially failed, then `bash -n action/install-opengrep.sh && PYTHONPATH=cli:.:tests .venv/bin/python -m unittest test_ci_workflow.ActionInstallTests.test_composite_action_installs_checksum_pinned_opengrep -v` passed after the correction.
- L9 · Full verification: `PYTHONPATH=cli:.:tests .venv/bin/python -m unittest discover -s tests -q` passed 107 tests.
- L10 · Package verifier unavailable: `.venv/bin/python -m pip wheel --no-deps --no-build-isolation ...` failed before building because the environment cannot import `setuptools.build_meta`. It was not retried or worked around; wheel packaging remains unverified.
- L11 · User scope addition verbatim: "sip, la idea es la misma para la POC usaremos el  cli en local apuntando a un proyecto y debermos tner las 3 SOBM con trvy, missconfiguration secretes con trivi , sast con opencgrep"
- L12 · User decisions: POC target is "Councilbox Server"; "Instala setuptools en .venv".
- L13 · Wheel evidence: `.venv/bin/python -m pip wheel --no-deps --no-build-isolation ...` produced `barad-0.1.0-py3-none-any.whl`, which contains `barad/rules/opengrep-baseline.yml`.
- L14 · User correction verbatim: "opengrep debera ser como trivy es decir instalar baradur cli y tener todo.... no inventemos". The current local-executable runner does not meet that requirement; reopen T1 and research an official distribution mechanism.
- L15 · User authorization verbatim: "implemtamos eso entonces". Implement the previously proposed single EngineManager, version/hash lockfile, verified persistent cache, and action reuse.
- L16 · Official asset inspection: OpenGrep v1.33.1 macOS ARM64 asset `opengrep-core_osx_aarch64.tar.gz` has SHA-256 `cce019aba35ba0c79f74b22fc9e2f8562ca651d76d5a04d7dcc440f967e45930` and contains `opengrep-core`; Windows x86 asset `opengrep-core_windows_x86.zip` has SHA-256 `5cd512bcd688e9cb1fe5203b742cbdeca05d144f807e4785815b782315169a83` and contains `opengrep-core.exe` plus required DLLs. The EngineManager must support safe archive extraction and preserve the Windows sibling DLLs.
- L17 · T1 evidence: delegated implementation reported deterministic RED/mutant proof and GREEN `PYTHONPATH=cli:.:tests .venv/bin/python -m unittest test_engines test_opengrep_runner test_config.ConfigurationTests test_scan_contract.ScanContractTests` (69 tests); managed archive extraction, checksums, cache lock, and absolute-path invocation are covered.
- L18 · Accepted design requirement verbatim: "barad health" "Comprueba motores, versiones, integridad y conectividad, sin instalar nada". Reopen T1 to add a read-only engine verification path to `health`.
- L19 · T1 health evidence: RED `test_missing_opengrep_cache_is_unavailable_without_installing` failed before `EngineManager` was integrated into health; GREEN `PYTHONPATH=cli:.:tests .venv/bin/python -m unittest test_health test_engines -v` passed 44 tests.
- L20 · T2 evidence: RED action contracts failed while `action/install-opengrep.sh` existed; after removal and documentation updates, `PYTHONPATH=cli:.:tests .venv/bin/python -m unittest test_ci_workflow test_architecture_contract test_health -q` passed 36 tests.
- L21 · Full-suite regression: `PYTHONPATH=cli:.:tests .venv/bin/python -m unittest discover -s tests -q` failed 1/151 at `test_cli_surface.CommandSurfaceTests.test_health_diagnostic_is_a_public_command`, which did not supply managed-engine health state. Reopen T1 and update only that test boundary.
- L22 · Wheel verification passed: `barad-0.1.0-py3-none-any.whl` includes `barad/resources/engines.lock.json` and `barad/rules/opengrep-baseline.yml`.
- L23 · Native assess could not inspect the candidate because existing unrelated untracked files require an explicit provider declaration. RDD is off; independent verification remains required for the security download change.
- L24 · Regression fix: `test_cli_surface.CommandSurfaceTests.test_health_diagnostic_is_a_public_command` now supplies a verified EngineManager health result; its focused run and full unit suite passed (151 tests).
- L25 · Independent high-risk verification passed S1-S7: CLI-owned pinned lockfile, hashes, cache isolation, archive safety, atomic publication, and concurrency lock were all confirmed; no duplicate action installer or CI DefectDojo flow remains. Live POC remains blocked only on the user-named target path.
- L26 · User decision: "Posponer la POC".
