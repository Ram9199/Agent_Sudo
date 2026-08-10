# Release Notes: Agent_Sudo v0.5.6

Security-correctness patch release. The headline fix closes an inversion in the taint model: requests tainted by external content could receive a *weaker* approval gate than untainted ones. No breaking changes, no schema changes, no new runtime dependencies.

## Security correctness

- **Taint monotonicity (#103, fixed by #104).** The classifier's `EXTERNAL_CONTENT` provenance branch returned SENSITIVE for any non-BLOCKED action — including actions whose policy tier is CRITICAL. A tainted `send_email`, `money_transfer`, `external_post`, `credential_access`, `run_shell_command`, `delete_file`, or `legal_or_employment_message` therefore required only normal approval instead of passphrase confirmation: the requests most likely to be attacker-influenced got the weaker gate. The rule is now monotonic — external content may raise risk but never lowers it. SAFE escalates to SENSITIVE as before; SENSITIVE stays SENSITIVE; CRITICAL stays CRITICAL; BLOCKED stays BLOCKED. The parallel `source_trust` branch was already correct and is unchanged, now guarded by tests.
- **Test coverage.** Regression tests pin all seven CRITICAL-policy actions under external-content taint, plus a property-style test asserting that for every default-policy action, across both taint channels (provenance origin and source trust) and their combination, the tainted classification is never lower than the untainted one — so the invariant holds even as actions are added or re-tiered.

## Reliability

- **Pending approval store concurrency (#100).** Mutations of the pending-approval store are serialized, so concurrent approval flows no longer race on the store file. Adds concurrency regression tests. (Landed on main after the v0.5.5 tag; first shipped in this release.)

## Visible behavior changes (intended)

- Actions whose policy tier is CRITICAL now require **strong/passphrase approval** when tagged with `EXTERNAL_CONTENT` provenance, where v0.5.5 asked for normal approval.
- Audit records for those tainted actions now carry classification **`CRITICAL`** instead of `SENSITIVE`. If you alert or report on classification counts, expect a shift from SENSITIVE to CRITICAL for tainted critical actions.

## Compatibility

- No breaking changes.
- No schema changes (`delegations.json` and `audit.jsonl` formats unchanged).
- Strictly tightening: nothing previously blocked is allowed, nothing previously allowed is blocked. The only decision changes are REQUIRE_APPROVAL → REQUIRE_STRONG_APPROVAL for external-content-tainted critical actions.
- No new runtime dependencies.
