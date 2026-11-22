# Devlog

Development notes for the scripts. Newest entries first. This log records what changed in the code and why. It never contains data or findings from any environment the scripts were run against.

## 2026-11-22: Follow-up analysis script (`Analyze-Findings.ps1`)

This automates the manual follow-up that was needed after a real run. It reads the output of the two scripts and makes read-only calls to Entra ID, Log Analytics and Resource Manager.

- **Secrets held by APIM:**
  - classifies each secret by type from its display name;
  - flags the same secret name on production and non-production instances, production-looking keys on non-production instances, non-production keys on production instances, and plain values with secret-like names.
- **Subscriptions:** the built-in all-access subscription (scope `/`) and "All APIs" subscriptions.
- **Live checks:**
  - backend credential structure, counting literal values versus named-value references without ever reading values;
  - logger credentials that no logger references, using the `{{Logger-Credentials-…}}` references in each logger.
- **Flagged Key Vault callers:**
  - resolves each identity through Graph `directoryObjects/getByIds`;
  - then, per caller and vault, collects all IPs over the log period, clients before and in the window, volume per day against the caller's own baseline, distinct items, and failed operations, ignoring routine `CertificateContactsGet` 403s;
  - checks whether the flagged IP is in the `AzureCloud` service tag, which comes from the Resource Manager `serviceTags` API, so no internet download is needed;
  - gives each caller a heuristic verdict.
- **Report and comparison:** writes `analysis-report.md` and `snapshot.json`. `-CompareTo` lists the changes against an earlier snapshot, and `-SkipLive` works from the CSVs alone.

What we learned while building it:
- **Pairs, not identities.** The audit script's "new caller" is new per identity *and* IP pair. On a real run, every flagged caller turned out to be a long-known identity with the same client on a new IP. The drill-down makes that visible instead of leaving it to manual queries.
- **All-access subscriptions.** Not every instance has an active built-in all-access subscription, so count them per instance rather than assuming one each.
- **PowerShell pitfalls:**
  - `0xFFFFFFFF` is an int32 (-1), so use `4294967295` for 32-bit masks.
  - `,` binds tighter than `+`, so string concatenation inside `@(a + b, c + d)` needs parentheses.

## 2026-11-22: Fewer false alarms in the audit script

What we learned from a real run:
- **The missing-object-ID warning was mostly noise.** Key Vault logs a 401 `Authentication` challenge before most authenticated calls, and control-plane operations (`VaultGet`, `AccessPolicy*`) never carry an object ID. Those rows made up roughly a third of all events. The check now counts only authenticated data-plane calls (`Secret*`, `Key*`, `Certificate*` without a 401). `Http` was added to the normalised schema for this.
- **Short retention made ordinary callers look new.** With a 90-day lookback but a workspace that keeps 30 days, the baseline before the window was only about three weeks. The script now warns when the logs start later than the lookback, and says roughly when the window's first day will age out. `vault-verdicts.csv` gains a `baselineDays` column.
- **Typical harmless "new callers"** were CI/CD agents, which use a new Azure IP on every run (Terraform's Go SDK, `CertificateContactsGet` 403s), and admins working from a new network with the same client string as always. The legend now says so.
- `.gitignore` now also covers report formats (`*.docx`, `*.doc`, `*.pdf`, `*.pptx`). Reports written from the output contain the same tenant data and must stay outside the repo.

## 2026-11-22: Ignore archived output

- `.gitignore` now also covers archives (`*.zip`, `*.7z`, `*.rar`, `*.tar`, `*.gz`) and spreadsheets (`*.xlsx`, `*.xls`). People often zip the output folders or open them in Excel to pass them on, and those copies contain the same tenant data as the CSVs.
- Added this devlog.

## 2026-11-22: Paging, pricing tiers and logger credentials (`54dec07`)

**Problem: lists were cut off at 100 items on Windows.** `az` is a batch file there (`az.cmd`), and `cmd.exe` cuts arguments at `&`. Every ARM `nextLink` (`…?api-version=…&$skip=100`) therefore fetched page 1 again and returned a non-zero exit code. Long lists of named values or subscriptions were truncated and reported as failures.

**Fix:** both scripts now call Azure Resource Manager directly with `Invoke-RestMethod` and a token from `az account get-access-token`, refreshed before it expires. Throttling (429) and 5xx responses are retried with backoff.

Also in this change:
- `MethodNotAllowedInPricingTier` is no longer treated as a failure. Consumption does not support identity providers, so there is nothing of that kind to expose, and those instances were wrongly reported as `UNCHECKED`.
- The `Logger-Credentials-…` named values that APIM creates for Application Insights loggers are now counted separately (`loggerCredentials`) and no longer affect the status. Repeated deployments can leave hundreds of them, which made the secret count misleading.
- `named-values.csv` now includes `displayName`, since `name` is often an opaque ID.
- The documentation now says that Git access is often reported as enabled by default, and that backend credentials are not inspected.

## 2026-11-22: License and author (`dc38699`, `af050a2`)

- Added the MIT license and an author section. The contact address is base64-encoded.

## 2026-11-22: First version with review fixes (`ac6cf6b`)

The first public version also included fixes from a code review.

`Check-KeyVaultAudit.ps1`:
- **Broken log query:** the `AZKVAuditLogs` branch used the wrong column names. It now uses `CallerIpAddress` and `_ResourceId`, checked against Microsoft's table reference, and reads the object-ID claim from either the short or the long form. Previously the misspelled IP column returned empty strings, so every APIM identity event looked like it came from an unexpected IP.
- **Missing warnings:** the script now warns when log rows lack a caller IP or object ID. Rows without an IP are marked for review instead of `UNEXPECTED IP`.
- **Inherited role assignments:** these now come through `authorizationScopeFilter=AtScopeAboveAndBelow`. By default, Resource Graph returns only assignments at or below the queried scope, so assignments from management groups were missed.
- **Vault-scoped assignments:** assignments made directly on a vault, or on an item inside it, are now matched. The old prefix test, `StartsWith("$scope/")`, never matched the vault itself.
- **Role filtering:** a role assignment now counts only if it gives Key Vault data access on an RBAC vault, or a way to grant itself access. Other assignments are written to `excluded-role-assignments.csv`. Management-group scopes are matched using each subscription's management-group ancestry.

`Check-ApimExposure.ps1`:
- Added checks for certificates (whether stored in APIM or in Key Vault), APIM subscriptions (metadata only), the direct management API and Git access.
- Certificates and client-secret objects held by APIM now count towards `LIKELY EXPOSED`.
- Principal IDs are compared without regard to upper/lower case.
- `hasManagedIdentity` is false for identity type `None`.

Both scripts:
- Resource Graph is called through its REST API, so results page beyond 1,000 rows.

## Open ideas

- ~~Backend credentials, leftover logger credentials, mixed environments~~: done in `Analyze-Findings.ps1`.
- **Group membership:** role assignments made through groups are not detected yet.
- **Shared secret values:** compare secret values across environments by hash only, so reuse can be confirmed without exposing values. This would need a deliberate opt-in, since it reads secret values.
- **Entra sign-in logs:** add an optional check of the flagged callers' sign-ins (IP, client app, location) when the account can read them.
- **Other platforms:** test on Linux and macOS.
