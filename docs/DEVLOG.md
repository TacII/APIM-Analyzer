# Devlog

Development notes for the scripts. Newest entries first. This log records what changed in the code and why. It never contains data or findings from any environment the scripts were run against.

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

- **Backend credentials:** inspect them in the script. It could report credentials that are typed in directly rather than referenced from a named value, without ever printing values.
- **Leftover logger credentials:** detect `Logger-Credentials-…` named values that no logger references.
- **Mixed environments:** flag named values on non-production instances whose names suggest production keys (no `test`/`dev` suffix), and the reverse.
- **Group membership:** role assignments made through groups are not detected yet.
- **Other platforms:** test on Linux and macOS.
