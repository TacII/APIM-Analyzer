# Devlog

Development notes for the scripts. Newest entries first. This log records what changed in the code and why. It never contains data or findings from any environment the scripts were run against.

## 2026-11-22: Internet ingress analysis (`Check-IngressExposure.ps1`)

**Why:** Microsoft's notice ties exposure to the missing "network integration" from the Network security section of its secret management guidance, and the first script only checks `virtualNetworkType` and private endpoints. In a real tenant the question is more specific: which instances can be reached from the internet, through which NSG rules, WAFs and front ends, and how wide are the source ranges. The management endpoint on port 3443 (Azure's control plane, formerly also the direct management API) is the one that matters most for "management functionality"; Microsoft's reference allows it only from the `ApiManagement` service tag, and in internal mode a public VIP still serves it.

**What the script does:**
- Reads APIM instances, VNets and subnets, NSGs, public IPs, Application Gateways and their WAF policies, both Front Door kinds and their WAF policies, Traffic Manager profiles, Azure Firewalls and firewall policies, IP groups and private endpoints through Resource Graph. Front Door Standard/Premium child resources (endpoints, origin groups, origins, routes, custom domains, security policies) and firewall policy rule collection groups are not in Resource Graph, so they are listed through ARM. The APIM global policy is read with `format=rawxml`.
- Evaluates the APIM subnet NSG per location: every inbound allow that admits TCP to 80, 443, 3443 or 6390, one row per source value, with the higher-priority deny that shadows it or partly restricts it. Source values are classified by width: `OPEN`, `BROAD` (wider than `-TightPrefixLength`, default /24, or `AzureCloud`), `AZURE-SHARED` (multi-tenant tags), `TIGHT`, `CONTROL-PLANE`, `VNET`, `PRIVATE`. CIDR math uses BigInteger so IPv4 and IPv6 share one path.
- Decides per mode where the management endpoint and the 443 endpoints can be reached from (`Get-ApimReach`), then builds pathway rows for Application Gateway (most specific WAF policy wins: path rule, listener, gateway, inline configuration; the gateway subnet's NSG refines the source class), Front Door (origin to route to domain to security policy), classic Front Door, Traffic Manager (DNS only), Azure Firewall DNAT (inline rules and policy rule collection groups, base policies included, IP groups expanded) and private endpoints.
- Rates WAF policies (`PREVENTION`, `DETECTION ONLY`, `WAF DISABLED`) and each custom rule: an Allow for a wide range or without a source restriction skips the managed rules; a Block with a negated address match is an allowlist. A WAF is `bypassable` when the instance also answers directly and neither checks `X-Azure-FDID` nor filters sources.
- One status per instance: `OPEN`, `BROAD`, `FILTERED`, `PRIVATE`, `UNCHECKED`.
- `-CheckGatewayPatch` queries `https://<gateway>/internal-status-0123456789abcdef` and applies the thresholds from Norway's NSM advisory of 20 Nov 2026 (0.52.x from 31936, 0.53.x from 31938). Unreadable is `unknown`, never `patched`.

**Facts the checks rest on** (all from Microsoft Learn, read on 22 Nov 2026): the NSG reference for VNet-injected Classic tiers (`virtual-network-reference`); internal mode keeps a public VIP "used only for control plane traffic to the management endpoint over port 3443", which "can be locked down to the ApiManagement service tag"; private endpoints cover the Gateway only and `publicNetworkAccess = Disabled` makes private endpoints "the exclusive access method" (documented for the gateway; the other hostnames are inferred); WAF policy precedence is path rule, then listener, then gateway; Front Door REST api-version 2026-10-01 (falls back to 2024-02-01); the azureFirewalls resource spells the NAT action `Dnat`, firewall policies spell it `DNAT`.

**Also in this change:**
- `Check-ApimExposure.ps1` and `Check-KeyVaultAudit.ps1` built output paths with backslashes (`"$out\file.csv"`). PowerShell 7 normalises those on macOS and Linux, but the scripts now use `Join-Path`, which does not depend on that.
- `Analyze-Findings.ps1` reads `ingress-exposure/ingress-summary.csv` when present: an Internet ingress section in the report, flags for instances whose management endpoint is reachable from the internet and for weak or bypassable WAFs, and ingress status in `snapshot.json` for `-CompareTo`.
- `tests/Ingress.Tests.ps1`: offline Pester tests for CIDR classification, port parsing, NSG evaluation (priority, deny shadowing, partial denies, destination prefixes, protocols), WAF assessment for both policy shapes and the inline configuration, hostname matching, per-mode reach, policy parsing, WAF bypass, the instance status and the NSM thresholds.
- `.gitignore` covers `ingress-exposure/`.
- `tests/EndToEnd.Tests.ps1` runs the ingress script's real main flow (everything after the Discovery banner) against `tests/fixtures/ingress-tenant.json`, with `az`, `Invoke-Graph`, `Get-Paged` and `Get-One` replaced by stubs that serve the fixture. It asserts the status of each of the nine synthetic instances, the pathway rows for every front-end kind, the NSG and policy findings, and that every output file is written. Added because the first live run happened in a tenant with no visible APIM instances, which left the per-instance code untested by real data.
- **One tenant per run.** `az account list` returns subscriptions from every tenant the login has touched, but the token the scripts request is valid for one tenant, so the other tenants' subscriptions showed up as `DENIED/ERROR` (401 or 404) in the preflight. `Get-EnabledSubscription` in `Apim-Helpers.ps1` now takes the tenant to read (`Get-AzTenantId` resolves it from `-TenantId` or the signed-in account), returns only that tenant's enabled subscriptions, drops the placeholder entry of a tenant without subscriptions and says which subscriptions it leaves out. `Check-ApimExposure.ps1` and `Check-KeyVaultAudit.ps1` use it and request their tokens with `--tenant`; `Analyze-Findings.ps1` takes `-TenantId` for its live calls; `Check-IngressExposure.ps1` still carries its own copy of the filter, together with its own ARM and Resource Graph helpers, until it is moved onto the shared helper. The filter moved into the helper when this change was rebased onto the hardening of 25 November 2026. Reading a second tenant was not tested here.

**Fixed after an adversarial review (six reviewers, two skeptics per finding) before the first commit:** an assignment to `$pid` (a constant automatic variable) that aborted the run in any tenant with a VNet-deployed Azure Firewall; deny rules shadowing an allow although they covered only part of the subnet or only some source ports (now a deny must cover every subnet prefix and all source ports, otherwise it is listed as partial); `PREVENTION` credited to WAF policies with no managed rule set and no blocking rule, or with a custom Allow that admits everyone (now `PREVENTION (no blocking rules)` / `PREVENTION (custom allow admits everyone)`, which do not mitigate); a location whose subnet or NSG was not visible hiding what the other locations showed; Consumption and v2 instances rated as if they had a 3443 endpoint; a tight pathway behind a prevention WAF rated PRIVATE instead of FILTERED; `-CompareTo` crashing on a snapshot from before the ingress key existed; the weak-WAF flag suppressed when one front end was in prevention mode; an `ip-filter` range spanning public space rated PRIVATE; disabled Front Door endpoints and Traffic Manager profiles producing pathways; a base service tag deny not shadowing its regional variants; an NSG admitting `AzureFrontDoor.Backend` counted as closing a WAF bypass; and the api-version fallback applied across providers.

**PowerShell pitfalls met:** `"$var: text"` inside a double-quoted string is a scope qualifier (use `${var}:`); `@($null).Count` is 1, so filter before counting; Pester evaluates `-TestCases` during discovery, so helpers used there must exist at file level as well as in `BeforeAll`.

## 2026-11-22: Tier family and platform next to every status

The same user retested with v0.1.0 and still read `LIKELY EXPOSED` on stv2.1 instances as a problem. Those instances are Classic tiers, so the behaviour is correct, but the console output made the mix-up easy.

- **Labelled statuses.** Each per-instance line now reads like `LIKELY EXPOSED [Classic, stv2.1]`, `REVIEW (v2 tier) [v2]` or `OUT OF SCOPE [Classic (Consumption), mtv1]`, built by `Get-StatusLabel`.
- **The stv2 note always prints,** also when Microsoft's list is used, not only with the fallback rule.
- **Tests.** New Pester cases cover the label, including the end-to-end case "Classic on stv2.1 reads as Classic".

## 2026-11-22: stv2 is not v2; v2 instances never rated LIKELY EXPOSED

**Report:** a user saw instances on platform `stv2.1` rated `LIKELY EXPOSED` and read that as "v2 instances". `stv1`/`stv2`/`stv2.1` is the compute platform of the **Classic** tiers. The v2 tiers are the SKUs `BasicV2`, `StandardV2` and `PremiumV2`. The user couldn't read the advisory, so the tier rule applied, and their instances were Classic dedicated tiers: in scope by design. In the tenant we tested, every instance Microsoft listed was a Classic tier on stv2.1.

**Real bug found while checking:** the path that uses Microsoft's list matched on instance **name only** and never looked at the tier. A v2 instance on the list would therefore be put in scope and, typically having no VNet, rated `LIKELY EXPOSED`. Our test tenant had no v2 instances, so this path had never run with one.

**Changes:**
- **Testable functions.** The scope and status decisions are now functions in `Check-ApimExposure.ps1`: `Get-TierFamily`, `Get-ScopeDecision` and `Get-InstanceStatus`.
- **Listed v2 instances.** A v2 instance on Microsoft's list stays in scope (it was probably migrated after the incident) but is rated `REVIEW (v2 tier)`, never `LIKELY EXPOSED`, and the script warns about it.
- **Resource ID matching.** Microsoft's list is matched on full resource ID where available (CSV `Resource ID` column, or the API's `targetResourceId`), and on name otherwise.
- **Clearer output.** `tierFamily` is added to `scope.csv` and `summary.csv`. The fallback rule prints that stv2 is the Classic platform, and the legend and README say so too.
- **Tests.** `tests/Scope.Tests.ps1` holds offline Pester 5 tests, loaded from the script's own AST so the script stays a single file. They cover every SKU, Classic on stv1/stv2.1, Consumption, the Microsoft list (resource ID, name, other subscription, listed v2) and the status rules.
- **CI.** `.github/workflows/tests.yml` checks that all scripts parse and runs the tests on every pull request and on pushes to main.

## 2026-11-22: Scope follows Microsoft's impacted-resources list

**Problem:** the scripts treated every Classic instance as in scope, Consumption included, because Microsoft's notice lists Consumption among the Classic tiers. In a real tenant, the advisory's **Impacted Resources** list held only the dedicated-tier instances: Developer, Basic and Standard, all on platform `stv2.1`. All Consumption (`mtv1`) instances were absent. Counting them added instances, secrets, subscriptions and even Key Vaults that Microsoft did not consider impacted.

**Fix:**
- **Microsoft's list first.** `Check-ApimExposure.ps1` uses Microsoft's list when it can get it:
  - `-ImpactedResourcesCsv` reads the portal's Export to CSV, matching on a resource ID column, else on service or resource name;
  - otherwise it finds the advisory in Resource Graph (`servicehealthresources`, event type `SecurityAdvisory`) and calls `listSecurityAdvisoryImpactedResources`.
  - That API needs more than Reader. On a 403 the script warns and explains how to export the list instead.
- **Fallback rule.** Without a list, only Classic dedicated tiers are in scope, and `-IncludeConsumption` adds Consumption back.
- **`scope.csv`.** The decision per instance is written to `scope.csv`, together with `platformVersion`. Out-of-scope instances appear in `summary.csv` as `OUT OF SCOPE` with the reason.
- **Shared scope.** `Check-KeyVaultAudit.ps1` and `Analyze-Findings.ps1` read `scope.csv` when present, with the same rule as fallback, so all three scripts use the same set.

Platform version can't be the criterion: the listed instances were all `stv2.1`, and none was `stv1`.

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
