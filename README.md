# apim-incident-tools

PowerShell scripts for checking whether an Azure tenant may be affected by the **Azure API Management (APIM) Classic-tier security issue** that Microsoft notified customers about in November 2026, reviewing Key Vault audit logs for signs of misuse, and performing selected, individually confirmed credential operations.

> **Status: untested, community-style tooling.** The scripts were written quickly during an incident and have been run in only one environment. Review them before running, and verify results independently. They do not replace Microsoft's guidance or your own security team's judgement.

## Background

Microsoft's notice states that a security issue affected APIM **Classic** tiers (Consumption, Developer, Basic, Standard, Premium) but not the **v2** tiers. It was identified on 18 November 2026 and the access path was closed on 19 November 2026. Instances may have been accessed if they:

- lacked the network integration described in Microsoft's "Network security" guidance for secret management, or
- stored secrets in APIM instead of referencing them from Azure Key Vault.

Potentially exposed items include named-value secrets, identity provider and OpenID Connect client secrets, subscription keys and management tokens.

Because the exact reach of the issue is not fully documented, these tools also look at Key Vaults that APIM managed identities can reach. That is a precaution, not a confirmed attack path.

Public context, as of 22 November 2026: Microsoft has published no advisory beyond the customer notice. Norway's National Security Authority (NSM) published an advisory on 20 November 2026 after attacks on Equinor and Skagerak Energi that exploited the issue; it says to assume all secrets and named values are compromised, and gives a way to check the gateway's patch level (see `-CheckGatewayPatch` below). Microsoft's Tech Community post *Rotating credentials in Azure API Management* (21 November 2026) lists the rotation endpoints. The "Network security" section the notice refers to matches Microsoft's *Secure your Azure API Management deployment* page: private endpoint plus disabled public network access, VNet injection (internal mode preferred), a WAF in front of an internal instance, and IP filtering.

### Which instances are in scope

**Microsoft's own list is authoritative.** In the Azure portal, open Service Health > Security advisories, select the advisory, and go to **Impacted Resources**. Use **Export to CSV** and pass the file to the exposure script:

```powershell
pwsh ./Check-ApimExposure.ps1 -ImpactedResourcesCsv ./impacted-resources.csv
```

If your account may read the advisory's impacted resources through the API (Owner/Contributor, or a role with `Microsoft.ResourceHealth/events/fetchEventDetails/action`), the script fetches the list itself.

Without that list, the script falls back to a rule: **Classic dedicated tiers** (Developer, Basic, Standard, Premium, Isolated).
- **v2 tiers** (`BasicV2`, `StandardV2`, `PremiumV2`) are out of scope under the fallback rule.
- **Consumption** (multi-tenant platform `mtv1`) is out of scope by default. Microsoft's notice names it among the Classic tiers, but in the tenants checked so far Microsoft's impacted-resources list included only dedicated-tier instances. Add `-IncludeConsumption` to include it anyway.
- **Platform version** is shown but not used. Instances on `stv2.1` were listed as impacted.

All four analysis scripts share these explicit SKU rules in `Apim-Helpers.ps1`:

| SKU | Family | Fallback scope |
|---|---|---|
| `Developer`, `Basic`, `Standard`, `Premium`, `Isolated` | Classic | Included for review; inclusion is not proof of impact |
| `Consumption` | Classic (Consumption) | Included only with `-IncludeConsumption` |
| `BasicV2`, `StandardV2`, `PremiumV2` | v2 | Excluded, unless the scope file explicitly includes them |
| Missing or unrecognized SKU, including a future name ending in `V2` | Unknown | Warn and retain for manual review; exposure status is `UNCHECKED`, even if an old scope file excludes it |

SKU matching ignores case and surrounding whitespace. The supported names follow the [service SKU reference](https://learn.microsoft.com/en-us/rest/api/apimanagement/api-management-service/get?view=rest-apimanagement-2024-05-01#skutype) and the [tier comparison](https://learn.microsoft.com/en-us/azure/api-management/api-management-features), which also documents Premium v2.

> **stv2 is not v2.** `stv1`, `stv2` and `stv2.1` in `platformVersion` are the compute platforms of the **Classic** tiers. Nearly every Classic instance runs on stv2.x today. The **v2 tiers** are a separate product line, identified by the SKU. The `tierFamily` column (`Classic`, `Classic (Consumption)`, `v2` or `Unknown`) in `scope.csv` and `summary.csv` shows which one an instance is. The console shows it next to each status, for example `LIKELY EXPOSED [Classic, stv2.1]`.

**Matching Microsoft's list.** Instances are matched on resource ID when the list has one (case-insensitive), and on name otherwise.

**A v2 instance on Microsoft's list.** If Microsoft lists an instance that is now a v2 tier, it was probably migrated from Classic after the incident. It stays in scope, because its secrets may have been exposed while it was Classic, but it is rated `REVIEW (v2 tier)` and never `LIKELY EXPOSED`. The script prints a warning for it.

The decision per instance is written to `apim-exposure/scope.csv`. The audit, ingress and analysis scripts use that file when it exists, so all four scripts work on the same set.

Malformed, duplicate or unrecognized `inScope` values stop the run rather than silently excluding resources. If a current instance is missing from an older scope file, the scripts warn and apply the tier fallback to that instance. Regenerate the scope file to reconcile new or removed resources. `-IncludeConsumption` is available on all four scripts and only affects the fallback, not an explicit scope-file decision.

## What is in this repo

| File | Purpose |
|---|---|
| `Check-ApimExposure.ps1` | Finds APIM instances across all subscriptions you can read, flags Classic tiers, and checks network settings. Lists named values, certificates, identity providers and other secret-bearing objects, APIM subscriptions, and whether the direct management API and Git access are enabled. Also maps what each instance's managed identity can reach. |
| `Check-KeyVaultAudit.ps1` | Can run without the exposure scan. Finds the vaults that APIM managed identities can read from, or can grant themselves access to. Checks whether audit logging is enabled, and queries Log Analytics for identity activity and new callers in a time window. |
| `Check-IngressExposure.ps1` | Maps every internet ingress pathway to the in-scope instances and rates how permissive it is: the instance's own network mode, the NSG on the APIM subnet (open or broad allows on 3443 and 443), Application Gateway and Front Door WAF policies (disabled, detection-only, permissive custom rules, bypassable), Traffic Manager, Azure Firewall DNAT rules and private endpoints. Optionally checks the gateway's patch level. Writes CSVs and `ingress-report.md`. |
| `Analyze-Findings.ps1` | Follow-up analysis of the exposure and audit scripts' output, plus the ingress summary when present. Classifies the secrets held by APIM and flags environment mixing, reused secret names, all-access subscriptions, leftover logger credentials and literal backend credentials. Resolves flagged Key Vault callers in Entra ID, drills into their log history and gives each a heuristic verdict. Writes a Markdown report and can compare with a previous run. |
| `Rotate-ApimCredential.ps1` | Opt-in, one-at-a-time subscription and legacy management key regeneration, APIM secret named-value updates, and Key Vault named-value refreshes. Requires a matching in-scope exposure scan and confirmation. |
| `Apim-Helpers.ps1` | Shared SKU, scope, identity, CLI, tenant and subscription selection, timestamp and response validation. Must remain alongside the entry scripts. |
| `docs/response-checklist.md` | Generic checklist for persistence checks, rotation and reporting steps. Not legal advice. |
| `docs/DEVLOG.md` | What changed in the scripts and why, plus open ideas. |
| `tests/` | Offline Pester 5 tests for scope, status decisions, audit-window queries, API failure handling, tenant selection and the ingress rules (CIDR width, NSG priority and deny shadowing, WAF assessment, per-mode reach, policy parsing), plus offline runs of the three older scripts and an end-to-end run of the ingress script's real main flow against the synthetic tenant in `tests/fixtures/ingress-tenant.json` (nine instances across every network mode, with an Application Gateway, both Front Door kinds, Traffic Manager, Azure Firewall DNAT and a private endpoint), with only the Azure calls stubbed. Run `Invoke-Pester ./tests`. GitHub Actions runs them on every pull request. |

## Requirements

- PowerShell 7+
- Keep `Apim-Helpers.ps1` alongside the entry scripts; clone/download the repository rather than copying one script alone
- Azure CLI (`az`), signed in with `az login`
- **Reader** on the subscriptions you want to cover (the ingress script also reads NSGs, gateways, Front Doors, firewalls and the APIM global policy, all covered by Reader)
- One tenant per run: the scripts read the enabled subscriptions of the current `az` tenant and say how many subscriptions they skip in each other tenant. For another tenant, run `az login --tenant <id>` and pass `-TenantId <id>`
- For the audit script: **Log Analytics Reader** on the workspaces that hold Key Vault logs
- For the follow-up analysis: also directory read access in Entra ID, to resolve object IDs

The four analysis scripts are read-only. **The separate rotation script changes Azure resources** and requires suitable write/action permissions in addition to Reader.

## Usage

```powershell
az login

# 1. Find Classic instances, network settings and secrets stored in APIM
pwsh ./Check-ApimExposure.ps1

# 1b. Who on the internet can reach the in-scope instances, through what, and how permissive is each path
pwsh ./Check-IngressExposure.ps1
# options: -TightPrefixLength 25 (treat /25 and smaller as tight; default 24), -AllInstances, -CheckGatewayPatch, -SkipPolicy

# 2. Review Key Vault audit logs for the incident window
pwsh ./Check-KeyVaultAudit.ps1
# optional: -WindowStart 2026-11-16 -WindowEnd 2026-11-21 -LookbackDays 90

# 3. Follow-up analysis of both outputs (same window as step 2)
pwsh ./Analyze-Findings.ps1
# later runs: compare with the previous result
pwsh ./Analyze-Findings.ps1 -OutDir ./incident-analysis-2 -CompareTo ./incident-analysis
```

### Running it in another tenant (for example a client's)

Each run reads one tenant: the one your `az` session is signed in to. For a client tenant, sign in there first and name it:

```powershell
az login --tenant <tenant-id>
pwsh ./Check-ApimExposure.ps1 -TenantId <tenant-id> -ImpactedResourcesCsv ./impacted-resources.csv
pwsh ./Check-IngressExposure.ps1 -TenantId <tenant-id>
```

You need Reader on the subscriptions that hold the instances. Nothing is written to Azure. The `-CheckGatewayPatch` option is off by default because it sends one HTTPS request to each instance's public gateway hostname; leave it off when you may only read configuration. The output folders hold that tenant's resource names, IDs and addresses: keep them out of the repository and share them only with the incident team.

Output goes to `./apim-exposure/`, `./ingress-exposure/`, `./kv-audit/` and `./incident-analysis/`. It contains real resource names, IDs, identities and IP addresses. **Do not commit it.** The folders, and report formats such as `.docx` and `.pdf`, are listed in `.gitignore`.

Windows are UTC, with an inclusive start and exclusive end. Timestamps without a timezone are treated as UTC; local timestamps are converted to UTC. Sub-day boundaries are preserved in queries and analysis snapshots. `WindowStart` must precede `WindowEnd`, and `LookbackDays` must be positive. If the window predates the requested lookback, the scripts warn that the logs may not cover it.

Warnings use PowerShell's warning stream. To preserve them locally, invoke the script directly from PowerShell, for example `.\Check-ApimExposure.ps1 3> .\scan-warnings.log`. Failed CLI commands, malformed responses, repeated continuation links and invalid required metadata never become successful empty scans. Log Analytics partial-error responses are treated as failed queries.

### Rotating credentials

Review [Microsoft's rotation guide](https://techcommunity.microsoft.com/blog/integrationsonazureblog/rotating-credentials-in-azure-api-management/4575478) and test in a non-production instance first. Run the exposure scan, review `scope.csv` and its preflight and failures, then select an explicit in-scope resource ID and credential. An in-scope finding is a precaution, not proof of compromise; an old scan may no longer reflect your environment. The script refuses targets absent from or excluded by `scope.csv`; it does not apply the SKU fallback.

Each invocation performs **one** operation and prompts for confirmation by default. `-WhatIf` previews without contacting Azure. Regenerating a key immediately invalidates that key: first move and test every caller on the other key; regenerate and test the replacement; move callers to it before separately regenerating the other key. Do not rotate both keys together. Management actions target the legacy Direct Management API, not Git keys.

```powershell
$id = '/subscriptions/<azure-subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.ApiManagement/service/<apim-name>'
# APIM subscription entity ID from apim-subscriptions.csv, not the Azure subscription ID
.\Rotate-ApimCredential.ps1 -ResourceId $id -Action SubscriptionPrimary -ItemId '<apim-subscription-id>' -WhatIf
.\Rotate-ApimCredential.ps1 -ResourceId $id -Action SubscriptionPrimary -ItemId '<apim-subscription-id>'
# Only after callers have switched and been tested:
.\Rotate-ApimCredential.ps1 -ResourceId $id -Action SubscriptionSecondary -ItemId '<apim-subscription-id>'
.\Rotate-ApimCredential.ps1 -ResourceId $id -Action ManagementPrimary
.\Rotate-ApimCredential.ps1 -ResourceId $id -Action ManagementSecondary

# Named value ID from named-values.csv; the replacement is prompted for with hidden input
.\Rotate-ApimCredential.ps1 -ResourceId $id -Action NamedValue -ItemId '<named-value-id>'
.\Rotate-ApimCredential.ps1 -ResourceId $id -Action RefreshKeyVault -ItemId '<named-value-id>'
```

For named values, first create the replacement at its issuer. For Key Vault references, store the replacement in Key Vault and update any version-pinned reference before refresh. A `202 Accepted` response is **not completion**: check provisioning and test before revoking the old credential. The script does not read or print existing secrets, but avoid terminal recording and transcripts when entering replacements. Updating APIM does not revoke the old issuer credential. See [the response checklist](docs/response-checklist.md#2-rotate) for backend, OAuth, identity provider, logger, certificate, policy, Git and other externally managed credentials, which are not automatically changed.

### Reading the follow-up analysis

`analysis-report.md` summarises everything. The CSVs next to it hold the details:
- `flags.csv`
- `named-value-categories.csv`
- `subscription-scopes.csv`
- `backend-credentials.csv`
- `logger-credentials.csv`
- `caller-drilldown.csv`
- `caller-ip-history.csv`
- `caller-clients.csv`
- `flagged-ip-other-callers.csv`

**Caller verdicts.** Each caller the audit script flagged is checked against its own history in the logs:

| Verdict | When |
|---|---|
| `SUSPICIOUS` | An APIM managed identity was used from an unexpected IP, or the identity can't be found in the directory. |
| `INVESTIGATE` | The identity was never seen before the window, its in-window requests failed, it used a client not seen before, or its volume was more than three times its own baseline. |
| `NOT ANALYSED` | Directory lookup or log queries failed, required log data is unavailable, or live checks were skipped. A failed directory lookup is not evidence that an identity was deleted. |
| `LIKELY CI/CD` | A known service principal or managed identity with a known client, calling from an Azure address or with an automation client such as Terraform. |
| `LIKELY BENIGN` | A known identity and client calling from a new IP. |

These are indicators, not proof. A stolen credential used with the same tool would look the same, so confirm every case with the owner, the sign-in logs or the pipeline history.

**Other heuristics.**
- **Environment** is inferred from names. Names without a `test`/`dev`/`prod` style marker are assumed to be production.
- **Secret types** are inferred from display names.
- **Backends** are checked for credential structure only. Credential values returned by the management API are inspected in memory to count literals and references; they are never printed or written out.

**Comparing runs.** `-CompareTo` lists what changed since the earlier run's `snapshot.json`: instance status, ingress status, vault verdicts, caller verdicts, flags and totals. Compare runs made in the same mode. A `-SkipLive` run has no backend, logger or caller data, so those show up as changes.

**Failed live checks.** If backend or logger enumeration fails, analysis stops with the failed URL and API error instead of treating inaccessible objects as an empty list. Resolve the error and rerun before relying on the output; files from an earlier or interrupted run may still be present.

### Reading the first script's output

1. Check the preflight line first. `Preflight clean` means every subscription was readable and the direct and Resource Graph counts agree. Any warning means those subscriptions were not properly checked.
2. The per-instance summary uses these statuses: `LIKELY EXPOSED`, `REVIEW` and `UNCHECKED`. There is deliberately no "safe" status, because the script cannot prove that nothing was accessed.
   - `LIKELY EXPOSED` means there is no VNet or private endpoint, or APIM holds secrets itself. That covers secret named values not in Key Vault, certificates uploaded directly, and identity provider, OpenID Connect or authorization server configurations, which may carry client secrets.
   - `UNCHECKED` means the SKU or network metadata is unknown, or named values, certificates or those client-secret objects could not be listed. Object kinds that the pricing tier explicitly reports as unsupported, such as identity providers on Consumption, are not counted as failures. Direct management API and Git checks are `n/a` on Consumption and v2.
   - Only `Approved` private endpoints count as protection. Pending and rejected connections do not. `approvedPrivateEndpoints` in `summary.csv` records the approved count; unknown connection states produce a warning and `UNCHECKED`.
   - `loggerCredentials` counts the `Logger-Credentials-…` named values that APIM creates for Application Insights loggers. They are shown separately from `secretsInApim` and don't affect the status. Repeated deployments can leave many of them behind.
3. `activeSubscriptions`, `directMgmtApi` and `gitAccess` are there for rotation planning and do not change the status. Every active APIM subscription has keys held in APIM. If `directMgmtApi` is `True`, management tokens could have been issued. `gitAccess` is often `True` without anyone having turned it on, and its keys exist either way. Subscription metadata goes to `apim-subscriptions.csv`. The keys themselves are never read.
4. Backends are listed in `other-secret-objects.csv` but their credentials (basic-auth headers, client certificates) are not inspected. Review them by hand.

### Reading the second script's output

- A vault counts as reachable when an APIM identity has an access policy on it, or a role that gives one of these:
  - data access on an RBAC-mode vault, such as Key Vault Secrets User;
  - the right to create role assignments, such as Owner or User Access Administrator;
  - the right to write vault settings or access policies on an access-policy vault, such as Contributor.
  Assignments that give none of these, such as Reader, go to `excluded-role-assignments.csv`. Roles that cannot be resolved are counted as reachable.
- An unknown vault authorization mode produces a warning and includes both possible authorization paths rather than silently excluding an RBAC-only grant.
- Role assignments inherited from management groups and the tenant root are included.
- Expected source IPs include the instance's primary and additional-region public/private addresses, including multi-region Premium deployments.
- `SUSPICIOUS - review` means an APIM identity was used **inside the selected window** from an address that is not one of the instance's own, or a caller and IP pair that was not seen before the window read secrets, keys or certificates inside it. New pairs can be benign. Investigate before concluding anything.
- `REVIEW` means there was APIM identity activity whose source IP cannot be checked. Either the instance has no static IP, or the log row has no caller IP.
- The script warns when authenticated data-plane rows lack a caller IP or object ID, which usually means the column mapping doesn't match that workspace. Such gaps prevent a `no anomaly found` verdict and produce `PARTIAL COVERAGE` unless another finding already requires investigation. 401 authentication challenges and control-plane operations such as `VaultGet` are left out, because they never carry an object ID.
- The script warns when the logs start later than `-LookbackDays`, which usually means the workspace's retention is shorter. The warning also says roughly when the window's first day will age out. `baselineDays` in `vault-verdicts.csv` shows how much history came before the window. With a short baseline, ordinary callers often show up as new, such as CI agents on changing IPs or admins on another network. Check the client and the caller's history before treating one as suspicious.
- `NO AUDIT LOGGING`, `NO LOG DATA` and `PARTIAL COVERAGE` mean there is no evidence either way. Treat those vaults as potentially accessed.
- `DIAGNOSTIC SETTINGS FAILED` means the script could not read or interpret the logging settings; it does not mean logging was disabled. The API/schema error is retained in `vault-logging.csv` and the verdict's `note`.
- `no anomaly found in available logs` requires the earliest and latest log timestamps to bracket the selected window, with complete caller fields. `logsFrom` and `logsTo` in `vault-verdicts.csv` expose those bounds. This is conservative: a quiet vault may receive `PARTIAL COVERAGE` even if logging was enabled. Bracketing timestamps still do not prove continuous logging or the absence of misuse.

### Reading the ingress output

`Check-IngressExposure.ps1` answers one question per instance: who on the internet can reach it, through what, and how permissive is each path. It uses `apim-exposure/scope.csv` when present (so it follows Microsoft's impacted-resources list), validated the same way as the audit and analysis scripts do, otherwise the shared tier rule, under which an unrecognized SKU is retained and analysed like a Classic tier; `-AllInstances` analyses everything.

Two endpoints matter for this incident:
- **The management endpoint on port 3443**: the service configuration endpoint on every Classic instance's public VIP, used by Azure's control plane (and formerly by the direct management API). Microsoft's reference NSG rule allows it only from the `ApiManagement` service tag.
- **The 443 endpoints**: gateway, developer portal, Git and the management hostname (`*.management.azure-api.net`).

**Source classes**, from most to least permissive: `OPEN` (the whole internet: `*`, `Internet`, `0.0.0.0/0`), `BROAD` (a public range wider than the tight threshold, or `AzureCloud`, which includes other customers' VMs), `AZURE-SHARED` (a multi-tenant service tag such as `AzureFrontDoor.Backend`: any tenant's Front Door), `TIGHT` (a public range at or below the threshold, default /24; set `-TightPrefixLength 25` to require /25 or smaller), `CONTROL-PLANE` (`ApiManagement`, `GatewayManager`, `AzureLoadBalancer`, `AzureTrafficManager`), `VNET` and `PRIVATE`. The address count of each range is in the CSVs, so you can sort by size regardless of the threshold.

**Per-instance status** (`ingress-summary.csv`, console):

| Status | Meaning |
|---|---|
| `OPEN` | The management endpoint or a 443 endpoint is reachable from the whole internet with nothing in front of it that blocks. A WAF in detection mode, a disabled WAF or a bypassable WAF does not count as blocking. |
| `BROAD` | The widest unmitigated path admits a wide range, a multi-tenant service tag or an unrecognised source. |
| `FILTERED` | Only tight ranges, or open paths that all sit behind a prevention-mode WAF that cannot be bypassed. |
| `PRIVATE` | Nothing beyond the Azure control plane, the VNet or private ranges. |
| `UNCHECKED` | The APIM subnet or its NSG could not be read. |

`managementReach` and `gatewayReach` say where each endpoint can be reached from. `CONTROL-PLANE ONLY` on the management endpoint means only Microsoft-operated service tags are admitted; Microsoft's reference is the `ApiManagement` tag, and any other control-plane tag on 3443 is listed for review. Consumption and v2 instances have no dedicated 3443 endpoint and show `n/a` there; an instance with an unrecognized SKU is analysed as if it had one, and its `tierFamily` says `Unknown`. In VNet modes the answer comes from the NSG on the APIM subnet (every location of a multi-region instance); without a VNet it comes from `publicNetworkAccess` and the private endpoints. Whether disabling public network access also closes the developer portal, Git and management hostnames is not documented by Microsoft; the script treats it as closing them and says so.

**Pathways** (`ingress-pathways.csv`, one row per way in): `direct (public VIP)`, `Application Gateway` (listener to backend pool, with the most specific WAF policy: path rule, then listener, then gateway, then the inline configuration; the gateway subnet's NSG refines the source class), `Front Door` and `Front Door (classic)` (origin or backend to route and domain, with the security policy's WAF), `Traffic Manager` (DNS only; exposure equals the target's own), `Azure Firewall DNAT` (rule sources, IP groups expanded) and `private endpoint`. `bypassable` is true when a WAF fronts the gateway but the instance also answers directly from the internet and neither checks `X-Azure-FDID` nor filters source addresses.

**NSG rows** (`nsg-inbound-rules.csv`): every inbound allow rule on the APIM subnet that admits TCP traffic to 80, 443, 3443 or 6390, one row per source value, with the higher-priority deny that shadows it (`effective = False`) or partly restricts it, and an assessment against Microsoft's reference. Other ports open to wide sources are listed as `other`. Service tags are not expanded.

**WAF rows** (`waf-policies.csv`, `waf-custom-rules.csv`): verdict (`PREVENTION`, `DETECTION ONLY`, `WAF DISABLED`, and `PREVENTION (no blocking rules)` or `PREVENTION (custom allow admits everyone)` for policies that block nothing; only a plain `PREVENTION` counts as mitigating), managed rule sets, disabled or weakened managed rules, exclusions, and each custom rule's assessment: an Allow for an open or broad range (`PERMISSIVE ALLOW`) or without a source restriction (`ALLOW BYPASS`) skips the managed rules; a Block with a negated address match is an `ALLOWLIST`.

**Global policy** (`apim-policy-controls.csv`): an `ip-filter` allowlist and its width, and whether an `X-Azure-FDID` `check-header` exists (unconditional or inside a `choose`). Policies protect API requests at the gateway only, never the management endpoint, the developer portal or Git.

**Patch level** (`-CheckGatewayPatch`, `gateway-patch-status.csv`): calls `https://<gateway>/internal-status-0123456789abcdef` on each instance's default gateway hostname and compares `RuntimeVersion` with NSM's thresholds (0.52.x patched from build 31936, 0.53.x from 31938; other patterns are v2/Consumption). Microsoft has not documented this endpoint; an unreachable or unparseable answer is `unknown`, never `patched`. Internal-mode instances are not reachable from outside their VNet.

`ingress-report.md` gathers the key numbers, the per-instance table, the permissive pathways, the NSG findings, the WAF policies and what to do about each finding, with Microsoft's own guidance linked.

## Known limitations

- Resource Graph hides resources you cannot read without reporting an error. The first script's preflight is meant to catch this, but it cannot see everything, for example deny assignments.
- Role assignments are only visible if your account can read them. A tenant administrator should confirm managed identity permissions for important instances.
- Group membership is not expanded. A role given to a group that contains an APIM identity is not detected.
- The vault-access check tests a small set of representative Key Vault operations against each role definition. Unusual custom roles may be classified incorrectly.
- Consumption-tier instances have no static IP, so the source-IP check cannot be applied to them. They also have no direct management API or Git access to check.
- Azure service-tag classification in the analysis is IPv4-only. IPv6 callers have an unknown Azure-IP classification, not a confirmed non-Azure classification.
- Log queries read both the `AzureDiagnostics` and the resource-specific `AZKVAuditLogs` schema. The `AZKVAuditLogs` column names were checked against Microsoft's table reference. The object-ID claim layout was not verified in every workspace.
- Access through any unlogged path will not appear in Key Vault's logs.
- The ingress script infers reachability from configuration; it does not probe. Service tags are opaque, partial denies are reported but not subtracted, only the global policy is read, and front ends it does not know (a reverse proxy on a VM, a non-Azure CDN) are not seen.
- `Check-ApimExposure.ps1`, `Check-KeyVaultAudit.ps1`, `Analyze-Findings.ps1` and `Rotate-ApimCredential.ps1` were written and tested on Windows with PowerShell 7. `Check-IngressExposure.ps1` was developed on macOS with PowerShell 7.7, where the whole test suite also passes.
- Azure Resource Manager is called directly with a token from `az account get-access-token`, not through `az rest`. On Windows, `az` is a batch file that cuts URLs at `&`, which broke paging in earlier versions.

## Offline validation

The regression suite covers all nine supported SKU names, unknown values, scope-file decisions, booleans, managed identities, API failures, paging, audit windows and log-response schemas. Workflow tests execute the exposure, audit and analysis scripts with synthetic data and mocked CLI/HTTP calls, and an end-to-end test runs the ingress script's main flow against `tests/fixtures/ingress-tenant.json` the same way; none of them contact Azure.

```powershell
Import-Module Pester -RequiredVersion 5.7.1
Invoke-Pester .\tests
```

GitHub Actions uses the same pinned Pester version and parses every PowerShell file.

## Contributing

Issues and pull requests are welcome, especially fixes for schema differences and other platforms. Please do not include real tenant data in issues or pull requests.

## Author

Mathias Haas, Fidelity Consulting AB

Contact (base64-encoded): `bWF0aGlhcy5oYWFzQGZpZGVsaXR5Y29uc3VsdGluZy5zZQ==`

## License

[MIT](LICENSE). The scripts are provided as is, without warranty of any kind. You are responsible for reviewing them and verifying their results before acting on them.
