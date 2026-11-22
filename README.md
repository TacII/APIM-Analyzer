# apim-incident-tools

Read-only PowerShell scripts for checking whether an Azure tenant may be affected by the **Azure API Management (APIM) Classic-tier security issue** that Microsoft notified customers about in November 2026, and for reviewing Key Vault audit logs for signs of misuse.

> **Status: untested, community-style tooling.** The scripts were written quickly during an incident and have been run in only one environment. Review them before running, and verify results independently. They do not replace Microsoft's guidance or your own security team's judgement.

## Background

Microsoft's notice states that a security issue affected APIM **Classic** tiers (Consumption, Developer, Basic, Standard, Premium) but not the **v2** tiers. It was identified on 18 November 2026 and the access path was closed on 19 November 2026. Instances may have been accessed if they:

- lacked the network integration described in Microsoft's "Network security" guidance for secret management, or
- stored secrets in APIM instead of referencing them from Azure Key Vault.

Potentially exposed items include named-value secrets, identity provider and OpenID Connect client secrets, subscription keys and management tokens.

Because the exact reach of the issue is not fully documented, these tools also look at Key Vaults that APIM managed identities can reach. That is a precaution, not a confirmed attack path.

## What is in this repo

| File | Purpose |
|---|---|
| `Check-ApimExposure.ps1` | Finds APIM instances across all subscriptions you can read, flags Classic tiers, and checks network settings. Lists named values, certificates, identity providers and other secret-bearing objects, APIM subscriptions, and whether the direct management API and Git access are enabled. Also maps what each instance's managed identity can reach. |
| `Check-KeyVaultAudit.ps1` | Standalone. Finds the vaults that APIM managed identities can read from, or can grant themselves access to. Checks whether audit logging is enabled, and queries Log Analytics for identity activity and new callers in a time window. |
| `docs/response-checklist.md` | Generic checklist for persistence checks, rotation and reporting steps. Not legal advice. |

## Requirements

- PowerShell 7+
- Azure CLI (`az`), signed in with `az login`
- **Reader** on the subscriptions you want to cover
- For the audit script: **Log Analytics Reader** on the workspaces that hold Key Vault logs

Neither script changes anything in Azure. Both only read.

## Usage

```powershell
az login

# 1. Find Classic instances, network settings and secrets stored in APIM
pwsh ./Check-ApimExposure.ps1

# 2. Review Key Vault audit logs for the incident window
pwsh ./Check-KeyVaultAudit.ps1
# optional: -WindowStart 2026-11-16 -WindowEnd 2026-11-21 -LookbackDays 90
```

Output goes to `./apim-exposure/` and `./kv-audit/` as CSV files. These contain real resource names, IDs and IP addresses. **Do not commit them** (they are listed in `.gitignore`).

### Reading the first script's output

1. Check the preflight line first. `Preflight clean` means every subscription was readable and the direct and Resource Graph counts agree. Any warning means those subscriptions were not properly checked.
2. The per-instance summary uses these statuses: `LIKELY EXPOSED`, `REVIEW` and `UNCHECKED`. There is deliberately no "safe" status, because the script cannot prove that nothing was accessed.
   - `LIKELY EXPOSED` means there is no VNet or private endpoint, or APIM holds secrets itself. That covers secret named values not in Key Vault, certificates uploaded directly, and identity provider, OpenID Connect or authorization server configurations, which may carry client secrets.
   - `UNCHECKED` means named values, certificates or those client-secret objects could not be listed.
3. `activeSubscriptions`, `directMgmtApi` and `gitAccess` are there for rotation planning and do not change the status. Every active APIM subscription has keys held in APIM. If `directMgmtApi` is `True`, management tokens could have been issued. Subscription metadata goes to `apim-subscriptions.csv`. The keys themselves are never read.

### Reading the second script's output

- A vault counts as reachable when an APIM identity has an access policy on it, or a role that gives one of these:
  - data access on an RBAC-mode vault, such as Key Vault Secrets User;
  - the right to create role assignments, such as Owner or User Access Administrator;
  - the right to write vault settings or access policies on an access-policy vault, such as Contributor.
  Assignments that give none of these, such as Reader, go to `excluded-role-assignments.csv`. Roles that cannot be resolved are counted as reachable.
- Role assignments inherited from management groups and the tenant root are included.
- `SUSPICIOUS - review` means an APIM identity was used from an address that is not one of the instance's own, or a caller and IP pair that was not seen before the window read secrets, keys or certificates. New pairs can be benign. Investigate before concluding anything.
- `REVIEW` means there was APIM identity activity whose source IP cannot be checked. Either the instance has no static IP, or the log row has no caller IP. The script also warns when log rows lack a caller IP or object ID, which usually means the column mapping doesn't match that workspace.
- `NO AUDIT LOGGING`, `NO LOG DATA` and `PARTIAL COVERAGE` mean there is no evidence either way. Treat those vaults as potentially accessed.
- `no anomaly found in available logs` only covers the period and data that were actually logged.

## Known limitations

- Resource Graph hides resources you cannot read without reporting an error. The first script's preflight is meant to catch this, but it cannot see everything, for example deny assignments.
- Role assignments are only visible if your account can read them. A tenant administrator should confirm managed identity permissions for important instances.
- Group membership is not expanded. A role given to a group that contains an APIM identity is not detected.
- The vault-access check tests a small set of representative Key Vault operations against each role definition. Unusual custom roles may be classified incorrectly.
- Consumption-tier instances have no static IP, so the source-IP check cannot be applied to them. They also have no direct management API or Git access to check.
- Log queries read both the `AzureDiagnostics` and the resource-specific `AZKVAuditLogs` schema. The `AZKVAuditLogs` column names were checked against Microsoft's table reference. The object-ID claim layout was not verified in every workspace.
- Access through any unlogged path will not appear in Key Vault's logs.
- Written and tested on Windows with PowerShell 7. Behaviour elsewhere is unknown.

## Contributing

Issues and pull requests are welcome, especially fixes for schema differences and other platforms. Please do not include real tenant data in issues or pull requests.

## License

No license has been chosen yet. Until one is added, all rights are reserved by the author.
