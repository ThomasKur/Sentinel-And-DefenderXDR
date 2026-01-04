# *Managed Service Provider User (B2B or GDAP) without Device Compliance or MFA claim is managing Intune*

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1072 | Software Deployment Tools | <https://attack.mitre.org/techniques/T1072/> |
| T1562 | Impair Defenses | <https://attack.mitre.org/techniques/T1562/> |

### Description

This detection monitors Managed Service Provider (MSP) and delegated admin access (GDAP) users managing Intune without enforcing device compliance or multi-factor authentication (MFA) claims. This is a critical security control to ensure that external service providers meet your organization's security baseline. Disabling or bypassing compliance policies is a form of defense evasion.
**Important:** Before enabling this detection, verify your current MSP/GDAP providers and ensure they support [cross-tenant access](https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview) policy configurations. Providers that cannot meet these security requirements should either be whitelisted with appropriate justification or removed from your trusted service provider list.
Mapped to MITRE ATT&CK **T1072 - Software Deployment Tools**, as Intune MSPs typically have broad deployment capabilities.

### Author

- **Name: Thomas Kurth**
- **Github: <https://github.com/ThomasKur/Sentinel-And-DefenderXDR>**
- **LinkedIn: <https://www.linkedin.com/in/thomas-kurth-a86b7851/>**
- **Medium: <https://medium.com/@kurtli_thomas>**

## Defender XDR

Mapping Proposal:

- Impacted Assets
  - AadUserId > Column: AccountObjectId
- Related Evidence
  - IP > Column: IpAddress

Potential Remediation Action: None

```KQL
IntuneAuditLogs 
| extend Actor = extract_json("$.Actor", Properties, typeof(string))
| extend IsDelegatedAdmin = extract_json("$.IsDelegatedAdmin", Actor, typeof(bool))
| extend PartnerTenantId = extract_json("$.PartnerTenantId", Actor, typeof(guid))
| extend IdentityObjectId = extract_json("$.ObjectId", Actor, typeof(string))
| join kind=leftouter (IdentityInfo
    | where Timestamp > ago(14d)
    | where Type == "User" and AccountUpn contains "#EXT#"
    | project IdentityId, AccountObjectId
    | extend Guest=true)
    on $left.IdentityObjectId == $right.AccountObjectId
| where IsDelegatedAdmin == true or Guest == true
| join kind=inner GraphAPIAuditEvents on $left.CorrelationId == $right.ClientRequestId
| join kind=leftouter (EntraIdSignInEvents
    | project
        AccountObjectId,
        AccountUpn,
        IPAddress,
        DeviceTrustType,
        AuthenticationRequirement,
        IsCompliant
    | distinct *)
    on $left.IpAddress == $right.IPAddress and $left.AccountObjectId == $right.AccountObjectId
| where IsCompliant != 1 or AuthenticationRequirement != "multiFactorAuthentication"
```
