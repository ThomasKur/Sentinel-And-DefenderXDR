# *Delete an Intune Multi Approval Policy by User with uncommon or risky behavior*

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1072 | Software Deployment Tools | <https://attack.mitre.org/techniques/T1072/> |

### Description

Detects deletion of Intune multi-approval policies by users exhibiting risky behavior, mapped to Software Deployment Tools (T1072). Typically informational/operational, but if an attacker persuades another admin to approve deletion, it removes safeguards and can enable unauthorized app or script deployment. Triggers when Medium/High risk users, suspicious behaviors (impossible travel, unusual locations, suspicious admin activity), or delegated admins perform the deletion.

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

Potential Remediation Action: Mark User as Compromised or Disable Account

```KQL
IntuneAuditLogs 
| where OperationName == "Delete OperationApprovalPolicy"
| extend Actor = extract_json("$.Actor", Properties, typeof(string))
| extend IsDelegatedAdmin = extract_json("$.IsDelegatedAdmin", Actor, typeof(bool))
| extend PartnerTenantId = extract_json("$.PartnerTenantId", Actor, typeof(guid))
| extend AccountObjectId = extract_json("$.ObjectId", Actor, typeof(guid))
| join kind=leftouter (BehaviorEntities
    | where ActionType in ("ActivityFromInfrequentCountry", "ImpossibleTravelActivity", "SuspiciousAdministrativeActivity","SuspiciousImpersonatedActivity","UnusualAdditionOfCredentialsToAnOauthApp")
    | where EntityType == "User"
    | summarize RiskBehaviors=make_list(ActionType), RiskBehaviorCount=count() by AccountName, BehaviorId) on $left.Identity == $right.AccountName
// Add User Risk Status
| join kind=leftouter (IdentityInfo | where RiskLevel != "" and Type == "User") on $left.Identity == $right.AccountUpn
| join kind=leftouter GraphAPIAuditEvents on $left.CorrelationId == $right.ClientRequestId
| where 
    // Trigger for all users when risky or behaviors are seen.
    (RiskLevel in ("Medium","High") or RiskBehaviorCount > 0) or
    // Trigger for Delegated Admin Users (Idea could be to check if the login is originating from Compliant Device.)
    (IsDelegatedAdmin)
```
