# *User with uncommon or risky behavior is deploying an Application with Intune to All Users or All Devices*

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1072 | Software Deployment Tools | <https://attack.mitre.org/techniques/T1072/> |

### Description

Detects when users exhibiting risky behavior use Intune's Software Deployment Tools (T1072) to deploy applications to all users or devices. Alerts when accounts with Medium/High risk levels, suspicious behavioral indicators (impossible travel, unusual locations, suspicious admin activity), or delegated admin status execute app assignments with "Required" intent targeting "AllLicensedUsersAssignmentTarget" or "AllDevicesAssignmentTarget" groups. This enables adversaries to distribute malicious or unwanted applications across the organization.

The recommended severity level for this detection is low or medium as mass deployments can be as well a normal operational action.

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
| where OperationName == 'Create MobileAppAssignment' or OperationName == 'Patch MobileAppAssignment'
| where  ResultType == 'Success'
| where isnotempty(Properties)
| extend props = parse_json(Properties)
| extend AuditEventId = tostring(props.AuditEventId)
| mv-apply T = props.Targets on (
    // Expand each target's ModifiedProperties (keeps targets even if ModifiedProperties is empty)
    mv-expand MP = T.ModifiedProperties
    // Compute counts of the required signals within the SAME target
    | summarize
        intentRequiredCount = countif(MP.Name == "Intent" and tostring(MP.New) == "Required"),
        targetTypeCount     = countif(MP.Name == "Target.Type" and tostring(MP.New) in ("AllLicensedUsersAssignmentTarget","AllDevicesAssignmentTarget"))
      by AuditEventId, TargetKey = coalesce(tostring(T.Name), tostring(T))
    // Keep only targets that have BOTH signals
    | where intentRequiredCount > 0 and targetTypeCount > 0
)
// Collapse back to the row level and return the matching rows
| summarize matched = count() by AuditEventId
| where matched > 0
// Rejoin to the full original row if you want all columns
| join kind=inner (
    IntuneAuditLogs
    | extend props = parse_json(Properties)
    | extend AuditEventId = tostring(props.AuditEventId)
) on AuditEventId
| project-away AuditEventId1
| extend Actor = extract_json("$.Actor", Properties, typeof(string))
| extend IsDelegatedAdmin = extract_json("$.IsDelegatedAdmin", Actor, typeof(bool))
| extend PartnerTenantId = extract_json("$.PartnerTenantId", Actor, typeof(guid))
| extend AccountObjectId = extract_json("$.ObjectId", Actor, typeof(guid))
// Check for Risky Events
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
