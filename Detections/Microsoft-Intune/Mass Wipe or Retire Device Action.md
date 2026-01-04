# *Mass Wipe / Retire Device Action*

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1072 | Software Deployment Tools | <https://attack.mitre.org/techniques/T1072/> |
| T1485 | Data Destruction | <https://attack.mitre.org/techniques/T1485/> |

### Description



### Author

- **Name: Thomas Kurth**
- **Github: <https://github.com/ThomasKur/Sentinel-And-DefenderXDR>**
- **LinkedIn: <https://www.linkedin.com/in/thomas-kurth-a86b7851/>**
- **Medium: <https://medium.com/@kurtli_thomas>**

## Defender XDR

Mapping Proposal:

- Impacted Assets
  - AadUserId > Column: AccountObjectId


Potential Remediation Action: Mark User as Compromised or Disable Account

```KQL
let WipeThreashold = 5; // A normal engineer is not wiping more than 5 devices per hour. Can be adjusted for the environment.
IntuneAuditLogs 
| where OperationName in('wipe ManagedDevice','retire ManagedDevice')
| where  ResultType == 'Success'
| where isnotempty(Properties)
| extend Targets = extract_json("$.Targets", Properties, typeof(dynamic))
| extend TargetCount= array_length(Targets)
| extend Actor = extract_json("$.Actor", Properties, typeof(string))
| extend AccountObjectId = extract_json("$.ObjectId", Actor, typeof(guid))
| summarize TotalWipeOrRetireTargetCount=sum(TargetCount), TimeGenerated=min(TimeGenerated), Identity=min(Identity) by AccountObjectId
| where TotalWipeOrRetireTargetCount > WipeThreashold
```
