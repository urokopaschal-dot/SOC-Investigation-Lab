# End-to-End SOC Investigation Lab

## Project Overview

This project simulates a cyber attack on a Windows system and demonstrates how a SOC Analyst can investigate malicious activity using Splunk and Sysmon.

The attack chain includes:

* PowerShell execution
* Scheduled Task persistence
* Registry Run Key persistence

The objective is to identify attacker activity, build a timeline, and map findings to the MITRE ATT&CK framework.

## Tools Used

* Windows 10 VM
* Splunk
* Sysmon
* PowerShell
* Command Prompt

## Attack Simulation

### Step 1 – PowerShell Execution

The attacker executes an obfuscated PowerShell command.

```powershell
powershell.exe -nop -w hidden -enc SQBFAFgA
```

### Step 2 – Scheduled Task Persistence

The attacker creates a scheduled task.

```cmd
schtasks /create /sc onlogon /tn EvilTask /tr "notepad.exe"
```

### Step 3 – Registry Run Key Persistence

The attacker creates a registry Run Key.

```cmd
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v EvilRun /t REG_SZ /d notepad.exe
```

## Detection Queries

### Detect PowerShell

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| stats count by _time ParentImage Image CommandLine
```

### Detect Scheduled Tasks

```spl
index=sysmon EventCode=1 CommandLine="*schtasks*"
| stats count by _time Image ParentImage CommandLine
| sort -_time
```

### Detect Registry Persistence

```spl
index=sysmon EventCode=13
TargetObject="*run*"
| stats count by Image TargetObject Details
```

## MITRE ATT&CK Mapping

| Activity             | Technique ID |
| -------------------- | ------------ |
| PowerShell Execution | T1059.001    |
| Scheduled Task       | T1053.005    |
| Registry Run Key     | T1547.001    |

## Findings

The investigation identified suspicious PowerShell activity and multiple persistence mechanisms. Splunk queries successfully detected attacker behavior, and Sysmon logs provided the telemetry required to reconstruct the attack timeline.

## Conclusion

This project demonstrates how a SOC Analyst can detect and investigate malicious activity using Splunk and Sysmon while mapping findings to the MITRE ATT&CK framework.
