# Splunk Queries Used

## PowerShell Execution

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| stats count by _time Image ParentImage CommandLine
| sort -_time
```

## Scheduled Task Detection

```spl
index=sysmon EventCode=1 CommandLine="*schtasks*"
| stats count by _time Image ParentImage CommandLine
| sort -_time
```

## Registry Persistence

```spl
index=sysmon EventCode=13
TargetObject="*run*"
| stats count by Image TargetObject Details 
```

## Process Creation Overview

```spl
index=sysmon EventCode=1
| stats count by Image
```

## Attack Timeline

```spl
index=sysmon
| table _time Computer Image CommandLine EventCode
| sort _time
```
