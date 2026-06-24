# Incident Report

## Executive Summary

A simulated attack was conducted on a Windows endpoint. The investigation identified malicious PowerShell execution and persistence mechanisms.

## Timeline

### Initial Access

PowerShell execution detected.

### Persistence

Scheduled task created.

### Persistence

Registry Run Key created.

## Indicators

* powershell.exe
* schtasks.exe
* Registry Run Key modification

## MITRE ATT&CK

* T1059.001
* T1053.005
* T1547.001

## Recommendations

* Restrict PowerShell execution.
* Monitor scheduled task creation.
* Monitor registry persistence locations.
* Enable Sysmon logging across endpoints.

## Status

Investigation Complete.
