# Windows Service Installation Detection — Splunk (Event ID 7045)

---

## What this is

A Splunk detection for Windows service installation using Event ID 7045. The rule surfaces new service installs by pulling the service name, executable path, account context, and host from Windows System logs.

Compared to earlier authentication-focused labs, this one sat closer to actual persistence detection — the kind of activity that shows up in real intrusions, not just login noise.

---

## Environment

| Component | Details |
|-----------|---------|
| SIEM | Splunk Enterprise 10.2.3 |
| OS | Windows VM |
| Log source | Windows System Logs |
| Event ID | 7045 |
| Forwarder | Splunk Universal Forwarder |

---

## Detection query

```spl
index=* EventCode=7045
| table _time host ComputerName Service_Name Service_Account Service_Type
```

---

## What it detects

Windows logs Event ID 7045 whenever a new service is installed. Attackers abuse service installation for:

- persistence across reboots
- privilege escalation via service accounts
- malware execution under a disguised service name
- deploying remote access tooling as a registered service

---

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Windows Service | T1543.003 |

---

## Test activity

Telemetry was generated using:

```cmd
sc create TestService binPath= "C:\Windows\System32\cmd.exe"
```

The event appeared in Splunk after querying `EventCode=7045`.

---

## Important fields observed

| Field | Purpose |
|-------|---------|
| `Service_Name` | Name of the installed service |
| `Service_File_Name` | Executable path |
| `Service_Account` | Account the service runs under |
| `Service_Type` | Type of service |
| `ComputerName` | Host that generated the event |

---

## Interesting finding

The test service pointed to `C:\Windows\System32\cmd.exe`. That's a legitimate Windows binary — which is exactly the problem. The raw event exposed the full executable path, startup type, service account, and service type, so even when an attacker uses a trusted binary, 7045 gives you enough context to flag it.

That's what makes this event worth monitoring. The binary name alone won't always look suspicious. The combination of fields tells the real story.

---

## Alert creation

The detection query was turned into a Splunk alert:

```text
Suspicious Service Installation
```

Trigger condition:

```text
Number of Results > 0
```

The goal was the same as prior labs — go through the full workflow from telemetry generation to a firing alert, not just write a query and stop.

---

## Cleanup

Test service was removed after validation:

```cmd
sc delete TestService
```

---

## Screenshots

| Screenshot | File |
|--|--|
| Raw event inspection | `screenshots/7045-raw-event.png` |
| Query results | `screenshots/7045-query-results.png` |
| Alert configuration | `screenshots/7045-alert-config.png` |

---

## What I took away from this

Service installation events are operationally more interesting than authentication logs. The executable path, service account, and service type are all right there in the raw event — which means a defender can catch LOLBin abuse and suspicious service names without needing additional correlation.

The bigger takeaway was understanding why 7045 matters in a real environment. Attackers registering persistence through services isn't rare, and the field visibility this event gives you is good enough to build useful detections on, even without enrichment.

---