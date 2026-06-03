<img width="1440" height="840" alt="image" src="https://github.com/user-attachments/assets/d940d85e-c142-4bd9-ba18-cda5b5788ed8" />

# Home Detection Lab Architecture

## Overview

Two laptop home lab running VirtualBox hypervisors with Wazuh SIEM, Windows 11 endpoint, and Kali Linux attack simulation VM. All endpoint telemetry flows to a centralised Wazuh dashboard for detection rule validation.

---

## Architecture Diagram

```
Intel Laptop (i5, 24 GB RAM)
        |
        └──> VirtualBox
                  |
                  └──> Wazuh VM (OVA 4.14.4, 8 GB RAM, x.x.1.12)
                                |
                                └──> Wazuh Dashboard
                                          ^
                                          |  (system events)
                                          |
AMD Laptop (Ryzen 5000, 24 GB RAM)        |
        |                                 |
        └──> VirtualBox                   |
                  |                       |
                  |──> Win 11 VM ─────────┤
                  |    Sysmon + Wazuh agent
                  |                       |
                  └──> Kali Linux VM ─────┘
                       YARA + Snort + Zeek
```

---

## Components

### Intel Laptop — Wazuh Server

| Component | Detail |
|-----------|--------|
| Hardware | Intel i5, 24 GB RAM |
| Hypervisor | Oracle VirtualBox |
| VM | Wazuh OVA 4.14.4 |
| VM RAM | 8 GB assigned |
| Network | Bridged adapter, static IP x.x.1.12 |
| Role | SIEM server, detection rule engine, dashboard |

### AMD Laptop — Endpoint and Attack VMs

| Component | Detail |
|-----------|--------|
| Hardware | AMD Ryzen 5000, 24 GB RAM |
| Hypervisor | Oracle VirtualBox |
| VM 1 | Windows 11 Developer Trial |
| VM 2 | Kali Linux |

---

## Virtual Machines

### Wazuh VM

- Wazuh OVA version 4.14.4
- Static IP: x.x.1.12
- Network mode: Bridged (eth1)
- Hosts Wazuh manager, indexer, and dashboard
- Receives agent telemetry from Win 11 and Kali VMs

### Windows 11 VM

- Microsoft Developer Trial (90 day)
- Wazuh agent installed (ID: 001, hostname: windows11Detect)
- Sysmon installed for rich Windows event telemetry
- Used for Atomic Red Team attack simulation
- Datadog agent installed for observability lab

### Kali Linux VM

- Primary attack simulation and analysis platform
- YARA installed for malware signature scanning
- Snort for network intrusion detection practice
- Zeek for protocol analysis and log generation
- Used to generate malicious traffic and test detections

---

## Data Flow

```
Win 11 VM
  Sysmon events
  Windows Security logs
  Process creation, registry, network events
        |
        | Wazuh agent (encrypted)
        v
Wazuh Manager (x.x.1.12)
  Rule matching engine
  Custom detection rules (rules 100001 to 100010)
  MITRE ATT&CK mapping
        |
        v
Wazuh Dashboard
  Alert visualisation
  Detection validation
  Screenshot capture for GitHub portfolio
```

---

## Detection Rules Active

| Rule ID | Technique | Description |
|---------|-----------|-------------|
| 100001 | T1033 | System owner and user discovery |
| 100002 | T1082 | System information discovery |
| 100003 | T1055 | Process injection detection |
| 100004 | T1055.004 | APC injection via renamed binary |
| 100005 | T1053.005 | Scheduled task creation |
| 100006 | T1053.005 | GhostTask registry write evasion |
| 100007 | T1053.005 | Schtasks execution path 1 |
| 100008 | T1053.005 | Schtasks execution path 2 |
| 100009 | T1547.001 | Registry run key persistence |
| 100010 | T1547.001 | Startup folder persistence |

---

## Validation Workflow

```
1. Select MITRE ATT&CK technique to test
2. Run Atomic Red Team simulation on Win 11 VM
3. Observe Sysmon telemetry generated
4. Confirm Wazuh alert fires in dashboard
5. Screenshot alert as evidence
6. Push detection rule and writeup to GitHub
```

---

## GitHub Portfolio

Detection rules, Sigma signatures, YARA malware
detection, and Python automation built in this lab:

[github.com/minnaked/DetectionEngineering](https://github.com/minnaked/DetectionEngineering)

Observability configurations and pipeline examples:

[github.com/minnaked/observability-engineering-lab](https://github.com/minnaked/observability-engineering-lab)
