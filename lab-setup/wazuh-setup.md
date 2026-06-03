
# Wazuh Detection Lab Setup

A home detection lab built to develop, test, and validate security detection rules mapped to MITRE ATT&CK. This document covers the complete setup from OVA deployment to custom rule validation.

---

## Environment

| Component | Detail |
|-----------|--------|
| Wazuh Version | OVA 4.14.4 |
| Host Machine | Intel i5, 24 GB RAM |
| Hypervisor | Oracle VirtualBox |
| Network Mode | Bridged adapter (eth1) |
| Wazuh Server IP | x.x.1.12 (static) |
| Endpoint VM | Windows 11 Developer Trial |
| Attack VM | Kali Linux |

---

## 1. Wazuh OVA Deployment

### Download

```
Download Wazuh OVA from:
https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html
```

### Import into VirtualBox

```
File → Import Appliance
Select the downloaded .ova file
Allocate minimum 8 GB RAM
Set network adapter to Bridged
```

### First Boot Configuration

```bash
# Default credentials on first boot
Username: wazuh-user
Password: wazuh

# Change password immediately after login
passwd wazuh-user

# Set static IP
sudo nano /etc/sysconfig/network-scripts/ifcfg-eth1

# Add these lines
BOOTPROTO=static
IPADDR=x.x.1.12
NETMASK=255.255.255.0
GATEWAY=x.x.1.1
DNS1=x.x.x.x
ONBOOT=yes

# Restart network
sudo systemctl restart network
```

### Verify Services

```bash
# Check all Wazuh services are running
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard

# Check manager is listening
sudo netstat -tlnp | grep 1514
```

### Access Dashboard

```
Open browser on host machine
Navigate to: https://x.x.1.12
Username: admin
Password: admin (change after first login)
```

---

## 2. Wazuh Agent Installation — Windows 11 VM

### Download Agent

```
From Wazuh dashboard:
Agents → Deploy new agent
Select: Windows
Copy the generated PowerShell command
```

### Install on Windows 11 VM

```powershell
# Run in PowerShell as Administrator
# Replace WAZUH_MANAGER with your server IP

Invoke-WebRequest `
  -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.4-1.msi `
  -OutFile wazuh-agent.msi

msiexec.exe /i wazuh-agent.msi `
  WAZUH_MANAGER="x.x.1.12" `
  WAZUH_AGENT_NAME="windows11Detect" /q

# Start the agent service
NET START WazuhSvc
```

### Verify Agent Registration

```bash
# On Wazuh server — verify agent appears
sudo /var/ossec/bin/agent_control -l

# Expected output
ID: 001  Name: windows11Detect  Status: Active
```

---

## 3. Sysmon Installation and Configuration

Sysmon provides rich Windows telemetry that Wazuh alone does not capture. It generates detailed process creation, network connection, registry, and file events that are essential for detection engineering.

### Download Sysmon

```
Download from Microsoft Sysinternals:
https://docs.microsoft.com/sysinternals/downloads/sysmon

Download SwiftOnSecurity Sysmon config:
https://github.com/SwiftOnSecurity/sysmon-config
```

### Install Sysmon on Windows 11 VM

```powershell
# Run in PowerShell as Administrator
# Place Sysmon64.exe and sysmonconfig.xml in same folder

.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Verify Sysmon is running
Get-Service Sysmon64
```

### Key Event IDs Captured

| Event ID | Description | Detection Use |
|----------|-------------|---------------|
| 1 | Process creation | Detect malicious process execution |
| 3 | Network connection | Detect C2 communications |
| 7 | Image loaded | Detect DLL injection |
| 10 | Process access | Detect credential dumping |
| 11 | File created | Detect file drops and staging |
| 12 | Registry object created or deleted | Detect persistence |
| 13 | Registry value set | Detect registry modifications |
| 17 | Pipe created | Detect lateral movement |
| 22 | DNS query | Detect DNS tunneling and DGA |

### Configure Wazuh to Collect Sysmon Events

```xml
<!-- Add to C:\Program Files (x86)\ossec-agent\ossec.conf -->
<ossec_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

```powershell
# Restart Wazuh agent after config change
Restart-Service WazuhSvc
```

---

## 4. Custom Detection Rules

Rules are stored on the Wazuh server at:

```
/var/ossec/etc/rules/local_rules.xml
```

Rule ID range used: 100001 to 100010

All rules are mapped to MITRE ATT&CK techniques and available at:

[github.com/minnaked/DetectionEngineering/wazuh/](https://github.com/minnaked/DetectionEngineering)

### Rules Summary

| Rule ID | MITRE Technique | Description |
|---------|----------------|-------------|
| 100001 | T1033 | System owner and user discovery via whoami |
| 100002 | T1082 | System information discovery via systeminfo |
| 100003 | T1055 | Process injection — generic detection |
| 100004 | T1055.004 | APC injection via renamed binary (OriginalFileName check) |
| 100005 | T1053.005 | Scheduled task creation via schtasks |
| 100006 | T1053.005 | GhostTask registry write evasion path |
| 100007 | T1053.005 | Scheduled task via at.exe |
| 100008 | T1053.005 | Scheduled task via COM object |
| 100009 | T1547.001 | Registry run key persistence |
| 100010 | T1547.001 | Startup folder file drop |

### Deploy Custom Rules

```bash
# On Wazuh server
sudo nano /var/ossec/etc/rules/local_rules.xml

# After adding rules, validate and restart
sudo /var/ossec/bin/wazuh-logtest
sudo systemctl restart wazuh-manager
```

---

## 5. Detection Validation Workflow

```
Step 1: Select MITRE ATT&CK technique to test

Step 2: Run Atomic Red Team test on Win 11 VM
        Install-Module -Name invoke-atomicredteam
        Invoke-AtomicTest T1053.005 -TestNumbers 1

Step 3: Observe Sysmon event generated in
        Windows Event Viewer under
        Microsoft-Windows-Sysmon/Operational

Step 4: Confirm Wazuh alert fires in dashboard
        Threat Intelligence → Alerts
        Filter by rule ID or MITRE technique

Step 5: Screenshot the alert as evidence

Step 6: Push rule and documentation to GitHub
```

---

## 6. MITRE ATT&CK Coverage

Current detection coverage mapped in Navigator:

[DetectionEngineering/mitre-navigator/](https://github.com/minnaked/DetectionEngineering)

Techniques currently covered:

```
T1033    System Owner and User Discovery
T1082    System Information Discovery
T1055    Process Injection
T1055.004 Asynchronous Procedure Call
T1053.005 Scheduled Task
T1547.001 Registry Run Keys and Startup Folder
```

---

## 7. Known Limitations

```
Windows 11 VM is a 90 day Microsoft
developer trial. Lab must be rebuilt
after expiry. Detection rules and
documentation persist on GitHub.

Lab uses only safe Atomic Red Team
simulations and PCAP replay files.
No live malware is used in this lab.

Lab network is isolated from production
environments. All testing is contained
within VirtualBox internal network.
```

---

## 8. References

```
Wazuh Documentation:
https://documentation.wazuh.com

Atomic Red Team:
https://github.com/redcanaryco/atomic-red-team

SwiftOnSecurity Sysmon Config:
https://github.com/SwiftOnSecurity/sysmon-config

MITRE ATT&CK Navigator:
https://mitre-attack.github.io/attack-navigator

Wazuh Rules Development:
https://documentation.wazuh.com/current/user-manual/ruleset/custom.html
```
