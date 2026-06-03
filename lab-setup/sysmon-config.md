# Sysmon Configuration for Detection Engineering

Sysmon configuration used in the home detection lab to generate rich Windows telemetry for Wazuh detection rule validation. Based on the SwiftOnSecurity community config with additional tuning for detection engineering use cases.

---

## Why Sysmon

Windows Security event logs alone do not provide sufficient detail for detection engineering. Sysmon fills the gap by capturing:

- Full process command line arguments
- Parent and child process relationships
- Network connection details per process
- Registry modifications with before and after values
- File creation with hashes
- DNS queries per process
- DLL loading events

Without Sysmon, many MITRE ATT&CK technique detections are impossible from Windows logs alone.

---

## Installation

### Prerequisites

```
Download from Microsoft Sysinternals:
https://docs.microsoft.com/sysinternals/downloads/sysmon

Files needed:
Sysmon64.exe   (64-bit Windows)
sysmonconfig.xml  (configuration file)
```

### Install Command

```powershell
# Run PowerShell as Administrator
# Install Sysmon with configuration file

.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Verify installation
Get-Service Sysmon64

# Check Sysmon version
.\Sysmon64.exe -s
```

### Update Configuration

```powershell
# If you modify the config file, update without reinstalling
.\Sysmon64.exe -c sysmonconfig.xml

# Verify config was applied
.\Sysmon64.exe -s
```

### Uninstall

```powershell
.\Sysmon64.exe -u
```

---

## Configuration File

The configuration below is tuned for detection engineering in a lab environment. It captures maximum telemetry for rule development and validation.

```xml
<Sysmon schemaversion="4.82">

  <HashAlgorithms>md5,sha256,imphash</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>

  <EventFiltering>

    <!-- Event ID 1: Process Creation
         Capture all process creation events.
         Critical for detecting T1059 scripting,
         T1053 scheduled tasks, T1033 discovery. -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <!-- Exclude noisy legitimate processes -->
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
        <Image condition="is">C:\Windows\System32\SearchIndexer.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Event ID 2: File Creation Time Changed
         Detect timestomping — T1070.006 -->
    <RuleGroup name="" groupRelation="or">
      <FileCreateTime onmatch="include">
        <TargetFilename condition="contains">\Temp\</TargetFilename>
        <TargetFilename condition="contains">\AppData\</TargetFilename>
      </FileCreateTime>
    </RuleGroup>

    <!-- Event ID 3: Network Connection
         Capture outbound connections from
         suspicious processes.
         Detects T1071 application layer protocol,
         T1041 exfiltration over C2. -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Image condition="contains">powershell</Image>
        <Image condition="contains">cmd.exe</Image>
        <Image condition="contains">wscript</Image>
        <Image condition="contains">cscript</Image>
        <Image condition="contains">mshta</Image>
        <Image condition="contains">regsvr32</Image>
        <Image condition="contains">rundll32</Image>
        <DestinationPort condition="is">4444</DestinationPort>
        <DestinationPort condition="is">8080</DestinationPort>
        <DestinationPort condition="is">8443</DestinationPort>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event ID 5: Process Terminated
         Capture process termination for
         correlation with process creation. -->
    <RuleGroup name="" groupRelation="or">
      <ProcessTerminate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
      </ProcessTerminate>
    </RuleGroup>

    <!-- Event ID 7: Image Loaded (DLL Load)
         Detect DLL injection — T1055.
         Capture unsigned or suspicious DLLs. -->
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="include">
        <Signed condition="is">false</Signed>
        <ImageLoaded condition="contains">\Temp\</ImageLoaded>
        <ImageLoaded condition="contains">\AppData\</ImageLoaded>
      </ImageLoad>
    </RuleGroup>

    <!-- Event ID 8: CreateRemoteThread
         Detect process injection — T1055.
         Any remote thread creation is suspicious. -->
    <RuleGroup name="" groupRelation="or">
      <CreateRemoteThread onmatch="include">
        <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
        <TargetImage condition="is">C:\Windows\System32\svchost.exe</TargetImage>
        <TargetImage condition="contains">explorer.exe</TargetImage>
      </CreateRemoteThread>
    </RuleGroup>

    <!-- Event ID 10: Process Access
         Detect credential dumping — T1003.
         Detect when processes access LSASS. -->
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
        <GrantedAccess condition="is">0x1010</GrantedAccess>
        <GrantedAccess condition="is">0x1410</GrantedAccess>
        <GrantedAccess condition="is">0x40</GrantedAccess>
      </ProcessAccess>
    </RuleGroup>

    <!-- Event ID 11: File Created
         Detect file staging — T1074.
         Capture files dropped in suspicious locations. -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\Temp\</TargetFilename>
        <TargetFilename condition="contains">\AppData\Roaming\</TargetFilename>
        <TargetFilename condition="contains">\ProgramData\</TargetFilename>
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.dll</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
        <TargetFilename condition="end with">.bat</TargetFilename>
        <TargetFilename condition="end with">.vbs</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- Event ID 12 and 13: Registry Events
         Detect persistence — T1547.001 Registry Run Keys.
         Detect defence evasion via registry modification. -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">
          \CurrentVersion\Run
        </TargetObject>
        <TargetObject condition="contains">
          \CurrentVersion\RunOnce
        </TargetObject>
        <TargetObject condition="contains">
          \Winlogon\
        </TargetObject>
        <TargetObject condition="contains">
          \Services\
        </TargetObject>
        <TargetObject condition="contains">
          \Tasks\
        </TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Event ID 15: FileCreateStreamHash
         Detect alternate data stream usage — T1564.004 -->
    <RuleGroup name="" groupRelation="or">
      <FileCreateStreamHash onmatch="include">
        <TargetFilename condition="contains">\Temp\</TargetFilename>
        <TargetFilename condition="contains">\Downloads\</TargetFilename>
      </FileCreateStreamHash>
    </RuleGroup>

    <!-- Event ID 17 and 18: Pipe Events
         Detect lateral movement via named pipes.
         Common in Cobalt Strike and Metasploit. -->
    <RuleGroup name="" groupRelation="or">
      <PipeEvent onmatch="include">
        <PipeName condition="contains">mojo</PipeName>
        <PipeName condition="contains">postex</PipeName>
        <PipeName condition="contains">status_</PipeName>
        <PipeName condition="contains">msagent_</PipeName>
      </PipeEvent>
    </RuleGroup>

    <!-- Event ID 22: DNS Query
         Detect DNS tunneling and DGA domains.
         Detect suspicious DNS lookups. -->
    <RuleGroup name="" groupRelation="or">
      <DnsQuery onmatch="exclude">
        <QueryName condition="end with">.microsoft.com</QueryName>
        <QueryName condition="end with">.windows.com</QueryName>
        <QueryName condition="end with">.windowsupdate.com</QueryName>
      </DnsQuery>
    </RuleGroup>

  </EventFiltering>

</Sysmon>
```

---

## Event ID Reference

| Event ID | Name | MITRE Techniques |
|----------|------|-----------------|
| 1 | Process creation | T1059, T1053, T1033, T1082 |
| 2 | File creation time changed | T1070.006 |
| 3 | Network connection | T1071, T1041 |
| 5 | Process terminated | Correlation |
| 7 | Image loaded | T1055 |
| 8 | CreateRemoteThread | T1055 |
| 10 | Process access | T1003 |
| 11 | File created | T1074, T1105 |
| 12 | Registry object created | T1547.001 |
| 13 | Registry value set | T1547.001, T1112 |
| 15 | File stream created | T1564.004 |
| 17 | Pipe created | Lateral movement |
| 18 | Pipe connected | Lateral movement |
| 22 | DNS query | T1071.004, T1568 |

---

## Wazuh Integration

After installing Sysmon, configure Wazuh agent to collect Sysmon events.

Add to ossec.conf on the Windows agent:

```xml
<ossec_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

Restart Wazuh agent:

```powershell
Restart-Service WazuhSvc
```

Verify events appear in Wazuh dashboard under:

```
Threat Intelligence → Events
Filter: data.win.system.channel: Microsoft-Windows-Sysmon/Operational
```

---

## Validation Test

Run this test to confirm Sysmon and Wazuh are working together:

```powershell
# This command triggers Event ID 1 (process creation)
# and Event ID 3 (network connection)
# Used to validate T1033 detection rule

whoami
systeminfo
```

Check Wazuh dashboard for alerts with:

```
Rule ID: 100001 (T1033 detection)
Rule ID: 100002 (T1082 detection)
```

---

## References

```
Sysmon Download:
https://docs.microsoft.com/sysinternals/downloads/sysmon

SwiftOnSecurity Sysmon Config:
https://github.com/SwiftOnSecurity/sysmon-config

Sysmon Modular Config:
https://github.com/olafhartong/sysmon-modular

Wazuh Sysmon Integration:
https://documentation.wazuh.com/current/proof-of-concept-guide/poc-integrate-sysmon.html
```
