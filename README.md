# THM-WriteUp-Preparation
Writeup for TryHackMe Preparation Lab -  IR preparation using Windows Event Logs, Sysmon, Atomic Red Team, registry edits, AuditPol, FTK Imager, and DumpIt for logging, simulation, and forensics.

By Ramyar Daneshgar 

---

### **1. Verifying and Configuring Event Logging on Windows Hosts**

After discovering that event logging was disabled, I navigated to the Registry Editor to inspect and fix the Event Log service startup settings.

```powershell
# Open Registry Editor
regedit

# Navigate to the EventLog service startup setting
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog

# Verify the value of the Start DWORD
# If it's set to 4 (disabled), I change it to 2 (automatic)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog' -Name Start -Value 2
```

After modifying the registry, I initiated a system reboot to apply changes:

```powershell
shutdown /r /t 0
```

Upon reboot, I verified the operational status of the Event Log service:

```powershell
Get-Service EventLog
```

---

### **2. Simulating Malicious Behavior via Atomic Red Team**

After confirming that the Event Log service was operational, I executed an **Atomic Red Team** test to simulate ransomware activity using MITRE ATT&CK technique T1486:

```powershell
# Show brief details of the ransomware test
Invoke-AtomicTest T1486 -ShowDetailsBrief

# Execute the specific test for PureLocker ransom note simulation
Invoke-AtomicTest T1486-5
```

This generated a `File Created` event observable in **Sysmon Event ID 11**.

To streamline investigation:

```powershell
# Filter logs to find the exact entry
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | 
  Where-Object { $_.Id -eq 11 } |
  Format-List TimeCreated, Message
```

---

### **3. Configuring Local Security Policies for Visibility**

I adjusted several GPO settings to align with visibility and auditing best practices:

```powershell
# Enable audit logon events for both success and failure
AuditPol /set /subcategory:"Logon" /success:enable /failure:enable

# Enable detailed process tracking
AuditPol /set /subcategory:"Process Creation" /success:enable

# Disable display of user info on locked sessions
secedit /export /cfg C:\secpol.cfg

# Manually edit cfg file: change
# Interactive logon: Display user information when session is locked = Do not display user information

# Reapply the policy
secedit /configure /db C:\Windows\Security\Database\secedit.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY
```

---

### **4. Collecting and Forwarding Logs to SIEM**

Assuming Wazuh or Winlogbeat is installed, here’s a command to configure log forwarding from a Windows host:

```powershell
# Configure Winlogbeat to forward logs to the SIEM
notepad "C:\Program Files\Winlogbeat\winlogbeat.yml"

# Example addition to config:
# winlogbeat.event_logs:
#   - name: Security
#     event_id: 4624, 4625, 4688, 1102

# Restart the service
Restart-Service winlogbeat
```

---

### **5. Forensic Imaging and Memory Acquisition (Jump Bag Tools)**

I performed disk and memory capture using FTK Imager and DumpIt:

```bash
# FTK Imager command line for disk acquisition (in a jump bag scenario)
ftkimager.exe \\.\PhysicalDrive0 D:\Images\disk01.E01 --e01

# Memory acquisition using DumpIt
cd C:\IR_Tools\
DumpIt.exe

# Verify hash of collected evidence
CertUtil -hashfile D:\Images\disk01.E01 SHA256
```

These were then logged in a Chain of Custody form and stored in a secure offline storage vault.

---

### **6. Asset Enumeration and Network Mapping**

For network telemetry, I executed `ipconfig` and `route print` to get a sense of current host positioning. I then used `arp` and `netstat` to inspect immediate connections and lateral movement potential:

```cmd
ipconfig /all
route print
arp -a
netstat -ano
```

Combined with `nmap`, this allowed me to detect exposed services and misconfigurations:

```bash
nmap -sS -sV -O 192.168.0.0/24
```

---

### **7. Software Restriction Policies and Execution Control**

To inspect and enforce Software Restriction Policies (SRP):

```powershell
# View the current SRP configuration
secpol.msc

# Navigate to: Security Settings -> Software Restriction Policies

# Default policy found: Unrestricted

# Optionally, add a policy to restrict execution from %APPDATA%
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{GUID}" `
  -ValueName "ItemData" -Value "%APPDATA%\*.exe"
```

---

## **Conclusion: 

Each step I performed in this lab reinforced the importance of **IR preparation as an operational discipline, not just a theoretical framework**. By integrating:
- Logging architecture setup and validation,
- Registry and policy reconfiguration,
- Live adversary emulation using TTPs,
- Evidence collection workflows with proper chain-of-custody management, and
- Log forwarding configurations for a centralized SIEM pipeline.


## Lessons Learned

- **Visibility is foundational**  
  Without proper logging (e.g., Event Log, Sysmon), detection and triage become guesswork. Enabling and verifying log services should be a first-step task in IR readiness.

- **Registry and GPO misconfigurations can silently cripple visibility**  
  I learned to validate the state of the Event Log service (`HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Start`) and configure auditing with `AuditPol` to ensure logging fidelity.

- **Atomic Red Team is invaluable for controlled adversary simulation**  
  Running `Invoke-AtomicTest T1486` allowed me to verify EDR/SIEM pipeline integrity and confirm logging of real-world TTPs under Sysmon Event ID 11.

- **Sysmon requires precise configuration to be effective**  
  Without a tuned XML config, critical events like process creation or file drops could be missed entirely.

- **IR tooling must be ready-to-go**  
  The concept of a “jump bag” taught me to pre-stage portable tools like FTK Imager and DumpIt for immediate disk/memory acquisition, which is critical in volatile evidence scenarios.

- **Chain of custody procedures are not optional**  
  Every tool run and artifact collected must be traceable with metadata and hash verification to preserve evidentiary integrity.

- **Gaps in policy enforcement (like Software Restriction Policies defaulting to Unrestricted)**  
  These can create blind spots for executable control and must be proactively reviewed and hardened.

- **Asset classification drives priority**  
  By knowing which systems were Tier 1 (e.g., mail server, finance DB), I could prioritize telemetry, forensics, and containment strategy accordingly.



