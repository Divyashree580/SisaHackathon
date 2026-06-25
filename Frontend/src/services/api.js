// Threat Intelligence API client and local mock processor.
// This service attempts to call the FastAPI backend, and falls back to local processing if the backend is down.

const API_BASE = 'http://localhost:8000/api';

// Regular expressions for IOC extraction
const REGEX_IPV4 = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
const REGEX_DOMAIN = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b/g;
const REGEX_URL = /https?:\/\/(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}(?:\/[^\s"']*)?/g;
const REGEX_EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const REGEX_MD5 = /\b[a-fA-C0-9]{32}\b/gi;
const REGEX_SHA1 = /\b[a-fA-C0-9]{40}\b/gi;
const REGEX_SHA256 = /\b[a-fA-C0-9]{64}\b/gi;
const REGEX_CVE = /\bCVE-\d{4}-\d{4,7}\b/gi;

// Clean up matches by removing duplicates and ignoring common benign assets
function cleanMatches(matches, excludeList = []) {
  if (!matches) return [];
  const unique = Array.from(new Set(matches.map(m => m.toLowerCase())));
  return unique.filter(val => !excludeList.includes(val));
}

// Check if string contains search terms
const contains = (text, terms) => {
  const lowercaseText = text.toLowerCase();
  return terms.some(term => lowercaseText.includes(term.toLowerCase()));
};

// 5 Seed Scenarios from PRD
export const SEED_SCENARIOS = [
  {
    id: 'lockbit-ransomware',
    name: 'LockBit 3.0 Ransomware Incident (Critical)',
    description: 'Active LockBit 3.0 ransomware campaign targeting Windows endpoints using Tor network infrastructure and customized payloads.',
    inputType: 'text',
    content: `ALERT: Incident response triggered on domain controllers. Files encrypted with extension .lockbit. 
Ransom note "Restore-My-Files.txt" dropped.
A customized LockBit 3.0 ransomware loader with hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 was executed.
The malware established C2 connections over Tor exit node 185.220.101.5 to http://lockbitapt2yf5pydobuuz5otbcr4z7z7ttrh2pn3knh4c7wt75574qd.onion.
The threat actor has threatened double extortion on their public leak site. CVE-2023-4966 (Citrix Bleed) was likely exploited for initial access.`,
    data: {
      analysis_id: 'lb-30-001',
      timestamp: new Date().toISOString(),
      input_type: 'text',
      risk_score: 95,
      risk_level: 'Critical',
      risk_factors: [
        { name: 'CVSS > 9 (Critical CVSS CVE-2023-4966)', points: 30 },
        { name: 'Public exploit available (Citrix Bleed POC)', points: 25 },
        { name: 'Malware associated (LockBit 3.0)', points: 15 },
        { name: 'Known threat actor (LockBit Group / Gold Southfield)', points: 10 },
        { name: 'High IOC reputation (Active Tor exit nodes / Onion domains)', points: 20 }
      ],
      iocs: [
        { type: 'IPv4', value: '185.220.101.5', reputation: 'Malicious', enriched: true, context: 'LockBit C2 Tor exit node' },
        { type: 'URL', value: 'http://lockbitapt2yf5pydobuuz5otbcr4z7z7ttrh2pn3knh4c7wt75574qd.onion', reputation: 'Malicious', enriched: true, context: 'LockBit Tor onion landing leak site' },
        { type: 'SHA256', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', reputation: 'Malicious', enriched: true, context: 'LockBit 3.0 Locker executable payload' },
        { type: 'CVE ID', value: 'CVE-2023-4966', reputation: 'Critical Vulnerability', enriched: true, context: 'Citrix Bleed session hijacking' }
      ],
      enrichment: {
        cve_id: 'CVE-2023-4966',
        cvss: 9.8,
        severity: 'Critical',
        description: 'Citrix NetScaler ADC and NetScaler Gateway buffer overflow vulnerability allowing sensitive information disclosure, leading to session hijacking.',
        exploit_available: true,
        malware_families: ['LockBit 3.0', 'LockBit Black'],
        threat_actors: ['LockBit', 'Gold Southfield']
      },
      mitre_mapping: [
        { tactic: 'Initial Access', technique: 'Exploit Public-Facing Application', technique_id: 'T1190', confidence: 'High' },
        { tactic: 'Execution', technique: 'Command and Scripting Interpreter', technique_id: 'T1059', confidence: 'High' },
        { tactic: 'Command and Control', technique: 'Application Layer Protocol (Tor Web Traffic)', technique_id: 'T1071', confidence: 'High' },
        { tactic: 'Impact', technique: 'Data Encrypted for Impact', technique_id: 'T1486', confidence: 'Critical' }
      ],
      ai_report: {
        summary: 'Active LockBit 3.0 (LockBit Black) ransomware deployment attempting full domain encryption and double-extortion exfiltration. Threat actors exploited CVE-2023-4966 (Citrix Bleed) to gain initial access, followed by execution of a customized ransomware binary and communication with Onion C2 servers.',
        attack_scenario: '1. NetScaler session hijacking (CVE-2023-4966) -> 2. Credentials dumped via LSASS -> 3. Internal reconnaissance using net.exe and Adfind -> 4. Scripted execution of ransomware binary using PsExec -> 5. Command & Control over Tor channels -> 6. Large-scale volume shadow copy deletion and file encryption.',
        business_impact: 'High risk of complete business operational stoppage, critical data loss, brand reputation damage, and ransom demands ranging from $50K to multiple millions. Regulatory compliance violations for sensitive data exposure.',
        immediate_actions: [
          'Isolate infected hosts (specifically the domain controllers and affected servers).',
          'Revoke all NetScaler user sessions and implement security patches for Citrix CVE-2023-4966 immediately.',
          'Block outbound network connections to Tor exit node 185.220.101.5.',
          'Reset credentials for all domain admins and high-privilege service accounts.'
        ],
        long_term_remediation: [
          'Deploy Endpoint Detection and Response (EDR) with active anti-ransomware blocking modes.',
          'Enforce strict multi-factor authentication (MFA) across all administrative access endpoints.',
          'Harden backups and store them in immutable, offsite networks.'
        ],
        monitoring: [
          'Monitor PowerShell processes spawning cmd.exe or performing base64 commands.',
          'Alert on administrative accounts logging into multiple endpoints in short time spans.',
          'Audit volume shadow copy deletions (vssadmin delete shadows).'
        ]
      },
      detection_rules: {
        sigma: `title: LockBit 3.0 Shadow Copy Deletion
id: 5797c28d-1941-471e-8e81-a75d1f893d56
status: experimental
description: Detects command-line execution associated with LockBit ransomware deleting shadow copies.
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        Image|endswith:
            - '\\vssadmin.exe'
            - '\\wmic.exe'
        CommandLine|contains:
            - 'delete shadows'
            - 'shadowcopy delete'
    condition: selection_cmd
falsepositives:
    - Administrative backup scripts (rare)
level: critical`,
        yara: `rule LockBit_3_0_Payload {
    meta:
        description = "Detects LockBit 3.0 ransomware binaries"
        author = "SISA Hackathon SOC Team"
        date = "2026-06-23"
        hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    strings:
        $s1 = "Restore-My-Files.txt" wide ascii
        $s2 = ".lockbit" wide ascii
        $s3 = "lockbitapt2yf5pyd" wide ascii
        $op1 = { 8A 02 8b 4d 08 88 04 0f 41 }

    condition:
        uint16(0) == 0x5A4D and (any of ($s*)) and $op1
}`,
        splunk: `index=security sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 
| eval cmd=lower(CommandLine) 
| where cmd LIKE "%vssadmin%delete%" OR cmd LIKE "%shadowcopy%delete%" 
| table _time, host, User, Image, CommandLine`,
        kql: `DeviceProcessEvents
| where ProcessCommandLine has "vssadmin" and ProcessCommandLine has "delete" and ProcessCommandLine has "shadows"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FolderPath, ProcessCommandLine`
      }
    }
  },
  {
    id: 'apt29-phishing',
    name: 'APT29 Spear Phishing Campaign (High)',
    description: 'Targeted diplomatic spear phishing campaign using lookalike Microsoft update domains and malicious attachments attributed to APT29 (Nobelium).',
    inputType: 'text',
    content: `PHISHING CAMPAIGN DETECTED: Diplomatic staff received phishing emails containing urgent security bulletins.
Sender address: update@security-update-microsoft.com
E-mails urge users to download security bulletins from lookalike C2 domain: security-update-microsoft.com
IP address linked to infrastructure: 93.184.216.34
A PDF attachment "Urgent_Patch_Details.pdf" contains an embedded malicious macro/exploit with MD5 hash 84c82835a5d21bb3c5f617a0d200c015.
Tactics align with APT29/Nobelium operations targeting NATO-aligned entities.`,
    data: {
      analysis_id: 'apt-29-002',
      timestamp: new Date().toISOString(),
      input_type: 'text',
      risk_score: 85,
      risk_level: 'High',
      risk_factors: [
        { name: 'CVSS 7–9 (High Risk Macro / Executable)', points: 20 },
        { name: 'Malware associated (Nobelium downloader)', points: 15 },
        { name: 'Known threat actor (APT29 / Nobelium / Cozy Bear)', points: 10 },
        { name: 'High IOC reputation (Active phishing domain & mail records)', points: 20 },
        { name: 'Public exploit available (CVE-2023-38831 WinRAR bypass)', points: 20 }
      ],
      iocs: [
        { type: 'Email', value: 'update@security-update-microsoft.com', reputation: 'Malicious', enriched: true, context: 'Spear phishing sender address' },
        { type: 'Domain', value: 'security-update-microsoft.com', reputation: 'Malicious', enriched: true, context: 'APT29 C2 / phishing lander' },
        { type: 'IPv4', value: '93.184.216.34', reputation: 'Suspicious', enriched: true, context: 'IP hosting phishing update site' },
        { type: 'MD5', value: '84c82835a5d21bb3c5f617a0d200c015', reputation: 'Malicious', enriched: true, context: 'Phishing attachment payload dropper' }
      ],
      enrichment: {
        cve_id: 'CVE-2023-38831',
        cvss: 7.8,
        severity: 'High',
        description: 'WinRAR security bypass vulnerability allowing attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive.',
        exploit_available: true,
        malware_families: ['GraphicalProton', 'EnvyScout'],
        threat_actors: ['APT29', 'Nobelium', 'Cozy Bear']
      },
      mitre_mapping: [
        { tactic: 'Initial Access', technique: 'Phishing: Spearphishing Attachment', technique_id: 'T1566.001', confidence: 'High' },
        { tactic: 'Execution', technique: 'User Execution: Malicious File', technique_id: 'T1204.002', confidence: 'High' },
        { tactic: 'Command and Control', technique: 'Web Service (HTTP/S over Domain)', technique_id: 'T1102', confidence: 'Medium' },
        { tactic: 'Exfiltration', technique: 'Exfiltration Over C2 Channel', technique_id: 'T1041', confidence: 'High' }
      ],
      ai_report: {
        summary: 'Targeted spear phishing campaign orchestrated by APT29 (Nobelium) leveraging fake Microsoft support emails to deliver file attachments exploiting WinRAR or macro executables. A malicious C2 domain is used for payload hosting and telemetry.',
        attack_scenario: '1. Phishing email sent to targets containing urgent PDF bulletins -> 2. Target opens attachment, triggering execution of embedded downloaders -> 3. Downloader queries security-update-microsoft.com for second-stage payloads -> 4. Establishes encrypted HTTPS tunnel to exfiltrate system parameters.',
        business_impact: 'High threat of intellectual property theft, unauthorized lateral access into enterprise mail networks, compromise of sensitive government communications, and potential backdoor persistence.',
        immediate_actions: [
          'Implement domain block for security-update-microsoft.com on firewalls and secure web gateways.',
          'Quarantine inbound emails originating from update@security-update-microsoft.com.',
          'Force logout and reset tokens for any employees who opened the attachment "Urgent_Patch_Details.pdf".',
          'Deploy remediation scripts to search for MD5 hash 84c82835a5d21bb3c5f617a0d200c015 on local disk paths.'
        ],
        long_term_remediation: [
          'Enable external sender warning banners in email servers.',
          'Configure Microsoft Office to block macros in files downloaded from the Internet.',
          'Transition to FIDO2 token-based authentication to mitigate session hijacking from phishing.'
        ],
        monitoring: [
          'Monitor dns query logs for lookalike Microsoft domains.',
          'Audit PDF readers or ZIP archivers spawning cmd.exe, powershell.exe, or wscript.exe.',
          'Check for unusual outbound HTTPS POST traffic to unclassified IP addresses.'
        ]
      },
      detection_rules: {
        sigma: `title: Suspicious Process Spawning from ZIP/PDF Reader
id: a7e38ffc-196e-44ab-b56e-8260a927fa1e
status: stable
description: Detects Microsoft Word, PDF readers or WinRAR spawning command interpreters.
logsource:
    category: process_creation
    product: windows
detection:
    parent_selection:
        ParentImage|endswith:
            - '\\winrar.exe'
            - '\\AcroRd32.exe'
            - '\\FoxitPDFReader.exe'
            - '\\winword.exe'
    target_selection:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\wscript.exe'
    condition: parent_selection and target_selection
falsepositives:
    - Custom company workflow extensions (rare)
level: high`,
        yara: `rule APT29_Spear_PDF {
    meta:
        description = "Detects malicious PDF loaders used in Nobelium phishing campaigns"
        author = "SISA Hackathon SOC Team"
        hash = "84c82835a5d21bb3c5f617a0d200c015"

    strings:
        $magic = { 25 50 44 46 } // %PDF
        $s1 = "update@security-update-microsoft.com" wide ascii
        $s2 = "/JavaScript" wide ascii
        $s3 = "/Launch" wide ascii

    condition:
        $magic at 0 and (any of ($s*))
}`,
        splunk: `index=email sourcetype=m365:email 
| where sender="update@security-update-microsoft.com" OR recipient_domain="security-update-microsoft.com"
| stats count by sender, recipient, subject, attachment_name`,
        kql: `EmailEvents
| where SenderMailFromAddress == "update@security-update-microsoft.com" or NetworkMessageId in (
    EmailAttachmentInfo | where AttachmentName has "Urgent_Patch_Details" | project NetworkMessageId
)
| project Timestamp, SenderMailFromAddress, Subject, RecipientEmailAddress`
      }
    }
  },
  {
    id: 'activemq-rce',
    name: 'Apache ActiveMQ RCE Exploit (Medium-High)',
    description: 'In-the-wild exploitation of Apache ActiveMQ remote code execution vulnerability CVE-2023-46604 to deploy reverse shells.',
    inputType: 'text',
    content: `VULNERABILITY EXPLOIT: External logs show incoming TCP traffic on port 61616 (ActiveMQ OpenWire).
Attacker sent a malicious marshalled class payload trigger exploiting vulnerability CVE-2023-46604.
The vulnerability allows remote execution of arbitrary commands. 
The system downloaded an XML configuration file containing command instructions from http://172.245.16.125/poc.xml.
IP 172.245.16.125 was flagged as the attack origin and payload host.
Host machine spawned java.exe with child cmd.exe running curl to pull next-stage binaries.`,
    data: {
      analysis_id: 'amq-rce-003',
      timestamp: new Date().toISOString(),
      input_type: 'text',
      risk_score: 75,
      risk_level: 'High',
      risk_factors: [
        { name: 'CVSS > 9 (CVE-2023-46604 CVSS 10.0)', points: 30 },
        { name: 'Public exploit available (Metasploit & Public GitHub POCs)', points: 25 },
        { name: 'Known threat actor (Kinsing malware group)', points: 10 },
        { name: 'IOC Reputation (Malicious payload server IP)', points: 10 }
      ],
      iocs: [
        { type: 'CVE ID', value: 'CVE-2023-46604', reputation: 'Critical Vulnerability', enriched: true, context: 'ActiveMQ RCE execution flaw' },
        { type: 'IPv4', value: '172.245.16.125', reputation: 'Malicious', enriched: true, context: 'Attacker payload delivery IP' },
        { type: 'URL', value: 'http://172.245.16.125/poc.xml', reputation: 'Malicious', enriched: true, context: 'ActiveMQ remote class XML config' }
      ],
      enrichment: {
        cve_id: 'CVE-2023-46604',
        cvss: 10.0,
        severity: 'Critical',
        description: 'Apache ActiveMQ OpenWire protocol remote code execution vulnerability. Unauthenticated remote attackers can execute arbitrary commands by submitting manipulated ClasspathXmlApplicationContext payloads.',
        exploit_available: true,
        malware_families: ['Kinsing', 'HelloKitty Ransomware'],
        threat_actors: ['Kinsing Actors', 'Threat Group 3390']
      },
      mitre_mapping: [
        { tactic: 'Initial Access', technique: 'Exploit Public-Facing Application', technique_id: 'T1190', confidence: 'High' },
        { tactic: 'Execution', technique: 'Exploitation for Client Execution', technique_id: 'T1203', confidence: 'High' }
      ],
      ai_report: {
        summary: 'Unauthenticated exploitation attempt of Apache ActiveMQ (CVE-2023-46604). The exploit payload directs the Java process to fetch an external XML schema file containing shell execution vectors, allowing remote control over the target application server.',
        attack_scenario: '1. Attacker sends a malicious OpenWire protocol request to port 61616 -> 2. The server parses the class trigger and attempts to retrieve http://172.245.16.125/poc.xml -> 3. The XML configuration commands the local JRE execution system to spawn cmd.exe/bash -> 4. Server executes curl/wget to retrieve subsequent binaries.',
        business_impact: 'High risk of infrastructure control. Can lead to botnet inclusion (Kinsing cryptominers) or server encryption (HelloKitty ransomware). Potential leakage of message queue details and internal API keys.',
        immediate_actions: [
          'Patch Apache ActiveMQ installations immediately to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3.',
          'Isolate the ActiveMQ server from directly accessing the internet.',
          'Block outbound network requests to 172.245.16.125.',
          'Scan active server processes for instances of java.exe spawning command-line utilities (cmd, powershell, sh, bash).'
        ],
        long_term_remediation: [
          'Implement network segmentation; prevent DMZ servers from initiating outgoing connections to foreign hosts except on approved proxies.',
          'Deploy web application firewalls (WAF) and deep packet inspection for OpenWire protocols.'
        ],
        monitoring: [
          'Create high-priority alerts on Java processes spawning shell shells (bash, cmd.exe, powershell).',
          'Track web server logs for connections containing XML schema lookups.'
        ]
      },
      detection_rules: {
        sigma: `title: Java Spawning Command Shell - ActiveMQ Exploit
id: d76de7cf-7a32-4d2d-a1ad-467cd9e6de73
status: stable
description: Detects a Java process executing command-line utilities, a common indicator of deserialization or RCE exploitation like CVE-2023-46604.
logsource:
    category: process_creation
    product: windows
detection:
    parent_selection:
        ParentImage|endswith:
            - '\\java.exe'
            - '\\javaw.exe'
    target_selection:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\wscript.exe'
            - '\\powershell_ise.exe'
    condition: parent_selection and target_selection
falsepositives:
    - Legitimate Java management tools (e.g. Jenkins agents)
level: high`,
        yara: `rule ActiveMQ_RCE_XML {
    meta:
        description = "Detects XML payload configuration files fetching commands via CVE-2023-46604"
        author = "SISA Hackathon SOC Team"
        reference = "https://github.com/X1r0z/ActiveMQ-RCE"

    strings:
        $tag = "<beans" xml wide ascii
        $bean = "class=\"org.springframework.context.support.ClassPathXmlApplicationContext\"" wide ascii
        $constructor = "<constructor-arg value=" wide ascii
        $exec = "value=\"cmd.exe\"" wide ascii
        $exec_sh = "value=\"/bin/sh\"" wide ascii

    condition:
        $tag and $bean and $constructor and ($exec or $exec_sh)
}`,
        splunk: `index=security EventCode=4688 Creator_Process_Name="*\\java.exe" (Process_Command_Line="*cmd.exe*" OR Process_Command_Line="*powershell*" OR Process_Command_Line="*curl*" OR Process_Command_Line="*wget*")
| table _time, ComputerName, New_Process_Name, Process_Command_Line`,
        kql: `DeviceProcessEvents
| where InitiatingProcessFileName =~ "java.exe" or InitiatingProcessFileName =~ "javaw.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "sh", "bash", "curl", "wget")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessCommandLine`
      }
    }
  },
  {
    id: 'pdf-shadowpad',
    name: 'ShadowPad Malware - Malicious PDF Upload (Critical)',
    description: 'Incident analysis of an uploaded system document payload containing ShadowPad malware loaders linked to APT41.',
    inputType: 'file',
    content: `FILE ANALYSIS COMPLETE: System diagnostic tool analyzed uploaded file "invoice_v9.2.exe" which contains hidden PE payloads.
File size: 1.4 MB
File hash SHA256: 6a65529f7f45c85672d5b62b71df6c88f1f513f568f237ef1be264585c5b9678
Static analysis matches threat signatures for ShadowPad (modular RAT malware).
The binary is programmed to side-load a malicious DLL.
Affiliated with threat actor group: APT41 (BARIUM).
Destined to connect to remote DNS domain: update.cloudservices-api.com.`,
    data: {
      analysis_id: 'sp-41-004',
      timestamp: new Date().toISOString(),
      input_type: 'file',
      risk_score: 90,
      risk_level: 'Critical',
      risk_factors: [
        { name: 'CVSS 7–9 (High Severity Backdoor Payload)', points: 20 },
        { name: 'Public exploit available (DLL sideloading vulnerability)', points: 25 },
        { name: 'Malware associated (ShadowPad RAT)', points: 15 },
        { name: 'Known threat actor (APT41 / BARIUM)', points: 10 },
        { name: 'High IOC reputation (Active APT41 infrastructure)', points: 20 }
      ],
      iocs: [
        { type: 'SHA256', value: '6a65529f7f45c85672d5b62b71df6c88f1f513f568f237ef1be264585c5b9678', reputation: 'Malicious', enriched: true, context: 'ShadowPad Loader DLL payload' },
        { type: 'Domain', value: 'update.cloudservices-api.com', reputation: 'Malicious', enriched: true, context: 'ShadowPad C2 DNS lookup host' }
      ],
      enrichment: {
        cve_id: 'N/A',
        cvss: 8.5,
        severity: 'High',
        description: 'DLL hijacking/sideloading in standard Windows binaries utilized to execute the ShadowPad loader. Attacker copies a legitimate executable alongside a malicious DLL bearing a expected filename.',
        exploit_available: true,
        malware_families: ['ShadowPad', 'PlugX'],
        threat_actors: ['APT41', 'BARIUM', 'Wicked Panda']
      },
      mitre_mapping: [
        { tactic: 'Initial Access', technique: 'Supply Chain Compromise: Compromise Software Dependencies', technique_id: 'T1195.002', confidence: 'High' },
        { tactic: 'Defense Evasion', technique: 'Hijack Execution Flow: DLL Side-Loading', technique_id: 'T1574.002', confidence: 'High' },
        { tactic: 'Command and Control', technique: 'Encrypted Channel (Custom Port Encryption)', technique_id: 'T1573', confidence: 'High' }
      ],
      ai_report: {
        summary: 'Analysis of a malicious executable bundle utilizing DLL sideloading techniques. The loader loads an encrypted payload shellcode file (ShadowPad RAT) into the memory space of a signed Microsoft/legitimate application to bypass EDR software. The payload connects to the dynamic C2 update.cloudservices-api.com.',
        attack_scenario: '1. User downloads or runs "invoice_v9.2.exe" -> 2. The legitimate executable loads the malicious DLL side-by-side -> 3. The DLL decrypts and injects ShadowPad shellcode into svchost.exe memory -> 4. Establishing a persistent backdoor using registry keys -> 5. Connecting back to update.cloudservices-api.com.',
        business_impact: 'Extremely high threat. ShadowPad allows full control over compromised servers, file manipulation, screen recording, shell execution, and lateral movement. Linked directly to state-sponsored corporate espionage.',
        immediate_actions: [
          'Perform immediate forensic sweep for SHA256 hash 6a65529f7f45c85672d5b62b71df6c88f1f513f568f237ef1be264585c5b9678 across endpoint host profiles.',
          'Inject domain block for update.cloudservices-api.com on enterprise DNS sinks.',
          'Isolate infected developer workstations or servers executing the suspicious binary.'
        ],
        long_term_remediation: [
          'Enforce AppLocker or Software Restriction Policies to prevent unsigned executables from running in User Temp folders.',
          'Improve network monitoring for persistent DNS requests to domain services matching suspicious patterns.'
        ],
        monitoring: [
          'Alert when unsigned DLLs are loaded by high-trust Windows system binaries in non-standard paths.',
          'Track unexpected outbound HTTPS/DNS connections originating from typical user processes (svchost.exe, explorer.exe).'
        ]
      },
      detection_rules: {
        sigma: `title: DLL Side-Loading of Unsigned DLL
id: c86ef9a8-da56-425f-bbcc-04ee22cf88ad
status: stable
description: Detects loading of suspicious or unsigned DLLs in the same folder as legitimate tools like Gptedit or Sigverif (standard side-loading vectors).
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith:
            - '\\mso.dll'
            - '\\ole32.dll'
            - '\\ntdsapi.dll'
        Image|endswith:
            - '\\invoice_v9.2.exe'
    condition: selection
falsepositives:
    - Legitimate application updates placing DLLs in root folders (rare)
level: high`,
        yara: `rule ShadowPad_Loader {
    meta:
        description = "Detects ShadowPad side-loading DLL binaries"
        author = "SISA Hackathon SOC Team"
        hash = "6a65529f7f45c85672d5b62b71df6c88f1f513f568f237ef1be264585c5b9678"

    strings:
        $magic = { 4D 5A } // MZ
        $s1 = "update.cloudservices-api.com" wide ascii
        $s2 = "shadow_pad" wide ascii
        $op = { E8 [4] 8B E5 5D C3 }

    condition:
        $magic at 0 and (all of ($s*)) and $op
}`,
        splunk: `index=sysmon EventCode=7 ImageLoaded="*\\invoice_v9.2.exe" OR ImageLoaded="*update.cloudservices-api.com*"
| stats count by host, Image, ImageLoaded`,
        kql: `DeviceImageLoadEvents
| where FolderPath has "invoice" or ImageLoadedName has "cloudservices-api"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, ImageLoadedName`
      }
    }
  },
  {
    id: 'low-risk-scan',
    name: 'Outbound Reconnaissance - Shodan Scanner (Low)',
    description: 'Routine scanning detected from a Shodan port check node. Low risk, no active exploitation or malware payload.',
    inputType: 'text',
    content: `LOG REPORT: Firewall blocked port scan on port 443 and 80.
Originating external IP: 198.51.100.42.
Reverse DNS resolution: shodan.io.
Action: Connection dropped.
This is classified as general internet background noise. No internal compromise detected.`,
    data: {
      analysis_id: 'sh-005',
      timestamp: new Date().toISOString(),
      input_type: 'text',
      risk_score: 15,
      risk_level: 'Low',
      risk_factors: [
        { name: 'CVSS 4–7 (Low/Medium severity scanner scan)', points: 10 },
        { name: 'Low IOC reputation (Well-known commercial web scanner)', points: 5 }
      ],
      iocs: [
        { type: 'IPv4', value: '198.51.100.42', reputation: 'Benign/Scanner', enriched: true, context: 'Shodan scanning infrastructure node' },
        { type: 'Domain', value: 'shodan.io', reputation: 'Benign/Scanner', enriched: true, context: 'Shodan crawler web service' }
      ],
      enrichment: {
        cve_id: 'N/A',
        cvss: 0.0,
        severity: 'Low',
        description: 'Commercial search engine crawler scanning ports to index public-facing internet systems. Does not target vulnerabilities or exploit applications.',
        exploit_available: false,
        malware_families: [],
        threat_actors: ['Shodan Crawler']
      },
      mitre_mapping: [
        { tactic: 'Reconnaissance', technique: 'Active Scanning', technique_id: 'T1595', confidence: 'High' }
      ],
      ai_report: {
        summary: 'Incoming TCP connection check originating from Shodan crawler node. Shodan regularly scans all public IPv4 ranges to index open ports and SSL certificates.',
        attack_scenario: '1. Scanner initiates TCP SYN packets to port 80/443 -> 2. Local firewall blocks connection and drops packet -> 3. Scanner records port status as closed/filtered.',
        business_impact: 'None. Standard internet background scanning activity.',
        immediate_actions: [
          'No immediate action required, firewall dropped connection successfully.',
          'Verify that critical management consoles (RDP, SSH, database ports) are not exposed publicly.'
        ],
        long_term_remediation: [
          'Enforce strict firewall rules allowing access to internal portals only via VPN/Zero-Trust Access.'
        ],
        monitoring: [
          'Monitor firewalls for abnormal volume spikes from single scanning hosts.'
        ]
      },
      detection_rules: {
        sigma: `title: High-Volume Firewall Dropped Packets
id: a87612f0-7b24-4f1e-9273-a612df130a84
status: stable
description: Detects large quantity of firewall block events from a single IP source within a short timeframe.
logsource:
    category: firewall
detection:
    selection:
        Action: 'block'
    timeframe: 1m
    threshold: 100
    condition: selection
level: low`,
        yara: `rule Benign_Shodan_Scanner_Strings {
    meta:
        description = "Identifies Shodan scanner client identifiers"
        author = "SISA Hackathon SOC Team"

    strings:
        $s1 = "shodan.io" wide ascii
        $s2 = "Shodan" wide ascii

    condition:
        any of ($s*)
}`,
        splunk: `index=firewall action=blocked src_ip="198.51.100.42"
| stats count, values(dest_port) by src_ip`,
        kql: `NetworkConnections
| where Action == "blocked" and RemoteIP == "198.51.100.42"
| summarize Count=count() by RemoteIP, RemotePort`
      }
    }
  }
];

// Heuristics Engine to analyze arbitrary inputs
export function processThreatLocally(content, inputType = 'text', filename = '', options = null) {
  const normalizedContent = content || '';
  const pipelineOptions = options || { mitre_mapping: true, generate_rules: true, risk_scoring: true };
  
  // 1. Extract IOCs using regex
  const ips = cleanMatches(normalizedContent.match(REGEX_IPV4) || []);
  const domains = cleanMatches(normalizedContent.match(REGEX_DOMAIN) || [], ['microsoft.com', 'google.com', 'apple.com', 'github.com', 'shodan.io']);
  const urls = cleanMatches(normalizedContent.match(REGEX_URL) || [], ['http://localhost', 'https://localhost']);
  const emails = cleanMatches(normalizedContent.match(REGEX_EMAIL) || []);
  const md5s = cleanMatches(normalizedContent.match(REGEX_MD5) || []);
  const sha1s = cleanMatches(normalizedContent.match(REGEX_SHA1) || []);
  const sha256s = cleanMatches(normalizedContent.match(REGEX_SHA256) || []);
  const cves = cleanMatches(normalizedContent.match(REGEX_CVE) || []);

  const iocs = [];
  ips.forEach(ip => iocs.push({ type: 'IPv4', value: ip, reputation: 'Suspicious', enriched: false, context: 'Extracted network address' }));
  domains.forEach(dom => iocs.push({ type: 'Domain', value: dom, reputation: 'Suspicious', enriched: false, context: 'Extracted domain record' }));
  urls.forEach(url => iocs.push({ type: 'URL', value: url, reputation: 'Suspicious', enriched: false, context: 'Extracted resource link' }));
  emails.forEach(em => iocs.push({ type: 'Email', value: em, reputation: 'Suspicious', enriched: false, context: 'Extracted mail identifier' }));
  md5s.forEach(hash => iocs.push({ type: 'MD5', value: hash, reputation: 'Malicious', enriched: false, context: 'Extracted file signature' }));
  sha1s.forEach(hash => iocs.push({ type: 'SHA1', value: hash, reputation: 'Malicious', enriched: false, context: 'Extracted file signature' }));
  sha256s.forEach(hash => iocs.push({ type: 'SHA256', value: hash, reputation: 'Malicious', enriched: false, context: 'Extracted file signature' }));
  cves.forEach(cve => iocs.push({ type: 'CVE ID', value: cve.toUpperCase(), reputation: 'Vulnerability Reference', enriched: false, context: 'Extracted vulnerability link' }));

  // 2. Identify Category / Threat Profile
  let category = 'Unknown Threat';
  let isRansomware = false;
  let isPhishing = false;
  let isExploit = false;
  let hasMalware = false;
  let hasThreatActor = false;
  let hasHighReputationIOC = false;

  if (contains(normalizedContent, ['ransomware', 'encrypt', 'lockbit', 'ransom', 'shadow copy', 'vssadmin'])) {
    category = 'Ransomware Outbreak';
    isRansomware = true;
    hasMalware = true;
  } else if (contains(normalizedContent, ['phish', 'spearphishing', 'email', 'attachment', 'bulletin', 'pdf'])) {
    category = 'Spear Phishing Campaign';
    isPhishing = true;
  } else if (contains(normalizedContent, ['exploit', 'rce', 'vulnerability', 'cve-', 'cve_'])) {
    category = 'Vulnerability Exploitation';
    isExploit = true;
  } else if (cves.length > 0) {
    category = 'Vulnerability Analysis';
    isExploit = true;
  } else if (iocs.length > 0) {
    category = 'IOC Compromise Advisory';
  }

  // Determine risk factors and calculate score
  const risk_factors = [];
  let score = 0;
  let risk_level = 'Low';

  if (pipelineOptions.risk_scoring !== false) {
    // CVSS Score Factor
    if (isRansomware || contains(normalizedContent, ['critical', 'rce', 'cve-2023-46604'])) {
      risk_factors.push({ name: 'CVSS > 9 (Critical CVSS Vulnerability/Payload)', points: 30 });
      score += 30;
    } else if (isPhishing || isExploit || contains(normalizedContent, ['high', 'backdoor', 'trojan'])) {
      risk_factors.push({ name: 'CVSS 7–9 (High Severity System Indicator)', points: 20 });
      score += 20;
    } else {
      risk_factors.push({ name: 'CVSS 4–7 (Medium System Threat Exposure)', points: 10 });
      score += 10;
    }

    // Exploit available
    if (isExploit || isRansomware || contains(normalizedContent, ['exploit available', 'poc', 'metasploit', 'sideloading'])) {
      risk_factors.push({ name: 'Public exploit available (PoC publicly published)', points: 25 });
      score += 25;
      isExploit = true;
    }

    // Malware Associated
    if (isRansomware || contains(normalizedContent, ['malware', 'backdoor', 'loader', 'plugx', 'agent', 'shadowpad', 'kinsing'])) {
      risk_factors.push({ name: 'Malware associated (Active loader, Trojan, or RAT)', points: 15 });
      score += 15;
      hasMalware = true;
    }

    // Threat Actor Known
    if (contains(normalizedContent, ['apt', 'actor', 'group', 'nobelium', 'lockbit group', 'barium', 'kinsing group'])) {
      risk_factors.push({ name: 'Known threat actor (Attributed group activity)', points: 10 });
      score += 10;
      hasThreatActor = true;
    }

    // IOC Reputation
    if (iocs.length > 3 || contains(normalizedContent, ['tor', 'onion', 'malicious', 'c2', 'reputation'])) {
      risk_factors.push({ name: 'High IOC reputation (Active reputation blacklists)', points: 20 });
      score += 20;
      hasHighReputationIOC = true;
    }

    score = Math.min(100, score);
    
    if (score > 80) risk_level = 'Critical';
    else if (score > 60) risk_level = 'High';
    else if (score > 30) risk_level = 'Medium';
  } else {
    risk_level = 'N/A';
  }

  // 3. MITRE Mapping
  const mitre_mapping = [];
  if (pipelineOptions.mitre_mapping !== false) {
    if (isPhishing) {
      mitre_mapping.push({ tactic: 'Initial Access', technique: 'Phishing: Spearphishing Attachment', technique_id: 'T1566.001', confidence: 'High' });
      mitre_mapping.push({ tactic: 'Execution', technique: 'User Execution: Malicious File', technique_id: 'T1204.002', confidence: 'High' });
    } else if (isExploit) {
      mitre_mapping.push({ tactic: 'Initial Access', technique: 'Exploit Public-Facing Application', technique_id: 'T1190', confidence: 'High' });
      mitre_mapping.push({ tactic: 'Execution', technique: 'Exploitation for Client Execution', technique_id: 'T1203', confidence: 'Medium' });
    } else if (isRansomware) {
      mitre_mapping.push({ tactic: 'Initial Access', technique: 'Exploit Public-Facing Application', technique_id: 'T1190', confidence: 'High' });
      mitre_mapping.push({ tactic: 'Impact', technique: 'Data Encrypted for Impact', technique_id: 'T1486', confidence: 'Critical' });
      mitre_mapping.push({ tactic: 'Command and Control', technique: 'Application Layer Protocol', technique_id: 'T1071', confidence: 'High' });
    } else {
      mitre_mapping.push({ tactic: 'Reconnaissance', technique: 'Active Scanning', technique_id: 'T1595', confidence: 'Medium' });
    }
  }

  // 4. Generate AI Report
  const ai_report = {
    summary: `Heuristics scan analyzed an input of type "${inputType}" ${filename ? `named "${filename}"` : ''}. The content indicates a ${category} representing a ${risk_level} threat level with a calculated risk score of ${score}/100.`,
    attack_scenario: `The attack timeline starts with suspected initial exposure: ${isPhishing ? 'Spearphishing delivery of dynamic payloads' : isExploit ? 'Exploitation of network-facing software' : 'Execution of system commands'}. The threat moves to local execution of binaries, followed by outbound connections targeting discovered IOC addresses.`,
    business_impact: `This incident represents a threat to local systems. Potential impacts include: ${risk_level === 'Critical' ? 'Full directory encryption, widespread server downtime, and extortion' : risk_level === 'High' ? 'Credential hijacking and backdoor presence leading to lateral expansion' : 'System enumeration scans and informational logs leakage'}.`,
    immediate_actions: [
      `Deploy blocks for all extracted network indicators (${ips.length + domains.length} targets).`,
      `Quarantine any machines showing signs of binary matching extracted hashes.`,
      `Inspect Active Directory logs for abnormal logins surrounding this timeframe.`
    ],
    long_term_remediation: [
      'Implement structured segment firewalls and isolate administrative zones.',
      'Apply updates for any software products containing CVE profiles matching this event.',
      'Mandate comprehensive Endpoint Detection and Response configurations.'
    ],
    monitoring: [
      'Monitor outgoing socket logs for traffic reaching the threat IP targets.',
      'Analyze Windows Security Auditing logs for abnormal process creations.'
    ]
  };

  // 5. Generate Sigma Rule
  const mainIocValue = sha256s[0] || ips[0] || domains[0] || 'Malicious_Value';
  const detectionField = sha256s[0] ? 'Hashes|contains' : ips[0] ? 'DestinationIp' : domains[0] ? 'QueryName' : 'CommandLine';
  
  let sigmaRule = "";
  let yaraRule = "";
  let splunkQuery = "";
  let kqlQuery = "";

  if (pipelineOptions.generate_rules !== false) {
    sigmaRule = `title: Extracted IOC Network/File Block Event
id: ${Math.random().toString(36).substring(2, 15)}-${Math.random().toString(36).substring(2, 15)}
status: experimental
description: Detects traffic or file matching extracted indicators: ${mainIocValue}
logsource:
    category: dns_query / network_connection / process_creation
detection:
    selection:
        ${detectionField}:
            - '${mainIocValue}'
    condition: selection
falsepositives:
    - Internal validation testing
level: ${risk_level.toLowerCase()}`;

    yaraRule = `rule Local_Threat_IOC_Rule {
    meta:
        description = "Detects files containing signatures or references extracted locally"
        date = "${new Date().toISOString().split('T')[0]}"
        score = ${score}

    strings:
        ${sha256s[0] ? `$hash = "${sha256s[0]}" wide ascii` : ''}
        ${ips[0] ? `$ip = "${ips[0]}" wide ascii` : ''}
        ${domains[0] ? `$domain = "${domains[0]}" wide ascii` : ''}
        $generic = "${category}" wide ascii

    condition:
        any of ($*)
}`;

    splunkQuery = `index=security (${ips.map(ip => `"${ip}"`).concat(domains.map(d => `"${d}"`)).concat(sha256s.map(h => `"${h}"`)).join(' OR ') || 'no IOCs found'})
| table _time, host, src_ip, dest_ip, query, process_name, file_hash`;

    kqlQuery = `DeviceEvents
| where ProcessCommandLine has_any ("${ips.concat(domains).concat(sha256s).join('", "') || 'empty'}") 
  or NetworkIPHashes has_any ("${sha256s.join('", "') || 'empty'}")
| project TimeGenerated, DeviceName, ActionType, ProcessCommandLine`;
  }

  return {
    analysis_id: `local-${Math.random().toString(36).substring(2, 9)}`,
    timestamp: new Date().toISOString(),
    input_type: inputType,
    risk_score: score,
    risk_level,
    risk_factors,
    iocs,
    enrichment: {
      cve_id: cves[0] || 'N/A',
      cvss: score >= 90 ? 9.8 : score >= 70 ? 8.2 : score >= 40 ? 5.5 : 2.0,
      severity: risk_level,
      description: cves[0] ? `Extracted reference to security vulnerability ${cves[0]} associated with this threat brief.` : `General threat assessment representing a ${risk_level} severity environment profile.`,
      exploit_available: isExploit,
      malware_families: hasMalware ? [category] : [],
      threat_actors: hasThreatActor ? ['Attributed Actor'] : []
    },
    mitre_mapping,
    ai_report,
    detection_rules: {
      sigma: sigmaRule,
      yara: yaraRule,
      splunk: splunkQuery,
      kql: kqlQuery
    },
    options: pipelineOptions
  };
}

// History storage in LocalStorage
export function loadHistoryFromStorage() {
  try {
    const list = localStorage.getItem('sisa_threat_analyses');
    if (list) {
      return JSON.parse(list);
    }
  } catch (e) {
    console.error('Failed to load history', e);
  }
  // Load standard seed scenarios as default history if empty
  const defaultHistory = SEED_SCENARIOS.map(s => ({
    ...s.data,
    description: s.description,
    presetName: s.name,
    presetId: s.id
  }));
  saveHistoryToStorage(defaultHistory);
  return defaultHistory;
}

export function saveHistoryToStorage(history) {
  try {
    localStorage.setItem('sisa_threat_analyses', JSON.stringify(history));
  } catch (e) {
    console.error('Failed to save history', e);
  }
}

// API Functions
export const api = {
  // Submit raw threat analysis
  analyzeThreat: async (content, params = {}) => {
    const { inputType = 'text', filename = '', selectedPresetId = null, options = null } = params;

    // Check if preset selected
    if (selectedPresetId) {
      const preset = SEED_SCENARIOS.find(s => s.id === selectedPresetId);
      if (preset) {
        // Add to history and apply options filters to the static preset data
        const pipelineOptions = options || { mitre_mapping: true, generate_rules: true, risk_scoring: true };
        const result = { ...preset.data, timestamp: new Date().toISOString(), options: pipelineOptions };
        
        if (pipelineOptions.mitre_mapping === false) {
          result.mitre_mapping = [];
        }
        if (pipelineOptions.generate_rules === false) {
          result.detection_rules = { sigma: "", yara: "", splunk: "", kql: "" };
        }
        if (pipelineOptions.risk_scoring === false) {
          result.risk_score = 0;
          result.risk_level = "N/A";
          result.risk_factors = [];
        }

        const history = loadHistoryFromStorage();
        saveHistoryToStorage([result, ...history.filter(h => h.analysis_id !== result.analysis_id)]);
        return result;
      }
    }

    const requestOptions = options || {
      mitre_mapping: true,
      generate_rules: true,
      risk_scoring: true
    };

    // Attempt API request
    try {
      const response = await fetch(`${API_BASE}/analyze-threat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          input_type: inputType,
          content: content,
          options: requestOptions
        })
      });
      if (response.ok) {
        const result = await response.json();
        // Save to local storage history
        const history = loadHistoryFromStorage();
        saveHistoryToStorage([result, ...history]);
        return result;
      }
      throw new Error(`API error: ${response.status}`);
    } catch (err) {
      console.warn('API connection failed. Processing threat locally.', err);
      // Run local processor
      const result = processThreatLocally(content, inputType, filename, requestOptions);
      const history = loadHistoryFromStorage();
      saveHistoryToStorage([result, ...history]);
      return result;
    }
  },

  // Submit file upload
  uploadThreatFile: async (file, params = {}) => {
    const { selectedPresetId = null, options = null } = params;

    // Read file as text for the mock engine first
    const reader = new FileReader();
    const fileContentPromise = new Promise((resolve) => {
      reader.onload = (e) => resolve(e.target.result);
      reader.readAsText(file);
    });

    const content = await fileContentPromise;

    const requestOptions = options || {
      mitre_mapping: true,
      generate_rules: true,
      risk_scoring: true
    };

    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('options', JSON.stringify(requestOptions));

      const response = await fetch(`${API_BASE}/analyze-threat/upload`, {
        method: 'POST',
        body: formData
      });

      if (response.ok) {
        const result = await response.json();
        const history = loadHistoryFromStorage();
        saveHistoryToStorage([result, ...history]);
        return result;
      }
      throw new Error(`API error: ${response.status}`);
    } catch (err) {
      console.warn('API upload failed. Processing file content locally.', err);
      const result = processThreatLocally(content, 'file', file.name, requestOptions);
      const history = loadHistoryFromStorage();
      saveHistoryToStorage([result, ...history]);
      return result;
    }
  },

  // Fetch generated YARA rule from backend
  getYaraRule: async () => {
    try {
      const response = await fetch(`${API_BASE}/yara`);
      if (response.ok) {
        return await response.json();
      }
      throw new Error(`API error: ${response.status}`);
    } catch (err) {
      console.warn('API YARA fetch failed. Using mock data.', err);
      return {
        rule_name: 'Phishing_Campaign_June2026',
        meta: {
          description: 'Detects artifacts from finance phishing campaign',
          threat_level: 'critical'
        },
        strings: {
          $domain: 'secure-login-update.com',
          $ip: '185.199.108.153',
          $hash: '{ 5d 41 40 2a bc 4b 2a 76 }'
        },
        condition: 'any of them'
      };
    }
  },

  // Fetch paginated history list
  getAnalyses: async (page = 1, pageSize = 20) => {
    try {
      const response = await fetch(`${API_BASE}/analyses?page=${page}&pageSize=${pageSize}`);
      if (response.ok) {
        return await response.json();
      }
      throw new Error(`API error: ${response.status}`);
    } catch (err) {
      console.warn('API history fetch failed. Pulling from local storage.', err);
      const list = loadHistoryFromStorage();
      return {
        items: list.slice((page - 1) * pageSize, page * pageSize),
        total: list.length,
        page,
        pageSize
      };
    }
  },

  // Fetch single analysis details
  getAnalysisById: async (analysisId) => {
    try {
      const response = await fetch(`${API_BASE}/analyses/${analysisId}`);
      if (response.ok) {
        return await response.json();
      }
      throw new Error(`API error: ${response.status}`);
    } catch (err) {
      console.warn(`API get ID ${analysisId} failed. Scanning local history.`, err);
      const list = loadHistoryFromStorage();
      const item = list.find(h => h.analysis_id === analysisId);
      if (item) return item;
      throw new Error('Analysis record not found');
    }
  },

  // Clear local storage history
  clearHistory: () => {
    localStorage.removeItem('sisa_threat_analyses');
  }
};
