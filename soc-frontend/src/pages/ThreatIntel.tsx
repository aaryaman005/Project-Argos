import { useState } from 'react';
import { Search, Globe, Hash, Shield, AlertCircle, CheckCircle, Loader2, MapPin, Clock, Link2, Crosshair, Server, Activity, ExternalLink, Copy, ChevronRight } from 'lucide-react';

const H = { fontFamily: "'PT Serif', serif" };

interface GeoData { country: string; city: string; asn: string; org: string; }
interface WhoisData { registrar: string; created: string; expires: string; nameservers: string[]; }
interface DetectionEvent { date: string; source: string; category: string; severity: 'critical' | 'high' | 'medium' | 'low'; }
interface RelatedIOC { indicator: string; type: string; relationship: string; risk: number; }
interface MitreTechnique { id: string; name: string; tactic: string; }

interface LookupResult {
    indicator: string;
    type: string;
    risk_score: number;
    verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
    sources: { name: string; detections?: string; link?: string }[];
    explanation: string;
    geo?: GeoData;
    whois?: WhoisData;
    first_seen: string;
    last_seen: string;
    total_reports: number;
    tags: string[];
    mitre: MitreTechnique[];
    timeline: DetectionEvent[];
    related: RelatedIOC[];
    recommended_actions: string[];
}

const MOCK_RESULTS: Record<string, LookupResult> = {
    '185.220.101.34': {
        indicator: '185.220.101.34', type: 'IP Address', risk_score: 92, verdict: 'malicious',
        sources: [
            { name: 'VirusTotal', detections: '14/89 engines', link: 'https://virustotal.com' },
            { name: 'AbuseIPDB', detections: '1,247 reports', link: 'https://abuseipdb.com' },
            { name: 'OTX AlienVault', detections: '23 pulses', link: 'https://otx.alienvault.com' },
            { name: 'Shodan', detections: '12 open ports', link: 'https://shodan.io' },
        ],
        explanation: 'This IP is associated with a known Tor exit node frequently used in brute force and credential stuffing attacks. It has been flagged by 47 threat intelligence feeds and reported 1,200+ times on AbuseIPDB in the last 30 days. Network telemetry shows connections to known C2 infrastructure.',
        geo: { country: 'Germany', city: 'Frankfurt', asn: 'AS205100', org: 'F3 Netze e.V.' },
        first_seen: '2024-08-12', last_seen: '2026-02-23', total_reports: 1247,
        tags: ['tor-exit', 'brute-force', 'credential-stuffing', 'scanner', 'proxy'],
        mitre: [
            { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
            { id: 'T1090', name: 'Proxy', tactic: 'Command and Control' },
            { id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance' },
        ],
        timeline: [
            { date: '2026-02-23', source: 'AbuseIPDB', category: 'SSH brute force', severity: 'high' },
            { date: '2026-02-22', source: 'OTX', category: 'Tor exit node activity', severity: 'medium' },
            { date: '2026-02-21', source: 'VirusTotal', category: 'Malware distribution', severity: 'critical' },
            { date: '2026-02-20', source: 'Shodan', category: 'Port scan detected', severity: 'medium' },
            { date: '2026-02-18', source: 'AbuseIPDB', category: 'Web attack (SQLi)', severity: 'high' },
            { date: '2026-02-15', source: 'OTX', category: 'C2 beacon traffic', severity: 'critical' },
        ],
        related: [
            { indicator: '185.220.101.35', type: 'IP', relationship: 'Same subnet', risk: 88 },
            { indicator: '185.220.101.33', type: 'IP', relationship: 'Same ASN', risk: 85 },
            { indicator: 'c2.badactor.xyz', type: 'Domain', relationship: 'Resolved from IP', risk: 88 },
            { indicator: 'evil-payload.exe', type: 'File', relationship: 'Downloaded from', risk: 95 },
        ],
        recommended_actions: [
            'Block IP at perimeter firewall immediately',
            'Check SIEM for any connections to/from this IP in the last 90 days',
            'Investigate any successful SSH logins from this source',
            'Add to permanent blocklist and threat intelligence feed',
            'Review correlated alerts for lateral movement indicators',
        ],
    },
    'c2.badactor.xyz': {
        indicator: 'c2.badactor.xyz', type: 'Domain', risk_score: 88, verdict: 'malicious',
        sources: [
            { name: 'VirusTotal', detections: '8/89 engines', link: 'https://virustotal.com' },
            { name: 'URLhaus', detections: 'Active C2', link: 'https://urlhaus.abuse.ch' },
            { name: 'OTX AlienVault', detections: '5 pulses', link: 'https://otx.alienvault.com' },
        ],
        explanation: 'This domain has been identified as a command-and-control server for a known RAT variant (AsyncRAT). DNS analysis shows it was registered 14 days ago with privacy-protected registration — consistent with malicious infrastructure. It resolves to multiple IPs across bulletproof hosting providers.',
        whois: { registrar: 'Namecheap', created: '2026-02-09', expires: '2027-02-09', nameservers: ['ns1.suspiciousdns.com', 'ns2.suspiciousdns.com'] },
        first_seen: '2026-02-10', last_seen: '2026-02-23', total_reports: 89,
        tags: ['c2', 'rat', 'asyncrat', 'dga-like', 'bulletproof-hosting'],
        mitre: [
            { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' },
            { id: 'T1568', name: 'Dynamic Resolution', tactic: 'Command and Control' },
            { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control' },
        ],
        timeline: [
            { date: '2026-02-23', source: 'URLhaus', category: 'Active C2 communication', severity: 'critical' },
            { date: '2026-02-22', source: 'VirusTotal', category: 'New malware sample phoning home', severity: 'high' },
            { date: '2026-02-20', source: 'OTX', category: 'Added to threat pulse', severity: 'medium' },
            { date: '2026-02-10', source: 'URLhaus', category: 'Domain first observed', severity: 'low' },
        ],
        related: [
            { indicator: '185.220.101.34', type: 'IP', relationship: 'Resolves to', risk: 92 },
            { indicator: 'a1b2c3d4e5f6', type: 'Hash', relationship: 'Payload hash', risk: 45 },
            { indicator: 'dropper.badactor.xyz', type: 'Domain', relationship: 'Same registrant', risk: 79 },
        ],
        recommended_actions: [
            'Block domain at DNS resolver and web proxy',
            'Search proxy logs for any outbound connections to this domain',
            'Scan endpoints for AsyncRAT indicators',
            'Add domain and all resolved IPs to blocklist',
        ],
    },
    'a1b2c3d4e5f6': {
        indicator: 'a1b2c3d4e5f6', type: 'File Hash (MD5)', risk_score: 45, verdict: 'suspicious',
        sources: [
            { name: 'VirusTotal', detections: '3/72 engines', link: 'https://virustotal.com' },
            { name: 'Hybrid Analysis', detections: 'Score: 55/100', link: 'https://hybrid-analysis.com' },
        ],
        explanation: 'This file hash has limited detections (3/72 engines on VirusTotal). Behavioral analysis in sandbox shows the executable creates a scheduled task, modifies registry keys, and attempts outbound connections on port 443 to non-standard domains. The file uses UPX packing and anti-VM techniques.',
        first_seen: '2026-02-18', last_seen: '2026-02-22', total_reports: 5,
        tags: ['packed-upx', 'anti-vm', 'scheduled-task', 'registry-modification'],
        mitre: [
            { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'Persistence' },
            { id: 'T1112', name: 'Modify Registry', tactic: 'Defense Evasion' },
            { id: 'T1027', name: 'Obfuscated Files', tactic: 'Defense Evasion' },
        ],
        timeline: [
            { date: '2026-02-22', source: 'Hybrid Analysis', category: 'Sandbox detonation', severity: 'medium' },
            { date: '2026-02-20', source: 'VirusTotal', category: 'First submission', severity: 'low' },
            { date: '2026-02-18', source: 'VirusTotal', category: 'New hash observed', severity: 'low' },
        ],
        related: [
            { indicator: 'c2.badactor.xyz', type: 'Domain', relationship: 'Contacts domain', risk: 88 },
            { indicator: 'b2c3d4e5f6a1', type: 'Hash', relationship: 'Similar binary', risk: 52 },
        ],
        recommended_actions: [
            'Quarantine file on any endpoints where detected',
            'Submit to sandbox for deeper behavioral analysis',
            'Check EDR logs for file execution and child processes',
            'Monitor for C2 callbacks to associated domains',
        ],
    },
    '45.155.205.233': {
        indicator: '45.155.205.233', type: 'IP Address', risk_score: 97, verdict: 'malicious',
        sources: [
            { name: 'VirusTotal', detections: '19/89 engines', link: 'https://virustotal.com' },
            { name: 'AbuseIPDB', detections: '3,412 reports', link: 'https://abuseipdb.com' },
            { name: 'OTX AlienVault', detections: '41 pulses', link: 'https://otx.alienvault.com' },
            { name: 'Shodan', detections: '23 open ports', link: 'https://shodan.io' },
        ],
        explanation: 'This IP is a known ransomware C2 server associated with the LockBit 3.0 ransomware-as-a-service operation. It hosts the data exfiltration endpoint and negotiation portal. Multiple ransomware incidents across finance and healthcare sectors have traced back to this infrastructure. Active since late 2025.',
        geo: { country: 'Russia', city: 'Moscow', asn: 'AS49505', org: 'Selectel Ltd.' },
        first_seen: '2025-11-03', last_seen: '2026-02-23', total_reports: 3412,
        tags: ['ransomware', 'lockbit', 'c2', 'data-exfiltration', 'raas', 'extortion'],
        mitre: [
            { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
            { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'Exfiltration' },
            { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' },
        ],
        timeline: [
            { date: '2026-02-23', source: 'AbuseIPDB', category: 'Ransomware C2 beacon', severity: 'critical' },
            { date: '2026-02-22', source: 'OTX', category: 'New LockBit campaign observed', severity: 'critical' },
            { date: '2026-02-20', source: 'VirusTotal', category: 'Payload download server', severity: 'high' },
            { date: '2026-02-18', source: 'AbuseIPDB', category: 'Mass scanning activity', severity: 'medium' },
            { date: '2026-02-14', source: 'Shodan', category: 'RDP exposed on non-standard port', severity: 'high' },
        ],
        related: [
            { indicator: '45.155.205.234', type: 'IP', relationship: 'Same subnet', risk: 94 },
            { indicator: 'lockbit-negotiate.onion', type: 'Domain', relationship: 'Tor negotiation site', risk: 99 },
            { indicator: 'e7d3f1a2b4c5', type: 'Hash', relationship: 'Ransomware payload', risk: 98 },
        ],
        recommended_actions: [
            'CRITICAL: Block at all perimeter firewalls immediately',
            'Trigger incident response playbook for ransomware',
            'Check for any data exfiltration to this IP in last 30 days',
            'Audit all RDP and VPN access logs for connections from this IP',
            'Notify CISO and legal team if data exfiltration confirmed',
            'Preserve forensic evidence on affected endpoints',
        ],
    },
    '94.232.42.116': {
        indicator: '94.232.42.116', type: 'IP Address', risk_score: 78, verdict: 'malicious',
        sources: [
            { name: 'VirusTotal', detections: '7/89 engines', link: 'https://virustotal.com' },
            { name: 'AbuseIPDB', detections: '567 reports', link: 'https://abuseipdb.com' },
            { name: 'Shodan', detections: '8 open ports', link: 'https://shodan.io' },
        ],
        explanation: 'This IP hosts a cryptomining operation that has been used to deploy XMRig miners through compromised web servers. It scans for exposed Redis, Docker, and Kubernetes instances, then deploys cryptocurrency miners. Associated with the TeamTNT threat group.',
        geo: { country: 'Netherlands', city: 'Amsterdam', asn: 'AS202425', org: 'IP Volume Inc.' },
        first_seen: '2025-06-14', last_seen: '2026-02-22', total_reports: 567,
        tags: ['cryptominer', 'xmrig', 'teamtnt', 'kubernetes-exploit', 'docker-abuse'],
        mitre: [
            { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact' },
            { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
            { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
        ],
        timeline: [
            { date: '2026-02-22', source: 'AbuseIPDB', category: 'Docker API exploitation attempt', severity: 'high' },
            { date: '2026-02-19', source: 'Shodan', category: 'Scanning for exposed Redis instances', severity: 'medium' },
            { date: '2026-02-15', source: 'VirusTotal', category: 'XMRig miner binary served', severity: 'high' },
            { date: '2026-01-28', source: 'OTX', category: 'TeamTNT attribution', severity: 'medium' },
        ],
        related: [
            { indicator: '94.232.42.117', type: 'IP', relationship: 'Same subnet', risk: 72 },
            { indicator: 'teamtnt-miner.sh', type: 'File', relationship: 'Dropper script', risk: 80 },
        ],
        recommended_actions: [
            'Block IP at firewall and verify all Docker/Kubernetes APIs are not publicly exposed',
            'Scan all container hosts for unauthorized XMRig processes',
            'Audit Redis, Docker, and K8s access controls',
            'Review cloud billing for unexpected compute usage spikes',
        ],
    },
    '198.51.100.78': {
        indicator: '198.51.100.78', type: 'IP Address', risk_score: 85, verdict: 'malicious',
        sources: [
            { name: 'VirusTotal', detections: '11/89 engines', link: 'https://virustotal.com' },
            { name: 'AbuseIPDB', detections: '892 reports', link: 'https://abuseipdb.com' },
            { name: 'OTX AlienVault', detections: '15 pulses', link: 'https://otx.alienvault.com' },
        ],
        explanation: 'This IP is part of a Cobalt Strike infrastructure operated by the APT29 (Cozy Bear) threat group. It serves as a staging server for post-exploitation tooling and lateral movement within compromised networks. The beacon uses HTTPS with a custom malleable C2 profile mimicking legitimate Microsoft traffic.',
        geo: { country: 'United States', city: 'Ashburn', asn: 'AS14618', org: 'Amazon Web Services' },
        first_seen: '2025-09-20', last_seen: '2026-02-23', total_reports: 892,
        tags: ['apt29', 'cobalt-strike', 'nation-state', 'lateral-movement', 'c2'],
        mitre: [
            { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution' },
            { id: 'T1021.006', name: 'Windows Remote Management', tactic: 'Lateral Movement' },
            { id: 'T1573', name: 'Encrypted Channel', tactic: 'Command and Control' },
            { id: 'T1036', name: 'Masquerading', tactic: 'Defense Evasion' },
        ],
        timeline: [
            { date: '2026-02-23', source: 'OTX', category: 'Cobalt Strike beacon detected', severity: 'critical' },
            { date: '2026-02-21', source: 'AbuseIPDB', category: 'HTTPS C2 communication', severity: 'high' },
            { date: '2026-02-18', source: 'VirusTotal', category: 'Cobalt Strike stager served', severity: 'critical' },
            { date: '2026-02-10', source: 'OTX', category: 'APT29 campaign linkage', severity: 'high' },
        ],
        related: [
            { indicator: 'update-service.microsoftonline.xyz', type: 'Domain', relationship: 'Malleable C2 domain', risk: 90 },
            { indicator: '203.0.113.42', type: 'IP', relationship: 'Secondary C2', risk: 82 },
            { indicator: 'beacon_x64.dll', type: 'File', relationship: 'Beacon payload', risk: 91 },
        ],
        recommended_actions: [
            'CRITICAL: Escalate to SOC Tier 3 — potential nation-state actor',
            'Isolate any endpoints communicating with this IP',
            'Deploy Cobalt Strike YARA rules across all endpoints',
            'Check for PowerShell execution anomalies in last 90 days',
            'Engage threat hunting team for lateral movement analysis',
        ],
    },
    '203.0.113.42': {
        indicator: '203.0.113.42', type: 'IP Address', risk_score: 82, verdict: 'malicious',
        sources: [
            { name: 'VirusTotal', detections: '9/89 engines', link: 'https://virustotal.com' },
            { name: 'AbuseIPDB', detections: '423 reports', link: 'https://abuseipdb.com' },
            { name: 'Shodan', detections: '6 open ports', link: 'https://shodan.io' },
        ],
        explanation: 'Secondary Cobalt Strike C2 server linked to the same APT29 campaign as 198.51.100.78. This server is used for backup C2 communications and data staging. It rotates IPs every 72 hours but has been consistently attributed to the same infrastructure based on TLS certificate fingerprints.',
        geo: { country: 'Singapore', city: 'Singapore', asn: 'AS16509', org: 'Amazon Web Services' },
        first_seen: '2025-12-05', last_seen: '2026-02-22', total_reports: 423,
        tags: ['apt29', 'cobalt-strike', 'backup-c2', 'ip-rotation', 'tls-fingerprint'],
        mitre: [
            { id: 'T1573', name: 'Encrypted Channel', tactic: 'Command and Control' },
            { id: 'T1008', name: 'Fallback Channels', tactic: 'Command and Control' },
            { id: 'T1074', name: 'Data Staged', tactic: 'Collection' },
        ],
        timeline: [
            { date: '2026-02-22', source: 'AbuseIPDB', category: 'Encrypted C2 traffic', severity: 'high' },
            { date: '2026-02-19', source: 'VirusTotal', category: 'TLS cert matches known APT infra', severity: 'critical' },
            { date: '2026-02-12', source: 'Shodan', category: 'Cobalt Strike team server fingerprint', severity: 'high' },
        ],
        related: [
            { indicator: '198.51.100.78', type: 'IP', relationship: 'Primary C2', risk: 85 },
            { indicator: 'update-service.microsoftonline.xyz', type: 'Domain', relationship: 'Shared C2 domain', risk: 90 },
        ],
        recommended_actions: [
            'Block IP and add TLS certificate hash to network detection rules',
            'Cross-reference with primary C2 indicators',
            'Implement DNS sinkholing for associated domains',
            'Enable enhanced logging on all egress points',
        ],
    },
    'phishing-login.accounts-verify.com': {
        indicator: 'phishing-login.accounts-verify.com', type: 'Domain', risk_score: 91, verdict: 'malicious',
        sources: [
            { name: 'VirusTotal', detections: '12/89 engines', link: 'https://virustotal.com' },
            { name: 'URLhaus', detections: 'Phishing site', link: 'https://urlhaus.abuse.ch' },
            { name: 'PhishTank', detections: 'Verified phish', link: 'https://phishtank.org' },
            { name: 'Google Safe Browsing', detections: 'Flagged', link: 'https://safebrowsing.google.com' },
        ],
        explanation: 'This domain is impersonating a Microsoft 365 login page to harvest corporate credentials. The page uses an Evilginx reverse proxy to capture session tokens in real-time, bypassing MFA. Currently targeting financial services firms via spear-phishing emails with invoice-themed lures.',
        whois: { registrar: 'Porkbun', created: '2026-02-19', expires: '2027-02-19', nameservers: ['ns1.cloudflare.com', 'ns2.cloudflare.com'] },
        first_seen: '2026-02-19', last_seen: '2026-02-23', total_reports: 234,
        tags: ['phishing', 'credential-harvest', 'evilginx', 'mfa-bypass', 'o365-impersonation'],
        mitre: [
            { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access' },
            { id: 'T1539', name: 'Steal Web Session Cookie', tactic: 'Credential Access' },
            { id: 'T1078', name: 'Valid Accounts', tactic: 'Persistence' },
        ],
        timeline: [
            { date: '2026-02-23', source: 'PhishTank', category: 'Active phishing campaign', severity: 'critical' },
            { date: '2026-02-22', source: 'URLhaus', category: 'Evilginx proxy detected', severity: 'critical' },
            { date: '2026-02-21', source: 'VirusTotal', category: 'Multiple submissions from users', severity: 'high' },
            { date: '2026-02-20', source: 'Google Safe Browsing', category: 'Domain flagged', severity: 'medium' },
            { date: '2026-02-19', source: 'URLhaus', category: 'Domain registered', severity: 'low' },
        ],
        related: [
            { indicator: '104.21.45.67', type: 'IP', relationship: 'Hosting IP (Cloudflare)', risk: 30 },
            { indicator: 'accounts-verify.com', type: 'Domain', relationship: 'Parent domain', risk: 85 },
            { indicator: 'secure-login.office365-auth.net', type: 'Domain', relationship: 'Same campaign', risk: 89 },
        ],
        recommended_actions: [
            'Block domain at web proxy and DNS resolver immediately',
            'Send org-wide phishing alert to all employees',
            'Check email gateway logs for delivery of emails containing this domain',
            'Force password reset and MFA re-enrollment for any users who clicked',
            'Report to Microsoft, PhishTank, and Google Safe Browsing',
        ],
    },
    'update-service.microsoftonline.xyz': {
        indicator: 'update-service.microsoftonline.xyz', type: 'Domain', risk_score: 90, verdict: 'malicious',
        sources: [
            { name: 'VirusTotal', detections: '10/89 engines', link: 'https://virustotal.com' },
            { name: 'OTX AlienVault', detections: '18 pulses', link: 'https://otx.alienvault.com' },
            { name: 'URLhaus', detections: 'Malware distribution', link: 'https://urlhaus.abuse.ch' },
        ],
        explanation: 'This domain impersonates Microsoft Online services and is used as the malleable C2 profile domain for an APT29 Cobalt Strike campaign. HTTPS traffic to this domain blends in with legitimate Microsoft authentication traffic, making detection challenging without TLS inspection.',
        whois: { registrar: 'Njalla', created: '2025-09-15', expires: '2026-09-15', nameservers: ['ns1.njalla.com', 'ns2.njalla.com'] },
        first_seen: '2025-09-16', last_seen: '2026-02-23', total_reports: 312,
        tags: ['apt29', 'cobalt-strike', 'typosquatting', 'malleable-c2', 'nation-state'],
        mitre: [
            { id: 'T1583.001', name: 'Acquire Infrastructure: Domains', tactic: 'Resource Development' },
            { id: 'T1036.005', name: 'Match Legitimate Name', tactic: 'Defense Evasion' },
            { id: 'T1071.001', name: 'Web Protocols', tactic: 'Command and Control' },
        ],
        timeline: [
            { date: '2026-02-23', source: 'OTX', category: 'Active C2 communication', severity: 'critical' },
            { date: '2026-02-20', source: 'URLhaus', category: 'Cobalt Strike stager download', severity: 'critical' },
            { date: '2026-02-14', source: 'VirusTotal', category: 'New detections added', severity: 'high' },
            { date: '2025-09-16', source: 'OTX', category: 'First observed in APT29 pulse', severity: 'medium' },
        ],
        related: [
            { indicator: '198.51.100.78', type: 'IP', relationship: 'Primary C2 server', risk: 85 },
            { indicator: '203.0.113.42', type: 'IP', relationship: 'Backup C2 server', risk: 82 },
        ],
        recommended_actions: [
            'Block domain at DNS resolver and add to proxy blocklist',
            'Enable TLS inspection for microsoftonline.xyz subdomains',
            'Deploy custom Snort/Suricata rule for this C2 profile',
            'Search network logs for any historical connections to this domain',
        ],
    },
    '10.0.0.1': {
        indicator: '10.0.0.1', type: 'IP Address (Private)', risk_score: 5, verdict: 'clean',
        sources: [
            { name: 'VirusTotal', detections: '0/89 engines', link: 'https://virustotal.com' },
        ],
        explanation: 'This is a private/internal IP address (RFC 1918). It cannot be routed on the public internet and is typically used for local network infrastructure such as gateway routers. No external threat intelligence data is applicable to private IP ranges.',
        first_seen: '-', last_seen: '-', total_reports: 0,
        tags: ['rfc1918', 'private-ip', 'internal', 'gateway'],
        mitre: [],
        timeline: [],
        related: [],
        recommended_actions: [
            'No external threat action needed — this is a private IP',
            'If investigating lateral movement, check internal SIEM logs',
            'Verify this IP belongs to expected infrastructure',
        ],
    },
    '77.91.68.200': {
        indicator: '77.91.68.200', type: 'IP Address', risk_score: 89, verdict: 'malicious',
        sources: [
            { name: 'VirusTotal', detections: '16/89 engines', link: 'https://virustotal.com' },
            { name: 'AbuseIPDB', detections: '2,100 reports', link: 'https://abuseipdb.com' },
            { name: 'OTX AlienVault', detections: '29 pulses', link: 'https://otx.alienvault.com' },
            { name: 'ThreatFox', detections: '12 IOCs', link: 'https://threatfox.abuse.ch' },
        ],
        explanation: 'This IP is a prolific malware distribution server hosting multiple stealer and loader families including RedLine Stealer, Raccoon Stealer v2, and SmokeLoader. It serves as both the initial payload delivery and exfiltration endpoint for stolen credentials. Active for over 6 months with consistent abuse reports.',
        geo: { country: 'Romania', city: 'Bucharest', asn: 'AS34977', org: 'BelCloud Hosting Corporation' },
        first_seen: '2025-08-20', last_seen: '2026-02-23', total_reports: 2100,
        tags: ['redline-stealer', 'raccoon-stealer', 'smokeloader', 'infostealer', 'credential-theft', 'loader'],
        mitre: [
            { id: 'T1555', name: 'Credentials from Password Stores', tactic: 'Credential Access' },
            { id: 'T1005', name: 'Data from Local System', tactic: 'Collection' },
            { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
            { id: 'T1129', name: 'Shared Modules', tactic: 'Execution' },
        ],
        timeline: [
            { date: '2026-02-23', source: 'ThreatFox', category: 'RedLine Stealer C2 active', severity: 'critical' },
            { date: '2026-02-22', source: 'AbuseIPDB', category: 'Malware payload delivery', severity: 'high' },
            { date: '2026-02-20', source: 'OTX', category: 'New Raccoon Stealer variant', severity: 'critical' },
            { date: '2026-02-17', source: 'VirusTotal', category: 'SmokeLoader download observed', severity: 'high' },
            { date: '2026-02-12', source: 'AbuseIPDB', category: 'Credential exfiltration endpoint', severity: 'critical' },
        ],
        related: [
            { indicator: '77.91.68.201', type: 'IP', relationship: 'Same hosting block', risk: 85 },
            { indicator: 'download-update.cloud', type: 'Domain', relationship: 'Distribution domain', risk: 87 },
            { indicator: 'e7d3f1a2b4c5', type: 'Hash', relationship: 'RedLine sample', risk: 93 },
            { indicator: 'f8e4g2h3i6j7', type: 'Hash', relationship: 'Raccoon Stealer sample', risk: 91 },
        ],
        recommended_actions: [
            'Block IP at firewall and add all related IOCs to blocklist',
            'Run endpoint scans for RedLine, Raccoon, and SmokeLoader signatures',
            'Check for credential exfiltration — force password resets if compromised',
            'Review browser credential stores on affected endpoints',
            'Monitor for new accounts created with potentially stolen credentials',
        ],
    },
    'e7d3f1a2b4c5': {
        indicator: 'e7d3f1a2b4c5', type: 'File Hash (SHA256)', risk_score: 93, verdict: 'malicious',
        sources: [
            { name: 'VirusTotal', detections: '52/72 engines', link: 'https://virustotal.com' },
            { name: 'Hybrid Analysis', detections: 'Score: 92/100', link: 'https://hybrid-analysis.com' },
            { name: 'MalwareBazaar', detections: 'RedLine Stealer', link: 'https://bazaar.abuse.ch' },
        ],
        explanation: 'This is a RedLine Stealer variant compiled on 2026-02-18. It targets browser-stored credentials, cryptocurrency wallets, Discord tokens, and system information. The malware uses process hollowing to inject into legitimate Windows processes and communicates via encrypted TCP to its C2 server.',
        first_seen: '2026-02-18', last_seen: '2026-02-23', total_reports: 156,
        tags: ['redline-stealer', 'infostealer', 'process-hollowing', 'credential-theft', 'crypto-wallet'],
        mitre: [
            { id: 'T1055.012', name: 'Process Hollowing', tactic: 'Defense Evasion' },
            { id: 'T1555.003', name: 'Credentials from Web Browsers', tactic: 'Credential Access' },
            { id: 'T1005', name: 'Data from Local System', tactic: 'Collection' },
            { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
        ],
        timeline: [
            { date: '2026-02-23', source: 'MalwareBazaar', category: 'Active distribution campaign', severity: 'critical' },
            { date: '2026-02-22', source: 'VirusTotal', category: '52 engine detections', severity: 'critical' },
            { date: '2026-02-20', source: 'Hybrid Analysis', category: 'Full behavioral analysis', severity: 'high' },
            { date: '2026-02-18', source: 'VirusTotal', category: 'First submission', severity: 'medium' },
        ],
        related: [
            { indicator: '77.91.68.200', type: 'IP', relationship: 'C2 server', risk: 89 },
            { indicator: 'f8e4g2h3i6j7', type: 'Hash', relationship: 'Same campaign dropper', risk: 91 },
            { indicator: 'download-update.cloud', type: 'Domain', relationship: 'Distribution site', risk: 87 },
        ],
        recommended_actions: [
            'Deploy hash to EDR blocklist across all endpoints immediately',
            'Run full system scan on endpoints where file was detected',
            'Force password resets for all accounts on affected machines',
            'Revoke Discord and other application tokens',
            'Check cryptocurrency wallet addresses for unauthorized transfers',
        ],
    },
    '154.216.17.89': {
        indicator: '154.216.17.89', type: 'IP Address', risk_score: 75, verdict: 'malicious',
        sources: [
            { name: 'VirusTotal', detections: '6/89 engines', link: 'https://virustotal.com' },
            { name: 'AbuseIPDB', detections: '340 reports', link: 'https://abuseipdb.com' },
            { name: 'Shodan', detections: '15 open ports', link: 'https://shodan.io' },
        ],
        explanation: 'This IP operates as a Mirai botnet controller targeting IoT devices, routers, and CCTV cameras. It exploits default credentials and known vulnerabilities (CVE-2023-46747, CVE-2024-3400) to compromise devices and enlist them for DDoS attacks. Recent campaigns have targeted gaming and financial infrastructure.',
        geo: { country: 'China', city: 'Hong Kong', asn: 'AS135377', org: 'UCLOUD Information Technology' },
        first_seen: '2025-10-11', last_seen: '2026-02-22', total_reports: 340,
        tags: ['mirai', 'botnet', 'iot', 'ddos', 'default-credentials', 'cve-exploit'],
        mitre: [
            { id: 'T1498', name: 'Network Denial of Service', tactic: 'Impact' },
            { id: 'T1078.001', name: 'Default Accounts', tactic: 'Initial Access' },
            { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
        ],
        timeline: [
            { date: '2026-02-22', source: 'AbuseIPDB', category: 'DDoS attack source', severity: 'high' },
            { date: '2026-02-19', source: 'Shodan', category: 'Scanning for IoT devices', severity: 'medium' },
            { date: '2026-02-15', source: 'VirusTotal', category: 'Mirai variant binary served', severity: 'high' },
            { date: '2026-02-08', source: 'AbuseIPDB', category: 'Telnet brute force', severity: 'medium' },
        ],
        related: [
            { indicator: '154.216.17.90', type: 'IP', relationship: 'Same botnet cluster', risk: 73 },
            { indicator: '154.216.17.91', type: 'IP', relationship: 'Same botnet cluster', risk: 71 },
        ],
        recommended_actions: [
            'Block IP at perimeter and verify all IoT device firmware is updated',
            'Change default credentials on all network devices',
            'Patch CVE-2023-46747 and CVE-2024-3400 on exposed appliances',
            'Segment IoT devices from production network',
            'Enable DDoS mitigation if under active attack',
        ],
    },
    '8.8.8.8': {
        indicator: '8.8.8.8', type: 'IP Address', risk_score: 2, verdict: 'clean',
        sources: [
            { name: 'VirusTotal', detections: '0/89 engines', link: 'https://virustotal.com' },
            { name: 'AbuseIPDB', detections: '12 reports (FP)', link: 'https://abuseipdb.com' },
            { name: 'Shodan', detections: '2 open ports', link: 'https://shodan.io' },
        ],
        explanation: 'This is Google\'s public DNS resolver (8.8.8.8). It is a legitimate and widely-used service. The small number of reports on AbuseIPDB are false positives from misconfigured security tools detecting DNS traffic. No malicious activity is associated with this IP.',
        geo: { country: 'United States', city: 'Mountain View', asn: 'AS15169', org: 'Google LLC' },
        first_seen: '2009-01-01', last_seen: '2026-02-23', total_reports: 12,
        tags: ['dns-resolver', 'google', 'legitimate', 'public-service'],
        mitre: [],
        timeline: [
            { date: '2026-02-23', source: 'AbuseIPDB', category: 'False positive DNS report', severity: 'low' },
        ],
        related: [
            { indicator: '8.8.4.4', type: 'IP', relationship: 'Google DNS secondary', risk: 2 },
        ],
        recommended_actions: [
            'No action needed — this is a legitimate Google DNS resolver',
            'If flagging this IP, review your detection rules for false positives',
            'Ensure DNS logging is enabled for visibility into resolution activity',
        ],
    },
};


const sevColors: Record<string, string> = {
    critical: 'text-red-400 bg-red-500/10',
    high: 'text-orange-400 bg-orange-500/10',
    medium: 'text-yellow-400 bg-yellow-500/10',
    low: 'text-blue-400 bg-blue-500/10',
};

const verdictConfig = {
    malicious: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', icon: AlertCircle, label: 'MALICIOUS' },
    suspicious: { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', icon: AlertCircle, label: 'SUSPICIOUS' },
    clean: { color: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/20', icon: CheckCircle, label: 'CLEAN' },
    unknown: { color: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/20', icon: Shield, label: 'UNKNOWN' },
};

function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
}

export default function ThreatIntel() {
    const [query, setQuery] = useState('');
    const [result, setResult] = useState<LookupResult | null>(null);
    const [loading, setLoading] = useState(false);
    const [searched, setSearched] = useState(false);
    const [activeTab, setActiveTab] = useState<'overview' | 'timeline' | 'related' | 'actions'>('overview');

    const handleLookup = () => {
        if (!query.trim()) return;
        setLoading(true);
        setSearched(true);
        setActiveTab('overview');
        setTimeout(() => {
            const match = Object.entries(MOCK_RESULTS).find(([key]) => query.toLowerCase().includes(key.toLowerCase()));
            setResult(match ? match[1] : {
                indicator: query, type: 'Unknown', risk_score: 0, verdict: 'unknown' as const,
                sources: [], explanation: 'No threat intelligence data found for this indicator. It may be benign or not yet indexed by threat feeds.',
                first_seen: '-', last_seen: '-', total_reports: 0, tags: [], mitre: [], timeline: [], related: [], recommended_actions: [],
            });
            setLoading(false);
        }, 1200);
    };

    const lookupRelated = (indicator: string) => {
        setQuery(indicator);
        setLoading(true);
        setSearched(true);
        setActiveTab('overview');
        setTimeout(() => {
            const match = Object.entries(MOCK_RESULTS).find(([key]) => indicator.toLowerCase().includes(key.toLowerCase()));
            setResult(match ? match[1] : {
                indicator, type: 'Unknown', risk_score: 0, verdict: 'unknown' as const,
                sources: [], explanation: 'No threat intelligence data found for this indicator.',
                first_seen: '-', last_seen: '-', total_reports: 0, tags: [], mitre: [], timeline: [], related: [], recommended_actions: [],
            });
            setLoading(false);
        }, 800);
    };

    const v = result ? verdictConfig[result.verdict] : null;

    return (
        <div className="p-6 space-y-6">
            <div>
                <h2 className="text-xl font-bold" style={H}>Threat Intelligence</h2>
                <p className="text-sm text-[#6B7089] mt-1">Enrich and analyze indicators of compromise across multiple threat feeds</p>
            </div>

            {/* Lookup Form */}
            <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                <h3 className="text-base font-semibold mb-4" style={H}>IOC Lookup</h3>
                <div className="flex gap-3">
                    <div className="relative flex-1">
                        <Search className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 text-[#6B7089]" />
                        <input type="text" value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleLookup()}
                            placeholder="Enter IP, domain, or file hash..."
                            className="w-full bg-[#1a1c3a] border border-white/5 rounded-xl py-3 pl-11 pr-4 text-sm outline-none focus:ring-1 focus:ring-[#7C5CFC] text-white placeholder-[#6B7089]" />
                    </div>
                    <button onClick={handleLookup} disabled={loading}
                        className="px-6 py-3 rounded-xl bg-[#7C5CFC] text-white text-sm font-medium hover:bg-[#6B4EE0] disabled:opacity-50 transition-colors flex items-center gap-2">
                        {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />} Lookup
                    </button>
                </div>
                <div className="flex gap-2 mt-3">
                    {Object.keys(MOCK_RESULTS).map(ex => (
                        <button key={ex} onClick={() => { setQuery(ex); }} className="text-xs px-2.5 py-1 rounded-lg bg-white/5 text-[#6B7089] hover:text-white hover:bg-white/10 transition-colors font-mono">{ex}</button>
                    ))}
                </div>
            </div>

            {/* Loading */}
            {loading && (
                <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-12 flex flex-col items-center">
                    <Loader2 className="w-8 h-8 text-[#7C5CFC] animate-spin mb-3" />
                    <p className="text-sm text-[#6B7089]">Querying threat intelligence feeds...</p>
                    <div className="flex gap-4 mt-4">
                        {['VirusTotal', 'AbuseIPDB', 'OTX', 'URLhaus'].map((s, i) => (
                            <span key={s} className="text-xs text-[#6B7089] animate-pulse" style={{ animationDelay: `${i * 200}ms` }}>{s}</span>
                        ))}
                    </div>
                </div>
            )}

            {/* Results */}
            {!loading && result && (
                <div className="space-y-4">
                    {/* Verdict Banner */}
                    <div className={`bg-[#111328]/60 backdrop-blur-xl border ${v!.border} rounded-2xl p-6`}>
                        <div className="flex items-start justify-between">
                            <div className="flex-1">
                                <div className="flex items-center gap-3 mb-3">
                                    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-semibold ${v!.bg} ${v!.color}`}>
                                        {(() => { const V = v!.icon; return <V className="w-4 h-4" />; })()}
                                        {v!.label}
                                    </div>
                                    <span className="text-xs text-[#6B7089]">Risk Score: <span className="font-bold text-white">{result.risk_score}/100</span></span>
                                </div>
                                <div className="flex items-center gap-2 mb-2">
                                    <span className="font-mono text-lg">{result.indicator}</span>
                                    <button onClick={() => copyToClipboard(result.indicator)} className="p-1 rounded hover:bg-white/10 transition-colors">
                                        <Copy className="w-3.5 h-3.5 text-[#6B7089]" />
                                    </button>
                                </div>
                                <span className="text-xs text-[#6B7089] bg-white/5 px-2 py-0.5 rounded">{result.type}</span>
                            </div>

                            {/* Risk Gauge */}
                            <div className="w-24 h-24 relative">
                                <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                                    <circle cx="50" cy="50" r="40" fill="none" stroke="#1a1c3a" strokeWidth="8" />
                                    <circle cx="50" cy="50" r="40" fill="none" strokeWidth="8" strokeLinecap="round"
                                        stroke={result.risk_score > 70 ? '#FF6B6B' : result.risk_score > 40 ? '#FF8C42' : '#2DD4BF'}
                                        strokeDasharray={`${result.risk_score * 2.51} 251`} />
                                </svg>
                                <div className="absolute inset-0 flex items-center justify-center">
                                    <span className="text-xl font-bold">{result.risk_score}</span>
                                </div>
                            </div>
                        </div>

                        {/* Tags */}
                        {result.tags.length > 0 && (
                            <div className="flex flex-wrap gap-2 mt-4 pt-4 border-t border-white/5">
                                {result.tags.map(t => (
                                    <span key={t} className="text-xs px-2 py-0.5 rounded-full bg-[#7C5CFC]/10 text-[#7C5CFC] font-mono">{t}</span>
                                ))}
                            </div>
                        )}

                        {/* Quick Stats */}
                        <div className="grid grid-cols-4 gap-4 mt-4 pt-4 border-t border-white/5">
                            <div className="text-center">
                                <p className="text-xs text-[#6B7089]">First Seen</p>
                                <p className="text-sm font-medium mt-1">{result.first_seen}</p>
                            </div>
                            <div className="text-center">
                                <p className="text-xs text-[#6B7089]">Last Seen</p>
                                <p className="text-sm font-medium mt-1">{result.last_seen}</p>
                            </div>
                            <div className="text-center">
                                <p className="text-xs text-[#6B7089]">Total Reports</p>
                                <p className="text-sm font-medium mt-1">{result.total_reports.toLocaleString()}</p>
                            </div>
                            <div className="text-center">
                                <p className="text-xs text-[#6B7089]">Sources</p>
                                <p className="text-sm font-medium mt-1">{result.sources.length}</p>
                            </div>
                        </div>
                    </div>

                    {/* Tab Navigation */}
                    <div className="flex gap-1 bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-1">
                        {(['overview', 'timeline', 'related', 'actions'] as const).map(tab => (
                            <button key={tab} onClick={() => setActiveTab(tab)}
                                className={`flex-1 px-4 py-2.5 rounded-xl text-sm font-medium transition-colors ${activeTab === tab ? 'bg-[#7C5CFC] text-white' : 'text-[#6B7089] hover:text-white hover:bg-white/5'}`}>
                                {tab === 'overview' ? 'Overview' : tab === 'timeline' ? 'Activity Timeline' : tab === 'related' ? 'Related IOCs' : 'Recommended Actions'}
                            </button>
                        ))}
                    </div>

                    {/* Tab Content */}
                    {activeTab === 'overview' && (
                        <div className="grid grid-cols-2 gap-4">
                            {/* Analysis */}
                            <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                                <h3 className="text-base font-semibold mb-3" style={H}>Analysis</h3>
                                <p className="text-sm text-[#c0c2d0] leading-relaxed">{result.explanation}</p>
                            </div>

                            {/* Sources */}
                            <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                                <h3 className="text-base font-semibold mb-3" style={H}>Intelligence Sources</h3>
                                <div className="space-y-3">
                                    {result.sources.map(s => (
                                        <div key={s.name} className="flex items-center justify-between p-3 rounded-xl bg-white/[0.02] border border-white/5">
                                            <div className="flex items-center gap-3">
                                                <Server className="w-4 h-4 text-[#7C5CFC]" />
                                                <div>
                                                    <p className="text-sm font-medium">{s.name}</p>
                                                    {s.detections && <p className="text-xs text-[#6B7089]">{s.detections}</p>}
                                                </div>
                                            </div>
                                            {s.link && (
                                                <a href={s.link} target="_blank" rel="noopener noreferrer" className="p-1.5 rounded-lg hover:bg-white/10 transition-colors">
                                                    <ExternalLink className="w-3.5 h-3.5 text-[#6B7089]" />
                                                </a>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* MITRE ATT&CK */}
                            {result.mitre.length > 0 && (
                                <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                                    <h3 className="text-base font-semibold mb-3" style={H}>MITRE ATT&CK Mapping</h3>
                                    <div className="space-y-2">
                                        {result.mitre.map(m => (
                                            <div key={m.id} className="flex items-center gap-3 p-3 rounded-xl bg-white/[0.02] border border-white/5">
                                                <Crosshair className="w-4 h-4 text-red-400" />
                                                <div className="flex-1">
                                                    <div className="flex items-center gap-2">
                                                        <span className="text-xs font-mono text-[#7C5CFC] bg-[#7C5CFC]/10 px-1.5 py-0.5 rounded">{m.id}</span>
                                                        <span className="text-sm font-medium">{m.name}</span>
                                                    </div>
                                                    <p className="text-xs text-[#6B7089] mt-0.5">{m.tactic}</p>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Geo / Whois */}
                            <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                                {result.geo ? (
                                    <>
                                        <h3 className="text-base font-semibold mb-3" style={H}>Geolocation & Network</h3>
                                        <div className="space-y-3">
                                            <div className="flex items-center gap-3"><MapPin className="w-4 h-4 text-[#4DAFFF]" /><div><p className="text-xs text-[#6B7089]">Location</p><p className="text-sm">{result.geo.city}, {result.geo.country}</p></div></div>
                                            <div className="flex items-center gap-3"><Activity className="w-4 h-4 text-[#4DAFFF]" /><div><p className="text-xs text-[#6B7089]">ASN</p><p className="text-sm font-mono">{result.geo.asn}</p></div></div>
                                            <div className="flex items-center gap-3"><Server className="w-4 h-4 text-[#4DAFFF]" /><div><p className="text-xs text-[#6B7089]">Organization</p><p className="text-sm">{result.geo.org}</p></div></div>
                                        </div>
                                    </>
                                ) : result.whois ? (
                                    <>
                                        <h3 className="text-base font-semibold mb-3" style={H}>WHOIS Information</h3>
                                        <div className="space-y-3">
                                            <div className="flex items-center gap-3"><Globe className="w-4 h-4 text-[#4DAFFF]" /><div><p className="text-xs text-[#6B7089]">Registrar</p><p className="text-sm">{result.whois.registrar}</p></div></div>
                                            <div className="flex items-center gap-3"><Clock className="w-4 h-4 text-[#4DAFFF]" /><div><p className="text-xs text-[#6B7089]">Created</p><p className="text-sm">{result.whois.created}</p></div></div>
                                            <div className="flex items-center gap-3"><Clock className="w-4 h-4 text-[#4DAFFF]" /><div><p className="text-xs text-[#6B7089]">Expires</p><p className="text-sm">{result.whois.expires}</p></div></div>
                                            <div className="flex items-center gap-3"><Server className="w-4 h-4 text-[#4DAFFF]" /><div><p className="text-xs text-[#6B7089]">Nameservers</p>{result.whois.nameservers.map(ns => <p key={ns} className="text-xs font-mono text-[#8B8DA0]">{ns}</p>)}</div></div>
                                        </div>
                                    </>
                                ) : (
                                    <>
                                        <h3 className="text-base font-semibold mb-3" style={H}>Additional Info</h3>
                                        <p className="text-sm text-[#6B7089]">No geolocation or WHOIS data available for this indicator type.</p>
                                    </>
                                )}
                            </div>
                        </div>
                    )}

                    {activeTab === 'timeline' && (
                        <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                            <h3 className="text-base font-semibold mb-4" style={H}>Detection Timeline</h3>
                            {result.timeline.length > 0 ? (
                                <div className="relative">
                                    <div className="absolute left-[19px] top-2 bottom-2 w-px bg-white/10" />
                                    <div className="space-y-0">
                                        {result.timeline.map((ev, i) => (
                                            <div key={i} className="flex gap-4 py-3 group">
                                                <div className="relative z-10">
                                                    <div className={`w-[10px] h-[10px] rounded-full mt-1.5 ring-4 ring-[#111328] ${ev.severity === 'critical' ? 'bg-red-400' : ev.severity === 'high' ? 'bg-orange-400' : ev.severity === 'medium' ? 'bg-yellow-400' : 'bg-blue-400'
                                                        }`} />
                                                </div>
                                                <div className="flex-1 flex items-start justify-between p-3 rounded-xl group-hover:bg-white/[0.02] transition-colors">
                                                    <div>
                                                        <p className="text-sm font-medium">{ev.category}</p>
                                                        <p className="text-xs text-[#6B7089] mt-1">Reported by <span className="text-[#7C5CFC]">{ev.source}</span></p>
                                                    </div>
                                                    <div className="flex items-center gap-3">
                                                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${sevColors[ev.severity]}`}>{ev.severity}</span>
                                                        <span className="text-xs text-[#6B7089] font-mono whitespace-nowrap">{ev.date}</span>
                                                    </div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ) : (
                                <p className="text-sm text-[#6B7089] text-center py-8">No timeline events available.</p>
                            )}
                        </div>
                    )}

                    {activeTab === 'related' && (
                        <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                            <h3 className="text-base font-semibold mb-4" style={H}>Related Indicators of Compromise</h3>
                            {result.related.length > 0 ? (
                                <div className="space-y-2">
                                    {result.related.map((rel, i) => (
                                        <button key={i} onClick={() => lookupRelated(rel.indicator)}
                                            className="w-full flex items-center justify-between p-4 rounded-xl bg-white/[0.02] border border-white/5 hover:bg-white/[0.05] hover:border-[#7C5CFC]/20 transition-all text-left group">
                                            <div className="flex items-center gap-4">
                                                <Link2 className="w-4 h-4 text-[#6B7089] group-hover:text-[#7C5CFC] transition-colors" />
                                                <div>
                                                    <p className="text-sm font-mono font-medium group-hover:text-[#7C5CFC] transition-colors">{rel.indicator}</p>
                                                    <p className="text-xs text-[#6B7089] mt-0.5">{rel.relationship} • {rel.type}</p>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-3">
                                                <div className="flex items-center gap-2">
                                                    <div className="w-16 h-1.5 bg-[#1a1c3a] rounded-full overflow-hidden">
                                                        <div className="h-full rounded-full" style={{ width: `${rel.risk}%`, background: rel.risk > 70 ? '#FF6B6B' : rel.risk > 40 ? '#FF8C42' : '#2DD4BF' }} />
                                                    </div>
                                                    <span className="text-xs font-bold w-6">{rel.risk}</span>
                                                </div>
                                                <ChevronRight className="w-4 h-4 text-[#6B7089] group-hover:text-[#7C5CFC] transition-colors" />
                                            </div>
                                        </button>
                                    ))}
                                </div>
                            ) : (
                                <p className="text-sm text-[#6B7089] text-center py-8">No related IOCs found.</p>
                            )}
                        </div>
                    )}

                    {activeTab === 'actions' && (
                        <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                            <h3 className="text-base font-semibold mb-4" style={H}>Recommended Actions</h3>
                            {result.recommended_actions.length > 0 ? (
                                <div className="space-y-2">
                                    {result.recommended_actions.map((action, i) => (
                                        <div key={i} className="flex items-start gap-3 p-3 rounded-xl bg-white/[0.02] border border-white/5">
                                            <div className="w-6 h-6 rounded-lg bg-[#7C5CFC]/10 flex items-center justify-center shrink-0 mt-0.5">
                                                <span className="text-xs font-bold text-[#7C5CFC]">{i + 1}</span>
                                            </div>
                                            <p className="text-sm text-[#c0c2d0]">{action}</p>
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <p className="text-sm text-[#6B7089] text-center py-8">No recommended actions available.</p>
                            )}
                        </div>
                    )}
                </div>
            )}

            {!loading && searched && !result && (
                <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-12 text-center text-[#6B7089]">
                    No results found for this indicator.
                </div>
            )}
        </div>
    );
}
