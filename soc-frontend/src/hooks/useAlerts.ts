import { useState, useEffect, useCallback } from 'react';
import api from '../services/api';
import type { Alert, Severity, AlertStatus } from '../types/alert';

// Mock alerts for development — replaced by real API when backend is connected
const MOCK_ALERTS: Alert[] = [
    { id: 'ARG-7721', timestamp: '2026-02-23T20:04:15Z', type: 'Ransomware', source: 'EDR', severity: 'critical', status: 'new', ioc_confidence: 0.95, asset_criticality: 0.9, description: 'File encryption burst detected on prod-db-01', target: 'prod-db-01', mitre_tactic: 'Impact', mitre_technique: 'T1486 - Data Encrypted for Impact', raw_log: '[2026-02-23T20:04:15Z] EDR Alert: Suspicious process crypt.exe spawned by explorer.exe. Multiple file rename operations detected in C:\\Data\\', iocs: [{ type: 'process', value: 'crypt.exe' }, { type: 'hash', value: 'a1b2c3d4e5f6...' }] },
    { id: 'ARG-7718', timestamp: '2026-02-23T19:58:32Z', type: 'Credential Stuffing', source: 'SIEM', severity: 'high', status: 'investigating', ioc_confidence: 0.82, asset_criticality: 0.7, description: 'Multiple failed logins from distributed IPs on auth-srv-03', target: 'auth-srv-03', mitre_tactic: 'Credential Access', mitre_technique: 'T1110 - Brute Force', iocs: [{ type: 'ip', value: '185.220.101.34' }, { type: 'ip', value: '91.132.147.12' }] },
    { id: 'ARG-7715', timestamp: '2026-02-23T19:45:10Z', type: 'Brute Force', source: 'Firewall', severity: 'medium', status: 'investigating', ioc_confidence: 0.68, asset_criticality: 0.5, description: 'SSH brute force attempts on jump-box-ext', target: 'jump-box-ext', mitre_tactic: 'Initial Access', mitre_technique: 'T1078 - Valid Accounts' },
    { id: 'ARG-7712', timestamp: '2026-02-23T19:30:44Z', type: 'DDoS', source: 'Cloud', severity: 'high', status: 'contained', ioc_confidence: 0.91, asset_criticality: 0.8, description: 'Volumetric DDoS attack on cdn-edge-01', target: 'cdn-edge-01', mitre_tactic: 'Impact', mitre_technique: 'T1498 - Network Denial of Service' },
    { id: 'ARG-7708', timestamp: '2026-02-23T19:15:22Z', type: 'Phishing', source: 'Email', severity: 'medium', status: 'new', ioc_confidence: 0.75, asset_criticality: 0.4, description: 'Suspicious email with macro-enabled attachment', target: 'user-ws-042', mitre_tactic: 'Initial Access', mitre_technique: 'T1566 - Phishing' },
    { id: 'ARG-7703', timestamp: '2026-02-23T18:50:11Z', type: 'Exfiltration', source: 'IDS', severity: 'critical', status: 'new', ioc_confidence: 0.88, asset_criticality: 0.95, description: 'Unusual outbound data transfer from finance-db', target: 'finance-db', mitre_tactic: 'Exfiltration', mitre_technique: 'T1041 - Exfiltration Over C2 Channel', iocs: [{ type: 'domain', value: 'c2.badactor.xyz' }, { type: 'ip', value: '45.33.32.156' }] },
    { id: 'ARG-7699', timestamp: '2026-02-23T18:30:05Z', type: 'Insider Threat', source: 'SIEM', severity: 'low', status: 'closed', ioc_confidence: 0.55, asset_criticality: 0.3, description: 'Off-hours access to restricted share by intern account', target: 'file-srv-02', mitre_tactic: 'Collection', mitre_technique: 'T1039 - Data from Network Shared Drive' },
    { id: 'ARG-7694', timestamp: '2026-02-23T18:10:33Z', type: 'Malware', source: 'EDR', severity: 'high', status: 'contained', ioc_confidence: 0.92, asset_criticality: 0.6, description: 'Cobalt Strike beacon detected on dev-ws-017', target: 'dev-ws-017', mitre_tactic: 'Command and Control', mitre_technique: 'T1071 - Application Layer Protocol', iocs: [{ type: 'hash', value: 'd4e5f6a7b8c9...' }, { type: 'domain', value: 'beacon.c2server.net' }] },
];

export function useAlerts() {
    const [alerts, setAlerts] = useState<Alert[]>([]);
    const [loading, setLoading] = useState(true);
    const [filters, setFilters] = useState<{ severity?: Severity; status?: AlertStatus; source?: string }>({});

    const fetchAlerts = useCallback(async () => {
        setLoading(true);
        try {
            const res = await api.get('/incidents');
            if (res.data.incidents) {
                setAlerts(res.data.incidents);
            }
        } catch (err) {
            console.warn("Backend unreachable, using mock data");
            setAlerts(MOCK_ALERTS);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { fetchAlerts(); }, [fetchAlerts]);

    const filtered = alerts.filter(a => {
        if (filters.severity && a.severity !== filters.severity) return false;
        if (filters.status && a.status !== filters.status) return false;
        if (filters.source && a.source !== filters.source) return false;
        return true;
    });

    return { alerts: filtered, allAlerts: alerts, loading, filters, setFilters, refetch: fetchAlerts };
}
