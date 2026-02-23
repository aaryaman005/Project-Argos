import { useState, useEffect, useCallback } from 'react';
import { Clock, User, Zap, Target, CheckCircle, RefreshCw, Loader2, Shield, Ban, Cpu } from 'lucide-react';
import api from '../services/api';

const H = { fontFamily: "'PT Serif', serif" };

interface AuditRecord {
    incident_id: string;
    timestamp: string;
    alert_type: string;
    priority_score: number;
    actions_taken: string[];
    status: string;
}

const actionIcons: Record<string, typeof Shield> = {
    block_ip: Ban,
    kill_process: Cpu,
    isolate_host: Shield,
};

const typeLabels: Record<string, string> = {
    privilege_escalation: 'Privilege Escalation',
    data_exfiltration: 'Data Exfiltration',
    ssh_brute_force: 'SSH Brute Force',
    ransomware: 'Ransomware',
    credential_stuffing: 'Credential Stuffing',
    phishing: 'Phishing',
};

export default function Audit() {
    const [records, setRecords] = useState<AuditRecord[]>([]);
    const [loading, setLoading] = useState(true);

    const fetchAudit = useCallback(async () => {
        setLoading(true);
        try {
            const res = await api.get('/audit');
            if (res.data.records) {
                setRecords(res.data.records.reverse()); // newest first
            }
        } catch {
            setRecords([]);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { fetchAudit(); }, [fetchAudit]);

    // Auto-refresh every 10s
    useEffect(() => {
        const interval = setInterval(fetchAudit, 10000);
        return () => clearInterval(interval);
    }, [fetchAudit]);

    return (
        <div className="p-6 space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-xl font-bold" style={H}>Audit Log</h2>
                    <p className="text-sm text-[#6B7089] mt-1">{records.length} recorded decisions • auto-refreshes every 10s</p>
                </div>
                <button onClick={fetchAudit} className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[#7C5CFC] text-white text-sm font-medium hover:bg-[#6B4EE0] transition-colors">
                    <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
                </button>
            </div>

            {loading && records.length === 0 ? (
                <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-12 flex flex-col items-center">
                    <Loader2 className="w-8 h-8 text-[#7C5CFC] animate-spin mb-3" />
                    <p className="text-sm text-[#6B7089]">Loading audit records from backend...</p>
                </div>
            ) : records.length === 0 ? (
                <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-12 text-center text-[#6B7089]">
                    No audit records yet. Run a simulation to generate data.
                </div>
            ) : (
                <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl overflow-hidden">
                    <table className="w-full text-sm">
                        <thead>
                            <tr className="text-[#6B7089] text-xs border-b border-white/5 bg-[#111328]/40">
                                <th className="text-left px-5 py-3 font-medium">Timestamp</th>
                                <th className="text-left px-5 py-3 font-medium">Incident ID</th>
                                <th className="text-left px-5 py-3 font-medium">Alert Type</th>
                                <th className="text-left px-5 py-3 font-medium">Priority</th>
                                <th className="text-left px-5 py-3 font-medium">Actions Taken</th>
                                <th className="text-left px-5 py-3 font-medium">Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {records.map((rec, i) => (
                                <tr key={`${rec.incident_id}-${i}`} className="border-b border-white/[0.03] hover:bg-white/[0.03] transition-colors">
                                    <td className="px-5 py-3.5 text-[#8B8DA0] text-xs">
                                        <div className="flex items-center gap-1.5">
                                            <Clock className="w-3 h-3" />
                                            {new Date(rec.timestamp).toLocaleString()}
                                        </div>
                                    </td>
                                    <td className="px-5 py-3.5 font-mono text-[#7C5CFC] text-xs">{rec.incident_id.split('-')[0]}...</td>
                                    <td className="px-5 py-3.5">{typeLabels[rec.alert_type] || rec.alert_type}</td>
                                    <td className="px-5 py-3.5">
                                        <span className={`text-xs px-2 py-0.5 rounded-full ${rec.priority_score > 80 ? 'bg-red-500/10 text-red-400' :
                                                rec.priority_score > 40 ? 'bg-orange-500/10 text-orange-400' :
                                                    rec.priority_score > 0 ? 'bg-yellow-500/10 text-yellow-400' : 'bg-gray-500/10 text-gray-400'
                                            }`}>{rec.priority_score.toFixed(1)}</span>
                                    </td>
                                    <td className="px-5 py-3.5">
                                        <div className="flex gap-1.5">
                                            {rec.actions_taken.map((action, j) => (
                                                <span key={j} className="text-xs px-2 py-0.5 rounded-full bg-[#7C5CFC]/10 text-[#7C5CFC]">
                                                    {action.replace('_', ' ')}
                                                </span>
                                            ))}
                                        </div>
                                    </td>
                                    <td className="px-5 py-3.5">
                                        <span className={`flex items-center gap-1.5 text-xs ${rec.status === 'resolved' ? 'text-green-400' : 'text-yellow-400'}`}>
                                            <CheckCircle className="w-3 h-3" /> {rec.status}
                                        </span>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}
