import { useState } from 'react';
import { Play, Pause, CheckCircle, AlertTriangle, Shield, Ban, UserX, Server, Loader2 } from 'lucide-react';
import type { Playbook } from '../types/alert';
import api from '../services/api';

const H = { fontFamily: "'PT Serif', serif" };

const initialPlaybooks: Playbook[] = [
    { id: 'pb-001', name: 'Block Malicious IP', description: 'Add source IP to firewall deny list and update IDS rules. Blocks all inbound/outbound traffic from the specified IP.', actions: ['Update firewall rules', 'Push IDS signature', 'Notify SOC team', 'Log to audit trail'], trigger_severity: 'high', dry_run: true, status: 'ready' },
    { id: 'pb-002', name: 'Disable Compromised User', description: 'Disable user account across AD and all SSO-integrated applications. Revoke active sessions and tokens.', actions: ['Disable AD account', 'Revoke OAuth tokens', 'Kill active sessions', 'Alert identity team'], trigger_severity: 'critical', dry_run: true, status: 'ready' },
    { id: 'pb-003', name: 'Quarantine Host', description: 'Isolate the host from the network while maintaining management access for forensic analysis.', actions: ['Network isolation via EDR', 'Capture memory snapshot', 'Preserve disk image', 'Assign to IR team'], trigger_severity: 'critical', dry_run: true, status: 'ready' },
    { id: 'pb-004', name: 'Enrich & Escalate', description: 'Automatically enrich all IOCs via threat intel feeds and escalate to senior analyst with full context.', actions: ['IOC enrichment via TI feeds', 'Generate incident summary', 'Assign to senior analyst', 'Set SLA timer'], trigger_severity: 'medium', dry_run: false, status: 'ready' },
];

const pbIcons: Record<string, typeof Shield> = { 'pb-001': Ban, 'pb-002': UserX, 'pb-003': Server, 'pb-004': Shield };

export default function Playbooks() {
    const [playbooks, setPlaybooks] = useState(initialPlaybooks);
    const [runningId, setRunningId] = useState<string | null>(null);
    const [showApproval, setShowApproval] = useState<string | null>(null);

    const toggleDryRun = (id: string) => {
        setPlaybooks(pbs => pbs.map(pb => pb.id === id ? { ...pb, dry_run: !pb.dry_run } : pb));
    };

    const executePlaybook = async (id: string) => {
        const pb = playbooks.find(p => p.id === id);
        if (!pb) return;

        if (!pb.dry_run && showApproval !== id) {
            setShowApproval(id);
            return;
        }

        setShowApproval(null);
        setRunningId(id);
        setPlaybooks(pbs => pbs.map(p => p.id === id ? { ...p, status: 'running' } : p));

        // Log playbook execution to audit
        try {
            await api.post('/audit', {
                actor: `Playbook: ${pb.name}`,
                action: pb.dry_run ? 'Playbook Dry Run' : 'Playbook Executed',
                target: pb.name,
                outcome: `${pb.dry_run ? 'Dry run' : 'Executed'}: ${pb.actions.join(', ')}`,
                incident_id: pb.id,
                alert_type: 'playbook_execution',
            });
        } catch { /* backend may be down */ }

        // Simulate execution
        setTimeout(() => {
            setPlaybooks(pbs => pbs.map(p => p.id === id ? { ...p, status: 'completed', last_run: new Date().toISOString() } : p));
            setRunningId(null);
        }, 2500);
    };

    return (
        <div className="p-6 space-y-6">
            <div>
                <h2 className="text-xl font-bold" style={H}>Response Playbooks</h2>
                <p className="text-sm text-[#6B7089] mt-1">Orchestrate automated and semi-automated response actions</p>
            </div>

            <div className="grid grid-cols-2 gap-6">
                {playbooks.map(pb => {
                    const PbIcon = pbIcons[pb.id] || Shield;
                    return (
                        <div key={pb.id} className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6 flex flex-col">
                            <div className="flex items-start gap-4 mb-4">
                                <div className="w-11 h-11 rounded-xl bg-[#7C5CFC]/15 flex items-center justify-center shrink-0">
                                    <PbIcon className="w-5 h-5 text-[#7C5CFC]" />
                                </div>
                                <div className="flex-1 min-w-0">
                                    <h3 className="text-base font-semibold" style={H}>{pb.name}</h3>
                                    <p className="text-xs text-[#6B7089] mt-1">{pb.description}</p>
                                </div>
                                <span className={`text-xs px-2 py-0.5 rounded-full shrink-0 ${pb.status === 'completed' ? 'bg-green-500/10 text-green-400' :
                                    pb.status === 'running' ? 'bg-cyan-500/10 text-cyan-400' :
                                        pb.status === 'failed' ? 'bg-red-500/10 text-red-400' : 'bg-gray-500/10 text-gray-400'
                                    }`}>{pb.status}</span>
                            </div>

                            {/* Actions list */}
                            <div className="space-y-1.5 mb-4 flex-1">
                                {pb.actions.map((action, i) => (
                                    <div key={i} className="flex items-center gap-2 text-xs text-[#8B8DA0]">
                                        <span className="w-5 h-5 rounded-full bg-white/5 flex items-center justify-center text-[10px] shrink-0">{i + 1}</span>
                                        {action}
                                    </div>
                                ))}
                            </div>

                            {/* Trigger severity */}
                            <div className="flex items-center justify-between text-xs text-[#6B7089] mb-4 pt-3 border-t border-white/5">
                                <span>Auto-trigger: <strong className={
                                    pb.trigger_severity === 'critical' ? 'text-red-400' : pb.trigger_severity === 'high' ? 'text-orange-400' : 'text-yellow-400'
                                }>{pb.trigger_severity}</strong></span>
                                {pb.last_run && <span>Last: {new Date(pb.last_run).toLocaleTimeString()}</span>}
                            </div>

                            {/* Controls */}
                            <div className="flex items-center gap-3">
                                <label className="flex items-center gap-2 cursor-pointer">
                                    <div className={`w-9 h-5 rounded-full relative transition-colors ${pb.dry_run ? 'bg-yellow-500/30' : 'bg-[#7C5CFC]/30'}`} onClick={() => toggleDryRun(pb.id)}>
                                        <div className={`absolute top-0.5 w-4 h-4 rounded-full transition-all ${pb.dry_run ? 'left-0.5 bg-yellow-400' : 'left-[18px] bg-[#7C5CFC]'}`} />
                                    </div>
                                    <span className="text-xs text-[#8B8DA0]">{pb.dry_run ? 'Dry Run' : 'Execute'}</span>
                                </label>

                                <div className="flex-1" />

                                {showApproval === pb.id ? (
                                    <div className="flex items-center gap-2">
                                        <span className="text-xs text-orange-400">Approve execution?</span>
                                        <button onClick={() => executePlaybook(pb.id)} className="px-3 py-1.5 rounded-lg bg-[#7C5CFC] text-white text-xs">Approve</button>
                                        <button onClick={() => setShowApproval(null)} className="px-3 py-1.5 rounded-lg bg-[#1a1c3a] text-white text-xs">Cancel</button>
                                    </div>
                                ) : (
                                    <button onClick={() => executePlaybook(pb.id)} disabled={pb.status === 'running'}
                                        className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[#7C5CFC] text-white text-sm font-medium hover:bg-[#6B4EE0] disabled:opacity-50 transition-colors">
                                        {pb.status === 'running' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                                        {pb.dry_run ? 'Dry Run' : 'Execute'}
                                    </button>
                                )}
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
