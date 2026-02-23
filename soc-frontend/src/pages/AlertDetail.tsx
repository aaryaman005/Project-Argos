import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, AlertTriangle, Shield, Crosshair, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react';
import { useState } from 'react';
import { useAlerts } from '../hooks/useAlerts';
import api from '../services/api';

const H = { fontFamily: "'PT Serif', serif" };

export default function AlertDetail() {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { allAlerts } = useAlerts();
    const alert = allAlerts.find(a => a.id === id);
    const [showRaw, setShowRaw] = useState(false);
    const [showConfirm, setShowConfirm] = useState<string | null>(null);

    if (!alert) {
        return (
            <div className="p-6 flex flex-col items-center justify-center h-full text-[#6B7089]">
                <AlertTriangle className="w-12 h-12 mb-4 text-[#7C5CFC]" />
                <p className="text-lg">Alert {id} not found</p>
                <button onClick={() => navigate('/alerts')} className="mt-4 text-sm text-[#7C5CFC] hover:underline">← Back to Alerts</button>
            </div>
        );
    }

    const handleAction = async (action: string) => {
        setShowConfirm(null);
        try {
            await api.post('/audit', {
                actor: 'Operator',
                action,
                target: alert.target,
                outcome: `${action} executed on ${alert.id}`,
                incident_id: alert.id,
                alert_type: alert.type,
            });
        } catch { /* backend may be down */ }
    };

    return (
        <div className="p-6 space-y-6">
            {/* Back + Header */}
            <div className="flex items-center gap-4">
                <button onClick={() => navigate('/alerts')} className="w-9 h-9 rounded-xl bg-[#1a1c3a] border border-white/5 flex items-center justify-center text-[#6B7089] hover:text-white transition-colors">
                    <ArrowLeft className="w-4 h-4" />
                </button>
                <div className="flex-1">
                    <h2 className="text-xl font-bold" style={H}>Investigation — {alert.id}</h2>
                    <p className="text-sm text-[#6B7089] mt-1">{alert.type} • {alert.source} • {new Date(alert.timestamp).toLocaleString()}</p>
                </div>
                <span className={`text-sm px-3 py-1 rounded-full font-medium ${alert.severity === 'critical' ? 'bg-red-500/15 text-red-400' :
                    alert.severity === 'high' ? 'bg-orange-500/15 text-orange-400' :
                        alert.severity === 'medium' ? 'bg-yellow-500/15 text-yellow-400' : 'bg-blue-500/15 text-blue-400'
                    }`}>{alert.severity.toUpperCase()}</span>
            </div>

            <div className="grid grid-cols-[1fr_340px] gap-6">
                {/* Left: Details */}
                <div className="space-y-6">
                    {/* Metadata */}
                    <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                        <h3 className="text-base font-semibold mb-4" style={H}>Alert Metadata</h3>
                        <div className="grid grid-cols-2 gap-4 text-sm">
                            <div><span className="text-[#6B7089]">Target</span><p className="font-mono mt-1">{alert.target}</p></div>
                            <div><span className="text-[#6B7089]">Status</span><p className="mt-1 capitalize">{alert.status}</p></div>
                            <div><span className="text-[#6B7089]">IOC Confidence</span><p className="mt-1">{(alert.ioc_confidence * 100).toFixed(0)}%</p></div>
                            <div><span className="text-[#6B7089]">Asset Criticality</span><p className="mt-1">{(alert.asset_criticality * 100).toFixed(0)}%</p></div>
                        </div>
                        <div className="mt-4 pt-4 border-t border-white/5">
                            <span className="text-[#6B7089] text-sm">Description</span>
                            <p className="mt-1 text-sm">{alert.description}</p>
                        </div>
                    </div>

                    {/* MITRE ATT&CK */}
                    {alert.mitre_tactic && (
                        <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                            <h3 className="text-base font-semibold mb-4" style={H}>MITRE ATT&CK Mapping</h3>
                            <div className="flex items-center gap-3">
                                <Crosshair className="w-5 h-5 text-[#FF6B6B]" />
                                <div>
                                    <p className="text-sm font-medium">{alert.mitre_tactic}</p>
                                    <p className="text-xs text-[#6B7089]">{alert.mitre_technique}</p>
                                </div>
                                <a href={`https://attack.mitre.org/techniques/${alert.mitre_technique?.split(' - ')[0]?.replace('T', 'T')}`} target="_blank" rel="noreferrer"
                                    className="ml-auto text-[#7C5CFC] hover:text-[#9B82FC]"><ExternalLink className="w-4 h-4" /></a>
                            </div>
                        </div>
                    )}

                    {/* IOCs */}
                    {alert.iocs && alert.iocs.length > 0 && (
                        <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                            <h3 className="text-base font-semibold mb-4" style={H}>Indicators of Compromise</h3>
                            <div className="space-y-2">
                                {alert.iocs.map((ioc, i) => (
                                    <div key={i} className="flex items-center gap-3 px-3 py-2 bg-white/[0.02] rounded-lg">
                                        <span className="text-xs px-2 py-0.5 rounded-full bg-[#7C5CFC]/10 text-[#7C5CFC] font-mono uppercase">{ioc.type}</span>
                                        <span className="text-sm font-mono text-[#8B8DA0]">{ioc.value}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Raw Log */}
                    <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                        <button onClick={() => setShowRaw(!showRaw)} className="flex items-center gap-2 text-base font-semibold w-full" style={H}>
                            Raw Log {showRaw ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                        </button>
                        {showRaw && (
                            <pre className="mt-4 p-4 bg-black/30 rounded-xl text-xs text-green-400 font-mono overflow-x-auto whitespace-pre-wrap">
                                {alert.raw_log || 'No raw log available for this alert.'}
                            </pre>
                        )}
                    </div>
                </div>

                {/* Right: Actions + AI Analysis */}
                <div className="space-y-6">
                    {/* LLM Explanation */}
                    <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                        <h3 className="text-base font-semibold mb-4" style={H}>AI Analysis</h3>
                        <div className="text-sm text-[#c0c2d0] space-y-3 leading-relaxed">
                            <p>This <strong className="text-white">{alert.type}</strong> alert on <strong className="text-white">{alert.target}</strong> has a confidence score of <strong className="text-white">{(alert.ioc_confidence * 100).toFixed(0)}%</strong> and targets an asset with <strong className="text-white">{(alert.asset_criticality * 100).toFixed(0)}%</strong> criticality.</p>
                            <p>The combination of high confidence and asset criticality suggests this is a {alert.severity === 'critical' ? 'high-priority incident requiring immediate response' : 'notable event warranting investigation'}.</p>
                            {alert.mitre_tactic && <p>Mapped to <strong className="text-[#FF6B6B]">{alert.mitre_tactic}</strong> tactic — indicative of {alert.mitre_tactic === 'Impact' ? 'destructive intent' : alert.mitre_tactic === 'Exfiltration' ? 'data theft' : 'adversary persistence'}.</p>}
                        </div>
                    </div>

                    {/* Response Actions */}
                    <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                        <h3 className="text-base font-semibold mb-4" style={H}>Response Actions</h3>
                        <div className="space-y-2">
                            {['Mark False Positive', 'Escalate to Senior', 'Isolate Host', 'Block Source IP'].map(action => (
                                <div key={action}>
                                    {showConfirm === action ? (
                                        <div className="flex items-center gap-2 p-3 bg-red-500/5 border border-red-500/20 rounded-xl">
                                            <span className="text-sm flex-1">Confirm: {action}?</span>
                                            <button onClick={() => handleAction(action)} className="px-3 py-1 rounded-lg bg-[#7C5CFC] text-white text-xs">Yes</button>
                                            <button onClick={() => setShowConfirm(null)} className="px-3 py-1 rounded-lg bg-[#1a1c3a] text-white text-xs">No</button>
                                        </div>
                                    ) : (
                                        <button onClick={() => setShowConfirm(action)}
                                            className="w-full text-left px-4 py-3 rounded-xl bg-white/[0.02] hover:bg-white/[0.05] text-sm transition-colors border border-transparent hover:border-white/5">
                                            {action}
                                        </button>
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
