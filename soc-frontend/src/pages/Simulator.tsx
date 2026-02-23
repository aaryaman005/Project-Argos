import { useState, useRef, useEffect } from 'react';
import { Play, Square, Zap, Shield, Server, AlertTriangle, Clock, Activity, ChevronRight, Loader2, RotateCcw, Gauge } from 'lucide-react';
import { useNotifications } from '../context/NotificationContext';

const H = { fontFamily: "'PT Serif', serif" };
const API = 'http://localhost:8000';

interface SimAction {
    id: string; type: string; target: string;
    security_gain: number; operational_cost: number; business_risk: number; status: string;
}
interface SimAlert {
    id: string; type: string; source: string; severity: string;
    description: string; ioc_confidence: number; asset_criticality: number; timestamp: string;
}
interface SimIncident {
    incident_id: string;
    alert: SimAlert;
    priority_score: number;
    blast_radius: number;
    recommended_actions: SimAction[];
    final_actions: SimAction[];
    status: string;
    processing_time_ms: number;
}

interface TimelineEntry {
    type: 'alert' | 'triage' | 'response' | 'audit';
    title: string;
    detail: string;
    severity?: string;
    timestamp: Date;
    incident?: SimIncident;
}

const sevColor: Record<string, string> = {
    CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/20',
    HIGH: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
    MEDIUM: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
    LOW: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
};

export default function Simulator() {
    const { addNotification } = useNotifications();
    const [running, setRunning] = useState(false);
    const [speed, setSpeed] = useState(3000); // ms between alerts
    const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
    const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, medium: 0, low: 0, avgTime: 0, totalActions: 0 });
    const [selectedIncident, setSelectedIncident] = useState<SimIncident | null>(null);
    const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
    const timelineEndRef = useRef<HTMLDivElement>(null);
    const processingTimesRef = useRef<number[]>([]);

    useEffect(() => {
        timelineEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [timeline]);

    const simulateOne = async () => {
        try {
            const res = await fetch(`${API}/simulate-one`, { method: 'POST' });
            const data: SimIncident = await res.json();

            // 1. Alert notification
            addNotification({
                type: 'alert',
                title: `🚨 ${data.alert.severity} Alert: ${data.alert.type.replace(/_/g, ' ')}`,
                message: data.alert.description,
                severity: data.alert.severity,
                incidentId: data.incident_id,
            });

            // Timeline: alert arrived
            setTimeline(prev => [...prev, {
                type: 'alert',
                title: `Alert: ${data.alert.type.replace(/_/g, ' ')}`,
                detail: `${data.alert.description} | Source: ${data.alert.source}`,
                severity: data.alert.severity,
                timestamp: new Date(),
            }]);

            // Small delay for visual effect
            await new Promise(r => setTimeout(r, 400));

            // Timeline: triage + priority
            setTimeline(prev => [...prev, {
                type: 'triage',
                title: `Triaged → Priority: ${data.priority_score}`,
                detail: `Blast radius: ${data.blast_radius} | Confidence: ${(data.alert.ioc_confidence * 100).toFixed(0)}% | Criticality: ${(data.alert.asset_criticality * 100).toFixed(0)}%`,
                severity: data.alert.severity,
                timestamp: new Date(),
            }]);

            await new Promise(r => setTimeout(r, 400));

            // Timeline: response actions
            const actionNames = data.final_actions.map(a => a.type.replace(/_/g, ' ')).join(', ');
            setTimeline(prev => [...prev, {
                type: 'response',
                title: `Response: ${actionNames}`,
                detail: `${data.final_actions.length} actions executed in ${data.processing_time_ms}ms on ${data.alert.source}`,
                severity: data.alert.severity,
                timestamp: new Date(),
                incident: data,
            }]);

            // 2. Response notification
            addNotification({
                type: 'response',
                title: `⚡ Auto-Response: ${actionNames}`,
                message: `Incident ${data.incident_id.slice(0, 8)} resolved — ${data.final_actions.length} actions on ${data.alert.source} in ${data.processing_time_ms}ms`,
                incidentId: data.incident_id,
            });

            await new Promise(r => setTimeout(r, 300));

            // Timeline: audit logged
            setTimeline(prev => [...prev, {
                type: 'audit',
                title: 'Audit logged',
                detail: `Incident ${data.incident_id.slice(0, 8)}… recorded to audit trail`,
                timestamp: new Date(),
            }]);

            // Update stats
            processingTimesRef.current.push(data.processing_time_ms);
            const avgTime = processingTimesRef.current.reduce((a, b) => a + b, 0) / processingTimesRef.current.length;
            setStats(prev => ({
                total: prev.total + 1,
                critical: prev.critical + (data.alert.severity === 'CRITICAL' ? 1 : 0),
                high: prev.high + (data.alert.severity === 'HIGH' ? 1 : 0),
                medium: prev.medium + (data.alert.severity === 'MEDIUM' ? 1 : 0),
                low: prev.low + (data.alert.severity === 'LOW' ? 1 : 0),
                avgTime: Math.round(avgTime),
                totalActions: prev.totalActions + data.final_actions.length,
            }));

        } catch (err) {
            addNotification({
                type: 'error',
                title: 'Simulation Error',
                message: 'Failed to connect to backend. Is the API running on port 8000?',
            });
        }
    };

    const startSimulation = () => {
        setRunning(true);
        simulateOne(); // fire first immediately
        intervalRef.current = setInterval(simulateOne, speed);
    };

    const stopSimulation = () => {
        setRunning(false);
        if (intervalRef.current) {
            clearInterval(intervalRef.current);
            intervalRef.current = null;
        }
    };

    const resetSimulation = () => {
        stopSimulation();
        setTimeline([]);
        setSelectedIncident(null);
        setStats({ total: 0, critical: 0, high: 0, medium: 0, low: 0, avgTime: 0, totalActions: 0 });
        processingTimesRef.current = [];
    };

    useEffect(() => {
        return () => {
            if (intervalRef.current) clearInterval(intervalRef.current);
        };
    }, []);

    // Update interval when speed changes
    useEffect(() => {
        if (running && intervalRef.current) {
            clearInterval(intervalRef.current);
            intervalRef.current = setInterval(simulateOne, speed);
        }
    }, [speed]);

    const entryIcon = (type: string) => {
        switch (type) {
            case 'alert': return <AlertTriangle className="w-4 h-4 text-red-400" />;
            case 'triage': return <Gauge className="w-4 h-4 text-yellow-400" />;
            case 'response': return <Zap className="w-4 h-4 text-green-400" />;
            case 'audit': return <Shield className="w-4 h-4 text-[#7C5CFC]" />;
            default: return <Activity className="w-4 h-4 text-[#6B7089]" />;
        }
    };

    const entryColor = (type: string) => {
        switch (type) {
            case 'alert': return 'border-red-500/30';
            case 'triage': return 'border-yellow-500/30';
            case 'response': return 'border-green-500/30';
            case 'audit': return 'border-[#7C5CFC]/30';
            default: return 'border-white/10';
        }
    };

    return (
        <div className="p-6 space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-xl font-bold" style={H}>Threat Simulator</h2>
                    <p className="text-sm text-[#6B7089] mt-1">
                        Generate live alerts through the SOC engine and watch autonomous response in real-time
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    {/* Speed Control */}
                    <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-[#111328]/60 border border-white/5">
                        <Clock className="w-4 h-4 text-[#6B7089]" />
                        <select value={speed} onChange={e => setSpeed(Number(e.target.value))}
                            className="bg-transparent text-sm text-white outline-none cursor-pointer">
                            <option value={1000} className="bg-[#111328]">1s interval</option>
                            <option value={2000} className="bg-[#111328]">2s interval</option>
                            <option value={3000} className="bg-[#111328]">3s interval</option>
                            <option value={5000} className="bg-[#111328]">5s interval</option>
                            <option value={8000} className="bg-[#111328]">8s interval</option>
                        </select>
                    </div>

                    <button onClick={resetSimulation}
                        className="px-4 py-2.5 rounded-xl bg-[#111328]/60 border border-white/5 text-sm text-[#6B7089] hover:text-white transition-colors flex items-center gap-2">
                        <RotateCcw className="w-4 h-4" /> Reset
                    </button>

                    {!running ? (
                        <button onClick={startSimulation}
                            className="px-6 py-2.5 rounded-xl bg-[#7C5CFC] text-white text-sm font-medium hover:bg-[#6B4EE0] transition-colors flex items-center gap-2 shadow-lg shadow-[#7C5CFC]/25">
                            <Play className="w-4 h-4" /> Start Simulation
                        </button>
                    ) : (
                        <button onClick={stopSimulation}
                            className="px-6 py-2.5 rounded-xl bg-red-500/20 text-red-400 border border-red-500/30 text-sm font-medium hover:bg-red-500/30 transition-colors flex items-center gap-2">
                            <Square className="w-4 h-4" /> Stop
                        </button>
                    )}
                </div>
            </div>

            {/* Live Stats */}
            <div className="grid grid-cols-6 gap-3">
                {[
                    { label: 'Total Alerts', value: stats.total, color: 'text-white', icon: AlertTriangle },
                    { label: 'Critical', value: stats.critical, color: 'text-red-400', icon: AlertTriangle },
                    { label: 'High', value: stats.high, color: 'text-orange-400', icon: AlertTriangle },
                    { label: 'Medium', value: stats.medium, color: 'text-yellow-400', icon: Shield },
                    { label: 'Avg MTTR', value: `${stats.avgTime}ms`, color: 'text-[#7C5CFC]', icon: Clock },
                    { label: 'Actions Taken', value: stats.totalActions, color: 'text-green-400', icon: Zap },
                ].map(s => (
                    <div key={s.label} className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-4">
                        <div className="flex items-center gap-2 mb-2">
                            <s.icon className={`w-4 h-4 ${s.color}`} />
                            <span className="text-xs text-[#6B7089]">{s.label}</span>
                        </div>
                        <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
                    </div>
                ))}
            </div>

            {/* Main Content — Timeline + Detail */}
            <div className="grid grid-cols-5 gap-4" style={{ height: 'calc(100vh - 340px)' }}>
                {/* Timeline Feed */}
                <div className="col-span-3 bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-5 flex flex-col">
                    <div className="flex items-center justify-between mb-4">
                        <h3 className="text-base font-semibold" style={H}>Live Event Feed</h3>
                        {running && (
                            <div className="flex items-center gap-2">
                                <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                                <span className="text-xs text-green-400">LIVE</span>
                            </div>
                        )}
                    </div>

                    <div className="flex-1 overflow-y-auto space-y-2 pr-1" style={{ scrollbarWidth: 'thin' }}>
                        {timeline.length === 0 && (
                            <div className="flex flex-col items-center justify-center h-full text-[#6B7089]">
                                <Server className="w-10 h-10 mb-3 opacity-30" />
                                <p className="text-sm">Press <strong>Start Simulation</strong> to begin generating alerts</p>
                                <p className="text-xs mt-1 opacity-50">The SOC engine will process each alert in real-time</p>
                            </div>
                        )}

                        {timeline.map((entry, i) => (
                            <div key={i}
                                onClick={() => entry.incident && setSelectedIncident(entry.incident)}
                                className={`flex items-start gap-3 p-3 rounded-xl border ${entryColor(entry.type)} bg-white/[0.01] 
                                    ${entry.incident ? 'cursor-pointer hover:bg-white/[0.04]' : ''} transition-all
                                    ${i === timeline.length - 1 ? 'animate-slideIn' : ''}`}>
                                <div className="mt-0.5">{entryIcon(entry.type)}</div>
                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2">
                                        <span className="text-sm font-medium">{entry.title}</span>
                                        {entry.severity && (
                                            <span className={`text-[10px] px-1.5 py-0.5 rounded font-semibold ${sevColor[entry.severity] || ''}`}>
                                                {entry.severity}
                                            </span>
                                        )}
                                    </div>
                                    <p className="text-xs text-[#6B7089] mt-0.5 truncate">{entry.detail}</p>
                                </div>
                                <span className="text-[10px] text-[#6B7089] font-mono shrink-0 mt-1">
                                    {entry.timestamp.toLocaleTimeString()}
                                </span>
                                {entry.incident && <ChevronRight className="w-4 h-4 text-[#6B7089] shrink-0 mt-1" />}
                            </div>
                        ))}
                        <div ref={timelineEndRef} />
                    </div>
                </div>

                {/* Incident Detail Panel */}
                <div className="col-span-2 bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-5 overflow-y-auto">
                    {selectedIncident ? (
                        <div className="space-y-5">
                            <div>
                                <h3 className="text-base font-semibold mb-1" style={H}>Incident Detail</h3>
                                <p className="text-xs text-[#6B7089] font-mono">{selectedIncident.incident_id}</p>
                            </div>

                            {/* Alert Info */}
                            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5 space-y-3">
                                <div className="flex items-center justify-between">
                                    <span className="text-xs text-[#6B7089]">Alert Type</span>
                                    <span className="text-sm font-medium">{selectedIncident.alert.type.replace(/_/g, ' ')}</span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-xs text-[#6B7089]">Severity</span>
                                    <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${sevColor[selectedIncident.alert.severity] || ''}`}>
                                        {selectedIncident.alert.severity}
                                    </span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-xs text-[#6B7089]">Source</span>
                                    <span className="text-sm font-mono">{selectedIncident.alert.source}</span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-xs text-[#6B7089]">IOC Confidence</span>
                                    <div className="flex items-center gap-2">
                                        <div className="w-16 h-1.5 bg-[#1a1c3a] rounded-full overflow-hidden">
                                            <div className="h-full rounded-full bg-[#7C5CFC]" style={{ width: `${selectedIncident.alert.ioc_confidence * 100}%` }} />
                                        </div>
                                        <span className="text-xs font-bold">{(selectedIncident.alert.ioc_confidence * 100).toFixed(0)}%</span>
                                    </div>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-xs text-[#6B7089]">Asset Criticality</span>
                                    <div className="flex items-center gap-2">
                                        <div className="w-16 h-1.5 bg-[#1a1c3a] rounded-full overflow-hidden">
                                            <div className="h-full rounded-full bg-orange-400" style={{ width: `${selectedIncident.alert.asset_criticality * 100}%` }} />
                                        </div>
                                        <span className="text-xs font-bold">{(selectedIncident.alert.asset_criticality * 100).toFixed(0)}%</span>
                                    </div>
                                </div>
                                <p className="text-xs text-[#8B8DA0] border-t border-white/5 pt-2">{selectedIncident.alert.description}</p>
                            </div>

                            {/* Analysis */}
                            <div className="grid grid-cols-3 gap-3">
                                <div className="p-3 rounded-xl bg-white/[0.02] border border-white/5 text-center">
                                    <p className="text-xs text-[#6B7089] mb-1">Priority</p>
                                    <p className="text-lg font-bold text-[#7C5CFC]">{selectedIncident.priority_score}</p>
                                </div>
                                <div className="p-3 rounded-xl bg-white/[0.02] border border-white/5 text-center">
                                    <p className="text-xs text-[#6B7089] mb-1">Blast Radius</p>
                                    <p className="text-lg font-bold text-orange-400">{selectedIncident.blast_radius}</p>
                                </div>
                                <div className="p-3 rounded-xl bg-white/[0.02] border border-white/5 text-center">
                                    <p className="text-xs text-[#6B7089] mb-1">MTTR</p>
                                    <p className="text-lg font-bold text-green-400">{selectedIncident.processing_time_ms}ms</p>
                                </div>
                            </div>

                            {/* Pipeline Steps */}
                            <div>
                                <h4 className="text-sm font-semibold mb-3" style={H}>SOC Pipeline</h4>
                                <div className="space-y-2">
                                    {[
                                        { step: 'Ingestion', desc: 'Alert received from SIEM/EDR stream', color: 'bg-blue-400' },
                                        { step: 'Triage', desc: `Severity classified as ${selectedIncident.alert.severity}`, color: 'bg-yellow-400' },
                                        { step: 'Priority Queue', desc: `Score: ${selectedIncident.priority_score} (max-heap)`, color: 'bg-orange-400' },
                                        { step: 'Blast Radius', desc: `Graph analysis: ${selectedIncident.blast_radius} impact`, color: 'bg-red-400' },
                                        { step: 'Optimization', desc: `${selectedIncident.final_actions.length} optimal actions selected (greedy)`, color: 'bg-[#7C5CFC]' },
                                        { step: 'Execution', desc: `Actions executed on ${selectedIncident.alert.source}`, color: 'bg-green-400' },
                                        { step: 'Audit', desc: 'Full decision trail logged', color: 'bg-[#7C5CFC]' },
                                    ].map((s, i) => (
                                        <div key={i} className="flex items-center gap-3 p-2.5 rounded-lg bg-white/[0.01]">
                                            <div className={`w-2 h-2 rounded-full ${s.color} shrink-0`} />
                                            <div className="flex-1">
                                                <span className="text-xs font-semibold">{s.step}</span>
                                                <p className="text-[11px] text-[#6B7089]">{s.desc}</p>
                                            </div>
                                            <span className="text-[10px] text-green-400">✓</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* Actions */}
                            <div>
                                <h4 className="text-sm font-semibold mb-3" style={H}>Actions Executed</h4>
                                <div className="space-y-2">
                                    {selectedIncident.final_actions.map((a, i) => (
                                        <div key={i} className="p-3 rounded-xl bg-white/[0.02] border border-green-500/10">
                                            <div className="flex items-center justify-between mb-2">
                                                <div className="flex items-center gap-2">
                                                    <Zap className="w-3.5 h-3.5 text-green-400" />
                                                    <span className="text-sm font-medium">{a.type.replace(/_/g, ' ')}</span>
                                                </div>
                                                <span className="text-xs text-green-400 bg-green-500/10 px-2 py-0.5 rounded-full">executed</span>
                                            </div>
                                            <div className="grid grid-cols-3 gap-2 text-xs">
                                                <div><span className="text-[#6B7089]">Target:</span> <span className="font-mono">{a.target}</span></div>
                                                <div><span className="text-[#6B7089]">Gain:</span> <span className="text-green-400">{a.security_gain}</span></div>
                                                <div><span className="text-[#6B7089]">Cost:</span> <span className="text-orange-400">{a.operational_cost}</span></div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="flex flex-col items-center justify-center h-full text-[#6B7089]">
                            <Activity className="w-10 h-10 mb-3 opacity-30" />
                            <p className="text-sm">Click a <strong>Response</strong> event to view incident details</p>
                            <p className="text-xs mt-1 opacity-50">Full pipeline breakdown with actions taken</p>
                        </div>
                    )}
                </div>
            </div>

            {/* CSS for slide-in animation */}
            <style>{`
                @keyframes slideIn {
                    from { opacity: 0; transform: translateY(8px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                .animate-slideIn { animation: slideIn 0.3s ease-out; }
            `}</style>
        </div>
    );
}
