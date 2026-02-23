import { useNavigate } from 'react-router-dom';
import { Filter, RefreshCw } from 'lucide-react';
import { useAlerts } from '../hooks/useAlerts';
import type { Severity, AlertStatus } from '../types/alert';

const severityColor: Record<Severity, string> = {
    critical: 'bg-red-500/10 text-red-400 border-red-500/20',
    high: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    medium: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    low: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
};

const statusColor: Record<AlertStatus, string> = {
    new: 'bg-purple-500/10 text-purple-400',
    investigating: 'bg-cyan-500/10 text-cyan-400',
    contained: 'bg-green-500/10 text-green-400',
    closed: 'bg-gray-500/10 text-gray-400',
};

const H = { fontFamily: "'PT Serif', serif" };

export default function Alerts() {
    const { alerts, loading, filters, setFilters, refetch } = useAlerts();
    const navigate = useNavigate();

    return (
        <div className="p-6 space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-xl font-bold" style={H}>Alert Queue</h2>
                    <p className="text-sm text-[#6B7089] mt-1">{alerts.length} alerts matching current filters</p>
                </div>
                <button onClick={refetch} className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[#7C5CFC] text-white text-sm font-medium hover:bg-[#6B4EE0] transition-colors">
                    <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
                </button>
            </div>

            {/* Filters */}
            <div className="flex gap-3 items-center bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-xl px-4 py-3">
                <Filter className="w-4 h-4 text-[#6B7089]" />
                <select value={filters.severity || ''} onChange={e => setFilters(f => ({ ...f, severity: e.target.value as Severity || undefined }))}
                    className="bg-[#1a1c3a] border border-white/5 rounded-lg px-3 py-1.5 text-sm text-white outline-none">
                    <option value="">All Severity</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                <select value={filters.status || ''} onChange={e => setFilters(f => ({ ...f, status: e.target.value as AlertStatus || undefined }))}
                    className="bg-[#1a1c3a] border border-white/5 rounded-lg px-3 py-1.5 text-sm text-white outline-none">
                    <option value="">All Status</option>
                    <option value="new">New</option>
                    <option value="investigating">Investigating</option>
                    <option value="contained">Contained</option>
                    <option value="closed">Closed</option>
                </select>
                <select value={filters.source || ''} onChange={e => setFilters(f => ({ ...f, source: e.target.value || undefined }))}
                    className="bg-[#1a1c3a] border border-white/5 rounded-lg px-3 py-1.5 text-sm text-white outline-none">
                    <option value="">All Sources</option>
                    <option value="EDR">EDR</option>
                    <option value="Firewall">Firewall</option>
                    <option value="IDS">IDS</option>
                    <option value="SIEM">SIEM</option>
                    <option value="Cloud">Cloud</option>
                    <option value="Email">Email</option>
                </select>
            </div>

            {/* Alert Table */}
            <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl overflow-hidden">
                <table className="w-full text-sm">
                    <thead>
                        <tr className="text-[#6B7089] text-xs border-b border-white/5 bg-[#111328]/40">
                            <th className="text-left px-5 py-3 font-medium">Alert ID</th>
                            <th className="text-left px-5 py-3 font-medium">Type</th>
                            <th className="text-left px-5 py-3 font-medium">Source</th>
                            <th className="text-left px-5 py-3 font-medium">Target</th>
                            <th className="text-left px-5 py-3 font-medium">Severity</th>
                            <th className="text-left px-5 py-3 font-medium">Status</th>
                            <th className="text-left px-5 py-3 font-medium">Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        {alerts.map(alert => (
                            <tr key={alert.id} onClick={() => navigate(`/alerts/${alert.id}`)}
                                className="border-b border-white/[0.03] hover:bg-white/[0.03] cursor-pointer transition-colors">
                                <td className="px-5 py-3.5 font-mono text-[#7C5CFC]">{alert.id}</td>
                                <td className="px-5 py-3.5">{alert.type}</td>
                                <td className="px-5 py-3.5 text-[#8B8DA0]">{alert.source}</td>
                                <td className="px-5 py-3.5 text-[#8B8DA0] font-mono text-xs">{alert.target}</td>
                                <td className="px-5 py-3.5">
                                    <span className={`text-xs px-2 py-0.5 rounded-full border ${severityColor[alert.severity]}`}>{alert.severity}</span>
                                </td>
                                <td className="px-5 py-3.5">
                                    <span className={`text-xs px-2 py-0.5 rounded-full ${statusColor[alert.status]}`}>{alert.status}</span>
                                </td>
                                <td className="px-5 py-3.5 text-[#8B8DA0] text-xs">{new Date(alert.timestamp).toLocaleTimeString()}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
                {alerts.length === 0 && (
                    <div className="text-center text-[#6B7089] py-16">No alerts match the current filters.</div>
                )}
            </div>
        </div>
    );
}
