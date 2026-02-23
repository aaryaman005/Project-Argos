import React, { useState, useEffect } from 'react';
import {
    Shield,
    AlertTriangle,
    Activity,
    Zap,
    CheckCircle,
    Cpu,
    Clock,
    Database,
    Search,
    Settings,
    Bell,
    BarChart3,
    Network
} from 'lucide-react';
import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    AreaChart,
    Area
} from 'recharts';

const data = [
    { time: '00:00', alerts: 12, resolved: 8 },
    { time: '04:00', alerts: 18, resolved: 14 },
    { time: '08:00', alerts: 45, resolved: 38 },
    { time: '12:00', alerts: 30, resolved: 28 },
    { time: '16:00', alerts: 55, resolved: 48 },
    { time: '20:00', alerts: 25, resolved: 22 },
];

export default function Dashboard() {
    const [activeAlerts, setActiveAlerts] = useState([
        { id: 'ARG-7721', type: 'Ransomware', target: 'prod-db-01', score: 92.4, status: 'Mitigating', time: '2m ago' },
        { id: 'ARG-7722', type: 'Exfiltration', target: 'finance-pc-12', score: 88.1, status: 'Triaging', time: '5m ago' },
        { id: 'ARG-7723', type: 'Brute Force', target: 'jump-box-ext', score: 45.2, status: 'Monitoring', time: '12m ago' },
    ]);

    return (
        <div className="min-h-screen bg-slate-950 flex flex-col">
            {/* Navbar */}
            <nav className="border-b border-slate-800 px-6 py-4 flex items-center justify-between bg-slate-900/50">
                <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-brand-600 rounded-lg flex items-center justify-center shadow-lg shadow-brand-500/20">
                        <Shield className="text-white w-6 h-6" />
                    </div>
                    <div>
                        <h1 className="text-xl font-bold tracking-tight">PROJECT <span className="text-brand-500">ARGOS</span></h1>
                        <p className="text-xs text-slate-400 font-medium">AUTONOMOUS RESPONSE ENGINE</p>
                    </div>
                </div>
                <div className="flex items-center gap-6">
                    <div className="relative">
                        <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                        <input
                            type="text"
                            placeholder="Search assets..."
                            className="bg-slate-800 border-none rounded-full py-2 pl-10 pr-4 text-sm focus:ring-2 focus:ring-brand-500 w-64 transition-all"
                        />
                    </div>
                    <Bell className="w-5 h-5 text-slate-400 cursor-pointer hover:text-white transition-colors" />
                    <Settings className="w-5 h-5 text-slate-400 cursor-pointer hover:text-white transition-colors" />
                    <div className="w-8 h-8 rounded-full bg-slate-700 border border-slate-600"></div>
                </div>
            </nav>

            <main className="flex-1 p-6 space-y-6 overflow-y-auto">
                {/* Top Stats */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                    <StatCard icon={<Zap className="text-amber-500" />} label="AUTONOMOUS ACTIONS" value="1,284" trend="+12.5%" />
                    <StatCard icon={<Clock className="text-brand-500" />} label="MEAN TIME TO RESPOND" value="0.45s" trend="-4s" />
                    <StatCard icon={<CheckCircle className="text-emerald-500" />} label="SUCCESS RATE" value="99.2%" trend="+0.4%" />
                    <StatCard icon={<Activity className="text-rose-500" />} label="ACTIVE THREATS" value="3" trend="-2" />
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Main Chart */}
                    <div className="lg:col-span-2 bg-slate-900/50 border border-slate-800 rounded-2xl p-6 shadow-xl">
                        <div className="flex items-center justify-between mb-8">
                            <h2 className="text-lg font-semibold flex items-center gap-2">
                                <BarChart3 className="w-5 h-5 text-brand-500" />
                                Response Intelligence Trends
                            </h2>
                            <select className="bg-slate-800 border-none text-xs rounded-lg py-1 px-3">
                                <option>Last 24 Hours</option>
                                <option>Last 7 Days</option>
                            </select>
                        </div>
                        <div className="h-72">
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={data}>
                                    <defs>
                                        <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#0e8ce9" stopOpacity={0.3} />
                                            <stop offset="95%" stopColor="#0e8ce9" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                                    <XAxis dataKey="time" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                                    <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                                    <Tooltip
                                        contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px' }}
                                        itemStyle={{ color: '#f8fafc' }}
                                    />
                                    <Area type="monotone" dataKey="alerts" stroke="#0e8ce9" strokeWidth={3} fillOpacity={1} fill="url(#colorAlerts)" />
                                    <Area type="monotone" dataKey="resolved" stroke="#10b981" strokeWidth={2} fillOpacity={0} />
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>
                    </div>

                    {/* Active Queue */}
                    <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col">
                        <h2 className="text-lg font-semibold mb-6 flex items-center gap-2">
                            <Cpu className="w-5 h-5 text-brand-500" />
                            Intelligence Queue
                        </h2>
                        <div className="space-y-4 flex-1">
                            {activeAlerts.map(alert => (
                                <div key={alert.id} className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4 flex items-center justify-between group hover:border-brand-500/50 transition-all cursor-pointer">
                                    <div className="flex items-center gap-4">
                                        <div className={`p-2 rounded-lg ${alert.score > 80 ? 'bg-rose-500/10' : 'bg-brand-500/10'}`}>
                                            <AlertTriangle className={`w-5 h-5 ${alert.score > 80 ? 'text-rose-500' : 'text-brand-500'}`} />
                                        </div>
                                        <div>
                                            <div className="flex items-center gap-2">
                                                <span className="text-sm font-bold">{alert.type}</span>
                                                <span className="text-[10px] bg-slate-700 px-1.5 py-0.5 rounded text-slate-400">{alert.id}</span>
                                            </div>
                                            <p className="text-xs text-slate-400 mt-1">Target: {alert.target}</p>
                                        </div>
                                    </div>
                                    <div className="text-right">
                                        <div className="text-sm font-mono text-brand-400">{alert.score}%</div>
                                        <div className="text-[10px] text-slate-500 mt-1">{alert.time}</div>
                                    </div>
                                </div>
                            ))}
                        </div>
                        <button className="w-full mt-6 py-3 bg-brand-600 hover:bg-brand-500 text-white text-sm font-bold rounded-xl transition-all shadow-lg shadow-brand-500/20 active:scale-95">
                            RUN SIMULATION STREAM
                        </button>
                    </div>
                </div>

                {/* Bottom Panel */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6 col-span-1">
                        <h3 className="text-sm font-bold text-slate-400 mb-4 flex items-center gap-2">
                            <Network className="w-4 h-4" /> BAST RADIUS TOPOLOGY
                        </h3>
                        <div className="h-40 bg-slate-800 rounded-xl flex items-center justify-center border border-slate-700 border-dashed">
                            <p className="text-xs text-slate-500 italic">Topology Graph Active - Monitoring nodes...</p>
                        </div>
                    </div>
                    <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6 col-span-2 overflow-hidden">
                        <h3 className="text-sm font-bold text-slate-400 mb-4 flex items-center gap-2">
                            <Database className="w-4 h-4" /> DECISION AUDIT LOG
                        </h3>
                        <div className="text-xs space-y-2 font-mono">
                            <div className="flex gap-4 text-emerald-400"><span className="text-slate-500">[20:04:15]</span> Autonomous decision: Isolate host prod-db-01 (Risk Reduction: 85%)</div>
                            <div className="flex gap-4 text-brand-400"><span className="text-slate-500">[20:02:44]</span> Greedy Optimizer: Selecting Block IP over Quarantine for cost efficiency.</div>
                            <div className="flex gap-4 text-amber-400"><span className="text-slate-500">[19:58:12]</span> Triage Complete: Alert ARG-7612 classified as HIGH (Confidence: 0.88)</div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
}

function StatCard({ icon, label, value, trend }) {
    return (
        <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6 shadow-lg group hover:bg-slate-800/50 transition-all">
            <div className="flex items-center justify-between mb-4">
                <div className="p-2 bg-slate-800 rounded-xl group-hover:bg-slate-700 transition-all">{icon}</div>
                <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${trend.startsWith('+') ? 'bg-emerald-500/10 text-emerald-500' : 'bg-rose-500/10 text-rose-500'}`}>
                    {trend}
                </span>
            </div>
            <p className="text-xs font-bold text-slate-500 uppercase tracking-wider">{label}</p>
            <p className="text-2xl font-bold mt-1">{value}</p>
        </div>
    );
}
