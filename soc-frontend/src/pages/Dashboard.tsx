import { useEffect, useState } from 'react';
import { Shield, Cpu, Activity, Clock, FileText, MoreVertical, ChevronDown } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import api from '../services/api';
import MagicBento from '../components/MagicBento';

const monthlyData = [
    { month: 'Jan', threats: 180 }, { month: 'Feb', threats: 250 },
    { month: 'Mar', threats: 220 }, { month: 'Apr', threats: 200 },
    { month: 'May', threats: 310 }, { month: 'Jun', threats: 290 },
    { month: 'Jul', threats: 190 }, { month: 'Aug', threats: 230 },
    { month: 'Sep', threats: 170 }, { month: 'Oct', threats: 200 },
    { month: 'Nov', threats: 280 }, { month: 'Dec', threats: 250 },
];

const threatTypeData = [
    { name: 'Ransomware', value: 35, color: '#7C5CFC' },
    { name: 'Phishing', value: 25, color: '#FF6B9D' },
    { name: 'DDoS', value: 20, color: '#FF8C42' },
    { name: 'Insider', value: 15, color: '#4DAFFF' },
];

const statCards = [
    { icon: Shield, label: 'Total Threats', value: '284', color: '#FF6B6B', bg: 'rgba(255,107,107,0.15)' },
    { icon: Cpu, label: 'Active Incidents', value: '12', color: '#7C5CFC', bg: 'rgba(124,92,252,0.15)' },
    { icon: Activity, label: 'Response Rate', value: '94%', color: '#4DAFFF', bg: 'rgba(77,175,255,0.15)' },
    { icon: Clock, label: 'Avg MTTR', value: '0.45s', color: '#2DD4BF', bg: 'rgba(45,212,191,0.15)' },
    { icon: FileText, label: 'Assets at Risk', value: '8', color: '#FF9FFC', bg: 'rgba(255,159,252,0.15)' },
];

const bentoCards = [
    { color: '#060010', title: 'Threats Detected', description: '284 threats identified across all sources', label: 'Detection' },
    { color: '#060010', title: 'Active Incidents', description: '12 incidents under active investigation', label: 'Incidents' },
    { color: '#060010', title: 'Response Rate', description: '94% automated response coverage', label: 'Response' },
    { color: '#060010', title: 'Mean Time to Respond', description: '0.45s average across all severities', label: 'MTTR' },
    { color: '#060010', title: 'Playbooks Executed', description: '47 automated playbook runs this week', label: 'Automation' },
    { color: '#060010', title: 'Audit Trail', description: '1,204 actions logged with full attribution', label: 'Compliance' },
];

const H = { fontFamily: "'PT Serif', serif" };

function RiskGauge({ score = 741 }: { score?: number }) {
    const r = 70, circ = Math.PI * r, filled = circ * (score / 1000);
    return (
        <div className="flex flex-col items-center">
            <svg viewBox="0 0 180 110" className="w-44">
                <defs><linearGradient id="gg" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stopColor="#2DD4BF" /><stop offset="50%" stopColor="#4DAFFF" /><stop offset="100%" stopColor="#FF6B9D" />
                </linearGradient></defs>
                <path d="M 20 100 A 70 70 0 0 1 160 100" fill="none" stroke="#1a1c3a" strokeWidth="14" strokeLinecap="round" />
                <path d="M 20 100 A 70 70 0 0 1 160 100" fill="none" stroke="url(#gg)" strokeWidth="14" strokeLinecap="round" strokeDasharray={`${filled} ${circ}`} />
                <text x="90" y="65" textAnchor="middle" fontSize="11" fill="#6B7089">Score</text>
                <text x="90" y="90" textAnchor="middle" fontSize="30" fontWeight="bold" fill="white">{score}</text>
                <text x="18" y="115" textAnchor="middle" fontSize="9" fill="#6B7089">0</text>
                <text x="162" y="115" textAnchor="middle" fontSize="9" fill="#6B7089">1000</text>
            </svg>
        </div>
    );
}


export default function Dashboard() {
    const [stats, setStats] = useState({
        queue_size: 0,
        incidents_resolved: 0,
        total_threats: 0,
        avg_mttr: '0.45s',
        threat_levels: { critical: 0, high: 0, medium: 0, low: 0 }
    });

    useEffect(() => {
        const fetchStats = () => api.get('/stats').then(r => setStats(r.data)).catch(() => { });
        fetchStats();
        const interval = setInterval(fetchStats, 5000);
        return () => clearInterval(interval);
    }, []);

    const dynamicStatCards = [
        { icon: Shield, label: 'Total Threats', value: stats.total_threats.toString(), color: '#FF6B6B', bg: 'rgba(255,107,107,0.15)' },
        { icon: Cpu, label: 'Active Incidents', value: stats.queue_size.toString(), color: '#7C5CFC', bg: 'rgba(124,92,252,0.15)' },
        { icon: Activity, label: 'Resolved', value: stats.incidents_resolved.toString(), color: '#4DAFFF', bg: 'rgba(77,175,255,0.15)' },
        { icon: Clock, label: 'Avg MTTR', value: stats.avg_mttr, color: '#2DD4BF', bg: 'rgba(45,212,191,0.15)' },
        { icon: FileText, label: 'Assets at Risk', value: '8', color: '#FF9FFC', bg: 'rgba(255,159,252,0.15)' },
    ];

    const dynamicBentoCards = [
        { color: '#060010', title: 'Threats Detected', description: `${stats.total_threats} threats identified across all sources`, label: 'Detection' },
        { color: '#060010', title: 'Active Incidents', description: `${stats.queue_size} incidents under active investigation`, label: 'Incidents' },
        { color: '#060010', title: 'Resolved', description: `${stats.incidents_resolved} cases successfully mitigated`, label: 'Mitigation' },
        { color: '#060010', title: 'Mean Time to Respond', description: `${stats.avg_mttr} average across all severities`, label: 'MTTR' },
        { color: '#060010', title: 'Playbooks Executed', description: 'Real-time response tracking enabled', label: 'Automation' },
        { color: '#060010', title: 'Audit Trail', description: 'All actions logged with full attribution', label: 'Compliance' },
    ];

    const riskScore = Math.min(1000, (stats.threat_levels.critical * 300) + (stats.threat_levels.high * 150) + (stats.threat_levels.medium * 50));
    const riskLevel = riskScore > 700 ? 'Critical' : riskScore > 400 ? 'High' : riskScore > 100 ? 'Medium' : 'Low';
    const riskColor = riskScore > 700 ? 'text-red-400 bg-red-500/15' : riskScore > 400 ? 'text-orange-400 bg-orange-500/15' : 'text-blue-400 bg-blue-500/15';

    return (
        <div className="p-6 space-y-6">
            {/* Row 1 */}
            <div className="grid grid-cols-[1fr_260px] gap-6">
                <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                    <div className="flex items-center justify-between mb-6">
                        <h3 className="text-base font-semibold" style={H}>Current Risk</h3>
                        <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-[#1a1c3a] border border-white/5 text-xs text-[#8B8DA0]">Daily <ChevronDown className="w-3 h-3" /></button>
                    </div>
                    <div className="grid grid-cols-5 gap-4">
                        {dynamicStatCards.map(s => (
                            <div key={s.label} className="flex flex-col items-center text-center relative group">
                                <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-3" style={{ backgroundColor: s.bg }}><s.icon className="w-5 h-5" style={{ color: s.color }} /></div>
                                <p className="text-xl font-bold">{s.value}</p>
                                <p className="text-[11px] text-[#6B7089] mt-1">{s.label}</p>
                            </div>
                        ))}
                    </div>
                </div>
                <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6 flex flex-col items-center justify-center">
                    <div className="flex items-center justify-between w-full mb-2">
                        <h3 className="text-base font-semibold" style={H}>Risk Score</h3>
                        <MoreVertical className="w-4 h-4 text-[#6B7089]" />
                    </div>
                    <RiskGauge score={riskScore} />
                    <span className={`mt-1 text-xs font-semibold px-3 py-1 rounded-full ${riskColor}`}>{riskLevel}</span>
                </div>
            </div>

            {/* Row 2 */}
            <div className="grid grid-cols-[1fr_300px] gap-6">
                <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                    <h3 className="text-base font-semibold mb-6" style={H}>Threat Summary</h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={monthlyData}>
                                <defs><linearGradient id="ct" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#7C5CFC" stopOpacity={0.3} /><stop offset="95%" stopColor="#7C5CFC" stopOpacity={0} /></linearGradient></defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#1E2040" vertical={false} />
                                <XAxis dataKey="month" stroke="#6B7089" fontSize={11} tickLine={false} axisLine={false} />
                                <YAxis stroke="#6B7089" fontSize={11} tickLine={false} axisLine={false} />
                                <Tooltip contentStyle={{ backgroundColor: '#1a1c3a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px' }} />
                                <Area type="monotone" dataKey="threats" stroke="#7C5CFC" strokeWidth={2.5} fill="url(#ct)" dot={{ r: 3, fill: '#7C5CFC', strokeWidth: 0 }} />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>
                <div className="bg-[#111328]/60 backdrop-blur-xl border border-white/5 rounded-2xl p-6">
                    <h3 className="text-base font-semibold mb-6" style={H}>Threats By Type</h3>
                    <div className="flex items-center gap-4">
                        <div className="space-y-3 flex-1">
                            {threatTypeData.map(t => (
                                <div key={t.name} className="flex items-center gap-2">
                                    <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: t.color }} />
                                    <span className="text-xs text-[#8B8DA0]">{t.name}</span>
                                </div>
                            ))}
                        </div>
                        <div className="relative w-[130px] h-[130px]">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart><Pie data={threatTypeData} cx="50%" cy="50%" innerRadius={40} outerRadius={58} dataKey="value" strokeWidth={0}>
                                    {threatTypeData.map((e, i) => <Cell key={i} fill={e.color} />)}
                                </Pie></PieChart>
                            </ResponsiveContainer>
                            <div className="absolute inset-0 flex flex-col items-center justify-center">
                                <span className="text-[10px] text-[#6B7089]">Total</span>
                                <span className="text-lg font-bold">95</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Row 3: MagicBento */}
            <div>
                <h3 className="text-base font-semibold mb-4" style={H}>Operations Overview</h3>
                <MagicBento
                    cardData={dynamicBentoCards}
                    textAutoHide={true}
                    enableStars={true}
                    enableSpotlight={true}
                    enableBorderGlow={true}
                    enableTilt={false}
                    enableMagnetism={false}
                    clickEffect={true}
                    spotlightRadius={400}
                    particleCount={12}
                    glowColor="132, 0, 255"
                    disableAnimations={false}
                />
            </div>
        </div>
    );
}
