import { useNavigate } from 'react-router-dom';
import { Shield, Zap, Eye, Brain, Target, Lock, BarChart3, AlertTriangle } from 'lucide-react';
import LightPillar from '../components/LightPillar';
import MagicBento from '../components/MagicBento';
import CardSwap, { Card } from '../components/CardSwap';
import Dock from '../components/Dock';

const H = { fontFamily: "'PT Serif', serif" };

const bentoCards = [
    { color: '#060010', title: 'Threat Detection', description: 'AI-powered alert triage with multi-source correlation and priority scoring', label: 'Detection' },
    { color: '#060010', title: 'SOC Dashboard', description: 'Real-time risk posture, MTTR tracking, and threat landscape visualization', label: 'Overview' },
    { color: '#060010', title: 'Incident Response', description: 'Automated playbooks with dry-run capability, approval workflows, and full audit trails', label: 'Response' },
    { color: '#060010', title: 'Threat Intelligence', description: 'IOC enrichment across VirusTotal, AbuseIPDB, and OTX with risk scoring and verdict analysis', label: 'Intel' },
    { color: '#060010', title: 'MITRE ATT&CK', description: 'Automatic technique mapping for every alert with kill chain visualization', label: 'Framework' },
    { color: '#060010', title: 'Audit & Compliance', description: 'Complete decision logging — every action, every actor, every outcome', label: 'Audit' },
];

const routes: Record<string, string> = {
    'Dashboard': '/',
    'Alerts': '/alerts',
    'Threat Intel': '/threat-intel',
    'Playbooks': '/playbooks',
    'Audit': '/audit',
};

const dockItems = [
    { icon: <BarChart3 size={18} />, label: 'Dashboard' },
    { icon: <AlertTriangle size={18} />, label: 'Alerts' },
    { icon: <Eye size={18} />, label: 'Threat Intel' },
    { icon: <Zap size={18} />, label: 'Playbooks' },
    { icon: <Lock size={18} />, label: 'Audit' },
];

export default function Landing() {
    const navigate = useNavigate();

    const dockWithNav = dockItems.map(item => ({
        ...item,
        onClick: () => navigate(routes[item.label] || '/'),
    }));

    return (
        <div className="relative min-h-screen bg-[#0B0D1A] text-white overflow-x-hidden" style={{ fontFamily: "'Inter', system-ui, sans-serif" }}>
            {/* LightPillar Background */}
            <div className="absolute inset-0 z-0 opacity-20 pointer-events-none">
                <LightPillar />
            </div>

            {/* Hero Section */}
            <div className="relative z-10 flex flex-col items-center pt-20 pb-10">
                {/* Badge */}
                <div className="flex items-center gap-2 px-4 py-1.5 rounded-full border border-[#7C5CFC]/20 bg-[#7C5CFC]/5 mb-8">
                    <Shield className="w-3.5 h-3.5 text-[#7C5CFC]" />
                    <span className="text-xs text-[#7C5CFC] font-medium tracking-wide">AUTONOMOUS SOC ENGINE</span>
                </div>

                <h1 className="text-5xl md:text-7xl font-bold text-center leading-tight max-w-4xl" style={H}>
                    Project <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#7C5CFC] to-[#4A8CFF]">Argos</span>
                </h1>

                <p className="mt-6 text-lg text-[#8B8DA0] text-center max-w-2xl leading-relaxed">
                    AI-driven Security Operations Center that autonomously detects, triages, and responds to threats — with full explainability and human-in-the-loop control.
                </p>

                {/* Enter Console Button */}
                <button
                    onClick={() => navigate('/')}
                    className="mt-10 group relative px-8 py-4 rounded-2xl bg-gradient-to-r from-[#7C5CFC] to-[#4A8CFF] text-white font-semibold text-lg shadow-lg shadow-[#7C5CFC]/25 hover:shadow-[#7C5CFC]/40 transition-all hover:scale-105 active:scale-95"
                >
                    <span className="flex items-center gap-3">
                        <Target className="w-5 h-5" />
                        Enter Console
                        <span className="text-white/50 group-hover:text-white/80 transition-colors">→</span>
                    </span>
                </button>

                <p className="mt-4 text-xs text-[#6B7089]">No authentication required for demo</p>
            </div>

            {/* CardSwap + Feature Highlights */}
            <div className="relative z-10 max-w-6xl mx-auto px-6 py-16">
                <div className="flex items-start gap-12">
                    {/* Left: Feature text */}
                    <div className="flex-1 space-y-8 pt-8">
                        <h2 className="text-3xl font-bold" style={H}>
                            Intelligent <span className="text-[#4A8CFF]">Threat Response</span>
                        </h2>
                        <div className="space-y-6">
                            {[
                                { icon: Brain, title: 'AI-Powered Triage', desc: 'Every alert is scored, classified, and mapped to MITRE ATT&CK — automatically.' },
                                { icon: Zap, title: 'Automated Playbooks', desc: 'One-click response actions with dry-run mode and approval workflows.' },
                                { icon: Eye, title: 'Full Explainability', desc: 'Every decision is logged. Every action is auditable. No black boxes.' },
                            ].map(({ icon: Icon, title, desc }) => (
                                <div key={title} className="flex gap-4">
                                    <div className="w-10 h-10 rounded-xl bg-[#7C5CFC]/10 flex items-center justify-center shrink-0">
                                        <Icon className="w-5 h-5 text-[#7C5CFC]" />
                                    </div>
                                    <div>
                                        <h3 className="text-sm font-semibold">{title}</h3>
                                        <p className="text-sm text-[#6B7089] mt-1">{desc}</p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Right: CardSwap */}
                    <div className="flex-1 relative" style={{ height: '420px' }}>
                        <CardSwap
                            cardDistance={50}
                            verticalDistance={60}
                            delay={4000}
                            pauseOnHover={true}
                            width={380}
                            height={280}
                            onCardClick={() => { }}
                        >
                            <Card>
                                <div className="p-6 h-full flex flex-col justify-between border border-[#7C5CFC]/10 rounded-2xl bg-gradient-to-br from-[#0B0D1A] to-[#111328]">
                                    <div className="flex items-center gap-2">
                                        <Shield className="w-5 h-5 text-[#FF6B6B]" />
                                        <span className="text-xs text-[#FF6B6B] font-medium">CRITICAL ALERT</span>
                                    </div>
                                    <div>
                                        <h3 className="text-lg font-semibold" style={H}>Privilege Escalation Detected</h3>
                                        <p className="text-xs text-[#6B7089] mt-2">prod-db-01 • Priority: 94.5 • MITRE: T1548</p>
                                        <div className="flex gap-2 mt-3">
                                            <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/10 text-red-400">block_ip</span>
                                            <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/10 text-red-400">isolate_host</span>
                                        </div>
                                    </div>
                                </div>
                            </Card>
                            <Card>
                                <div className="p-6 h-full flex flex-col justify-between border border-[#4A8CFF]/10 rounded-2xl bg-gradient-to-br from-[#0B0D1A] to-[#111328]">
                                    <div className="flex items-center gap-2">
                                        <Eye className="w-5 h-5 text-[#4A8CFF]" />
                                        <span className="text-xs text-[#4A8CFF] font-medium">THREAT INTEL</span>
                                    </div>
                                    <div>
                                        <h3 className="text-lg font-semibold" style={H}>IOC Enrichment Complete</h3>
                                        <p className="text-xs text-[#6B7089] mt-2">185.220.101.34 • Risk: 92 • Verdict: Malicious</p>
                                        <div className="flex gap-2 mt-3">
                                            <span className="text-xs px-2 py-0.5 rounded-full bg-[#7C5CFC]/10 text-[#7C5CFC]">VirusTotal</span>
                                            <span className="text-xs px-2 py-0.5 rounded-full bg-[#7C5CFC]/10 text-[#7C5CFC]">AbuseIPDB</span>
                                        </div>
                                    </div>
                                </div>
                            </Card>
                            <Card>
                                <div className="p-6 h-full flex flex-col justify-between border border-green-500/10 rounded-2xl bg-gradient-to-br from-[#0B0D1A] to-[#111328]">
                                    <div className="flex items-center gap-2">
                                        <Zap className="w-5 h-5 text-green-400" />
                                        <span className="text-xs text-green-400 font-medium">PLAYBOOK EXECUTED</span>
                                    </div>
                                    <div>
                                        <h3 className="text-lg font-semibold" style={H}>Block Malicious IP</h3>
                                        <p className="text-xs text-[#6B7089] mt-2">4 actions completed • MTTR: 0.45s</p>
                                        <div className="flex gap-2 mt-3">
                                            <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/10 text-green-400">resolved</span>
                                        </div>
                                    </div>
                                </div>
                            </Card>
                        </CardSwap>
                    </div>
                </div>
            </div>

            {/* Bento Grid */}
            <div className="relative z-10 flex justify-center pb-32">
                <MagicBento
                    cardData={bentoCards}
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

            {/* Dock */}
            <Dock
                items={dockWithNav}
                panelHeight={68}
                baseItemSize={50}
                magnification={70}
            />
        </div>
    );
}
