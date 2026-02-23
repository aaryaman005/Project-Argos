import { useState, useRef, useEffect } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import {
    LayoutDashboard, AlertTriangle, Server, Shield, BookOpen,
    FileText, HelpCircle, Settings, LogOut, ChevronRight,
    Search, Bell, MessageSquare, Play, X, Check, Trash2
} from 'lucide-react';
import { useNotifications, Notification } from '../context/NotificationContext';
import api from '../services/api';
// @ts-ignore — LightPillar is vanilla JS
import LightPillar from '../components/LightPillar';

const navSections = [
    {
        title: 'General', items: [
            { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
            { to: '/alerts', icon: AlertTriangle, label: 'Alerts' },
            { to: '/threat-intel', icon: Shield, label: 'Threat Intel' },
        ]
    },
    {
        title: 'Response', items: [
            { to: '/playbooks', icon: BookOpen, label: 'Playbooks' },
        ]
    },
    {
        title: 'Operations', items: [
            { to: '/simulator', icon: Play, label: 'Simulator' },
        ]
    },
    {
        title: 'Reports', items: [
            { to: '/audit', icon: FileText, label: 'Audit Log' },
        ]
    },
];

function NotificationPanel({ onClose }: { onClose: () => void }) {
    const { notifications, unreadCount, markAllRead, markRead, clearAll } = useNotifications();
    const panelRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const handleClick = (e: MouseEvent) => {
            if (panelRef.current && !panelRef.current.contains(e.target as Node)) onClose();
        };
        document.addEventListener('mousedown', handleClick);
        return () => document.removeEventListener('mousedown', handleClick);
    }, [onClose]);

    const iconForType = (type: Notification['type']) => {
        switch (type) {
            case 'alert': return '🚨';
            case 'response': return '⚡';
            case 'success': return '✅';
            case 'error': return '❌';
            default: return 'ℹ️';
        }
    };

    const borderForType = (type: Notification['type']) => {
        switch (type) {
            case 'alert': return 'border-l-red-400';
            case 'response': return 'border-l-green-400';
            case 'error': return 'border-l-red-500';
            case 'success': return 'border-l-green-400';
            default: return 'border-l-[#7C5CFC]';
        }
    };

    return (
        <div ref={panelRef} className="absolute right-0 top-12 w-[400px] max-h-[500px] bg-[#111328] border border-white/10 rounded-2xl shadow-2xl shadow-black/50 z-50 overflow-hidden flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-white/5">
                <div className="flex items-center gap-2">
                    <Bell className="w-4 h-4 text-[#7C5CFC]" />
                    <h3 className="text-sm font-semibold">Notifications</h3>
                    {unreadCount > 0 && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-red-500/20 text-red-400 font-bold">{unreadCount}</span>
                    )}
                </div>
                <div className="flex items-center gap-1">
                    {unreadCount > 0 && (
                        <button onClick={markAllRead} className="p-1.5 rounded-lg hover:bg-white/10 text-[#6B7089] hover:text-white transition-colors" title="Mark all read">
                            <Check className="w-3.5 h-3.5" />
                        </button>
                    )}
                    {notifications.length > 0 && (
                        <button onClick={clearAll} className="p-1.5 rounded-lg hover:bg-white/10 text-[#6B7089] hover:text-white transition-colors" title="Clear all">
                            <Trash2 className="w-3.5 h-3.5" />
                        </button>
                    )}
                    <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/10 text-[#6B7089] hover:text-white transition-colors">
                        <X className="w-3.5 h-3.5" />
                    </button>
                </div>
            </div>

            <div className="flex-1 overflow-y-auto" style={{ scrollbarWidth: 'thin' }}>
                {notifications.length === 0 ? (
                    <div className="p-8 text-center text-[#6B7089]">
                        <Bell className="w-8 h-8 mx-auto mb-2 opacity-30" />
                        <p className="text-sm">No notifications yet</p>
                        <p className="text-xs mt-1 opacity-50">Start the simulator to see live alerts</p>
                    </div>
                ) : (
                    <div className="p-2 space-y-1">
                        {notifications.slice(0, 50).map(n => (
                            <div key={n.id}
                                onClick={() => markRead(n.id)}
                                className={`p-3 rounded-xl border-l-2 ${borderForType(n.type)} cursor-pointer transition-all
                                    ${n.read ? 'bg-transparent opacity-60' : 'bg-white/[0.03]'} hover:bg-white/[0.05]`}>
                                <div className="flex items-start gap-2">
                                    <span className="text-sm shrink-0 mt-0.5">{iconForType(n.type)}</span>
                                    <div className="flex-1 min-w-0">
                                        <p className={`text-xs font-semibold ${n.read ? 'text-[#8B8DA0]' : 'text-white'}`}>
                                            {n.title}
                                        </p>
                                        <p className="text-[11px] text-[#6B7089] mt-0.5 truncate">{n.message}</p>
                                        <p className="text-[10px] text-[#6B7089] mt-1 font-mono">
                                            {n.timestamp.toLocaleTimeString()}
                                        </p>
                                    </div>
                                    {!n.read && <span className="w-2 h-2 rounded-full bg-[#7C5CFC] shrink-0 mt-1" />}
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}

export default function AppLayout() {
    const location = useLocation();
    const { unreadCount, addNotification } = useNotifications();
    const [showNotifications, setShowNotifications] = useState(false);
    const seenIds = useRef<Set<string>>(new Set());
    const isFirstLoad = useRef(true);

    // Global Alert Polling
    useEffect(() => {
        const checkForNewAlerts = async () => {
            try {
                const res = await api.get('/incidents');
                const incidents = res.data.incidents || [];

                let foundNew = false;
                incidents.forEach((inc: any) => {
                    if (!seenIds.current.has(inc.id)) {
                        seenIds.current.add(inc.id);

                        // Don't notify for everything on first load
                        if (!isFirstLoad.current) {
                            addNotification({
                                type: 'alert',
                                title: `🚨 New ${inc.severity.toUpperCase()} Alert`,
                                message: `${inc.type}: ${inc.description}`,
                                severity: inc.severity.toUpperCase(),
                                incidentId: inc.id
                            });
                            foundNew = true;
                        }
                    }
                });

                if (isFirstLoad.current) {
                    isFirstLoad.current = false;
                }
            } catch (err) {
                console.error("Polling failed", err);
            }
        };

        checkForNewAlerts();
        const interval = setInterval(checkForNewAlerts, 5000);
        return () => clearInterval(interval);
    }, [addNotification]);

    return (
        <div className="flex h-screen bg-[#0B0D1A] text-white overflow-hidden relative" style={{ fontFamily: "'Inter', system-ui, sans-serif" }}>
            {/* LightPillar Background */}
            <div className="absolute inset-0 z-0 opacity-15 pointer-events-none">
                <LightPillar topColor="#5227FF" bottomColor="#FF9FFC" intensity={1} rotationSpeed={0.3}
                    glowAmount={0.002} pillarWidth={3} pillarHeight={0.4} noiseIntensity={0.5}
                    pillarRotation={25} interactive={false} mixBlendMode="screen" quality="high" />
            </div>

            {/* Sidebar */}
            <aside className="relative z-10 w-[220px] border-r border-white/5 flex flex-col bg-[#0D0F1F]/80 backdrop-blur-xl shrink-0">
                <div className="px-5 py-6">
                    <h1 className="text-lg font-bold tracking-wider" style={{ fontFamily: "'PT Serif', serif" }}>
                        <span className="text-[#7C5CFC]">Project</span>Argos
                    </h1>
                </div>

                <nav className="flex-1 px-3 space-y-6 overflow-y-auto">
                    {navSections.map(section => (
                        <div key={section.title}>
                            <p className="text-[10px] font-semibold text-[#6B7089] uppercase tracking-widest px-3 mb-2">{section.title}</p>
                            <div className="space-y-1">
                                {section.items.map(item => (
                                    <NavLink key={item.to} to={item.to} end={item.to === '/'}
                                        className={({ isActive }) => `w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm transition-all ${isActive ? 'bg-[#7C5CFC] text-white font-medium shadow-lg shadow-[#7C5CFC]/20' : 'text-[#8B8DA0] hover:bg-white/5 hover:text-white'
                                            }`}>
                                        <item.icon className="w-[18px] h-[18px]" />
                                        <span className="flex-1 text-left">{item.label}</span>
                                    </NavLink>
                                ))}
                            </div>
                        </div>
                    ))}
                </nav>

                <div className="px-3 pb-2 space-y-1">
                    <p className="text-[10px] font-semibold text-[#6B7089] uppercase tracking-widest px-3 mb-2">Settings</p>
                    <button className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm text-[#8B8DA0] hover:bg-white/5 hover:text-white transition-all">
                        <HelpCircle className="w-[18px] h-[18px]" /><span>Help & Support</span>
                    </button>
                    <button className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm text-[#8B8DA0] hover:bg-white/5 hover:text-white transition-all">
                        <Settings className="w-[18px] h-[18px]" /><span>Settings</span>
                    </button>
                </div>

                <div className="px-3 py-4 border-t border-white/5">
                    <button className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm text-[#8B8DA0] hover:bg-white/5 hover:text-red-400 transition-all">
                        <LogOut className="w-[18px] h-[18px]" /><span>Log Out</span>
                    </button>
                </div>
            </aside>

            {/* Main Content */}
            <main className="relative z-10 flex-1 flex flex-col min-w-0">
                <header className="flex items-center justify-between px-8 py-4 border-b border-white/5 bg-[#0D0F1F]/60 backdrop-blur-xl shrink-0 relative z-20 shadow-xl shadow-black/40">
                    <div className="flex items-center gap-4">
                        <div className="w-10 h-10 rounded-full bg-gradient-to-br from-[#7C5CFC] to-[#FF9FFC]" />
                        <div>
                            <h2 className="text-base font-semibold" style={{ fontFamily: "'PT Serif', serif" }}>Welcome! Operator</h2>
                            <p className="text-xs text-[#6B7089]">Security is a process, not a product.</p>
                        </div>
                    </div>
                    <div className="flex items-center gap-4">
                        <div className="relative">
                            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#6B7089]" />
                            <input type="text" placeholder="Search Here"
                                className="bg-[#111328]/80 border border-white/5 rounded-full py-2 pl-10 pr-4 text-sm w-64 focus:ring-1 focus:ring-[#7C5CFC] outline-none text-white placeholder-[#6B7089]" />
                        </div>
                        <button className="w-9 h-9 rounded-full bg-[#111328]/80 border border-white/5 flex items-center justify-center text-[#6B7089] hover:text-white transition-colors">
                            <MessageSquare className="w-4 h-4" />
                        </button>

                        {/* Notification Bell — now functional */}
                        <div className="relative">
                            <button
                                onClick={() => setShowNotifications(!showNotifications)}
                                className="relative w-9 h-9 rounded-full bg-[#111328]/80 border border-white/5 flex items-center justify-center text-[#6B7089] hover:text-white transition-colors">
                                <Bell className="w-4 h-4" />
                                {unreadCount > 0 && (
                                    <span className="absolute -top-1 -right-1 min-w-[18px] h-[18px] flex items-center justify-center bg-red-500 rounded-full text-[10px] font-bold text-white px-1 border-2 border-[#0B0D1A]">
                                        {unreadCount > 99 ? '99+' : unreadCount}
                                    </span>
                                )}
                            </button>
                            {showNotifications && <NotificationPanel onClose={() => setShowNotifications(false)} />}
                        </div>
                    </div>
                </header>

                <div className="flex-1 overflow-y-auto">
                    <Outlet />
                </div>
            </main>
        </div>
    );
}
