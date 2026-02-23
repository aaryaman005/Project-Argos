import { createContext, useContext, useState, useCallback, ReactNode } from 'react';

export interface Notification {
    id: string;
    type: 'alert' | 'response' | 'info' | 'success' | 'error';
    title: string;
    message: string;
    timestamp: Date;
    read: boolean;
    severity?: string;
    incidentId?: string;
}

interface NotificationContextType {
    notifications: Notification[];
    unreadCount: number;
    addNotification: (n: Omit<Notification, 'id' | 'timestamp' | 'read'>) => void;
    markAllRead: () => void;
    markRead: (id: string) => void;
    clearAll: () => void;
}

const NotificationContext = createContext<NotificationContextType | null>(null);

export function NotificationProvider({ children }: { children: ReactNode }) {
    const [notifications, setNotifications] = useState<Notification[]>([]);

    const addNotification = useCallback((n: Omit<Notification, 'id' | 'timestamp' | 'read'>) => {
        const newNotif: Notification = {
            ...n,
            id: crypto.randomUUID(),
            timestamp: new Date(),
            read: false,
        };
        setNotifications(prev => [newNotif, ...prev]);
    }, []);

    const markAllRead = useCallback(() => {
        setNotifications(prev => prev.map(n => ({ ...n, read: true })));
    }, []);

    const markRead = useCallback((id: string) => {
        setNotifications(prev => prev.map(n => n.id === id ? { ...n, read: true } : n));
    }, []);

    const clearAll = useCallback(() => {
        setNotifications([]);
    }, []);

    const unreadCount = notifications.filter(n => !n.read).length;

    return (
        <NotificationContext.Provider value={{ notifications, unreadCount, addNotification, markAllRead, markRead, clearAll }}>
            {children}
        </NotificationContext.Provider>
    );
}

export function useNotifications() {
    const ctx = useContext(NotificationContext);
    if (!ctx) throw new Error('useNotifications must be used within NotificationProvider');
    return ctx;
}
