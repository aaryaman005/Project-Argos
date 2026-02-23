import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { NotificationProvider } from './context/NotificationContext';
import AppLayout from './app/AppLayout';
import Landing from './pages/Landing';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import AlertDetail from './pages/AlertDetail';
import ThreatIntel from './pages/ThreatIntel';
import Playbooks from './pages/Playbooks';
import Audit from './pages/Audit';
import Simulator from './pages/Simulator';

export default function App() {
    return (
        <NotificationProvider>
            <BrowserRouter>
                <Routes>
                    <Route path="/landing" element={<Landing />} />
                    <Route element={<AppLayout />}>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/alerts" element={<Alerts />} />
                        <Route path="/alerts/:id" element={<AlertDetail />} />
                        <Route path="/threat-intel" element={<ThreatIntel />} />
                        <Route path="/playbooks" element={<Playbooks />} />
                        <Route path="/audit" element={<Audit />} />
                        <Route path="/simulator" element={<Simulator />} />
                    </Route>
                </Routes>
            </BrowserRouter>
        </NotificationProvider>
    );
}
