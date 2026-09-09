/**
 * App Root Component
 * Routes, layout, and context providers.
 */

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { EmailProvider } from './context/EmailContext';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import EmailAnalyzer from './pages/EmailAnalyzer';
import GeoTracer from './pages/GeoTracer';
import CaseManagement from './pages/CaseManagement';
import ForensicReport from './pages/ForensicReport';

export default function App() {
  return (
    <EmailProvider>
      <BrowserRouter>
        <div className="app-layout">
          <Sidebar />
          <main className="main-content">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/dashboard" element={<Navigate to="/" replace />} />
              <Route path="/analyze" element={<EmailAnalyzer />} />
              <Route path="/email-analyzer" element={<Navigate to="/analyze" replace />} />
              <Route path="/geo-tracer" element={<GeoTracer />} />
              <Route path="/cases" element={<CaseManagement />} />
              <Route path="/case-management" element={<Navigate to="/cases" replace />} />
              <Route path="/reports" element={<ForensicReport />} />
              <Route path="/forensic-report" element={<Navigate to="/reports" replace />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </EmailProvider>
  );
}
