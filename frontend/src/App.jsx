/**
 * App Root Component
 * Routes, layout, and context providers.
 */

import { BrowserRouter, Routes, Route } from 'react-router-dom';
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
              <Route path="/analyze" element={<EmailAnalyzer />} />
              <Route path="/geo-tracer" element={<GeoTracer />} />
              <Route path="/cases" element={<CaseManagement />} />
              <Route path="/reports" element={<ForensicReport />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </EmailProvider>
  );
}
