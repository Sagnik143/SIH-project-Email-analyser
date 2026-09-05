import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import ThreatScoreCard from './components/ThreatScoreCard';
import GeoRelayMap from './components/GeoRelayMap';
import RelayTimeline from './components/RelayTimeline';
import AIIntelligenceCard from './components/AIIntelligenceCard';
import AuthMatrix from './components/AuthMatrix';
import IoCVault from './components/IoCVault';
import HeaderInspector from './components/HeaderInspector';
import ForensicReportModal from './components/ForensicReportModal';
import EmailInputModal from './components/EmailInputModal';
import { API_BASE_URL } from './config';
import { Shield, Loader2, AlertCircle, Sparkles, CheckCircle2 } from 'lucide-react';

export default function App() {
  const [samples, setSamples] = useState([]);
  const [selectedSampleId, setSelectedSampleId] = useState('');
  const [dossier, setDossier] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState(null);
  const [openrouterModel, setOpenrouterModel] = useState('minimax/minimax-m3:free');

  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);

  // Initialize data on mount
  useEffect(() => {
    async function init() {
      try {
        const healthRes = await fetch(`${API_BASE_URL}/api/health`);
        if (healthRes.ok) {
          const healthData = await healthRes.json();
          if (healthData.primaryModel) setOpenrouterModel(healthData.primaryModel);
        }

        const samplesRes = await fetch(`${API_BASE_URL}/api/samples`);
        if (samplesRes.ok) {
          const samplesData = await samplesRes.json();
          const list = samplesData.samples || [];
          setSamples(list);

          if (list.length > 0) {
            loadAndAnalyzeSample(list[0].id);
          }
        }
      } catch (err) {
        console.error('Initialization error:', err);
        setError('Failed to connect to forensic backend API. Please check your network connection.');
      }
    }

    init();
  }, []);

  const loadAndAnalyzeSample = async (sampleId) => {
    setIsAnalyzing(true);
    setError(null);
    setSelectedSampleId(sampleId);

    try {
      const res = await fetch(`${API_BASE_URL}/api/samples/${sampleId}`);
      if (!res.ok) throw new Error('Failed to load sample dataset');
      const sample = await res.json();

      await runAnalysis(sample.rawEmail);
    } catch (err) {
      console.error('Sample analysis error:', err);
      setError(err.message || 'Analysis pipeline failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const runAnalysis = async (rawEmailText) => {
    setIsAnalyzing(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE_URL}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawEmail: rawEmailText })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Forensic analysis failed');
      }

      const forensicData = await response.json();
      setDossier(forensicData);
    } catch (err) {
      console.error('Analysis error:', err);
      setError(err.message);
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 text-slate-800 font-sans selection:bg-blue-100 selection:text-blue-900">
      
      {/* Top Navigation Header */}
      <Header
        samples={samples}
        selectedSampleId={selectedSampleId}
        onSelectSample={loadAndAnalyzeSample}
        onOpenUploadModal={() => setIsUploadModalOpen(true)}
        onOpenReportModal={() => setIsReportModalOpen(true)}
        isAnalyzing={isAnalyzing}
        openrouterModel={openrouterModel}
      />

      {/* Main Content Dashboard */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 lg:px-8 py-6 space-y-6">
        
        {/* Error Alert */}
        {error && (
          <div className="p-4 rounded-2xl bg-rose-50 border border-rose-200 text-rose-800 text-xs flex items-center justify-between shadow-xs">
            <div className="flex items-center gap-2.5">
              <AlertCircle className="w-5 h-5 text-rose-600 shrink-0" />
              <span>{error}</span>
            </div>
            <button
              onClick={() => selectedSampleId && loadAndAnalyzeSample(selectedSampleId)}
              className="px-3 py-1 rounded-lg bg-rose-100 hover:bg-rose-200 text-rose-800 text-xs font-semibold transition"
            >
              Retry
            </button>
          </div>
        )}

        {/* Loading State Overlay */}
        {isAnalyzing && (
          <div className="p-10 rounded-2xl bg-white border border-slate-200 shadow-sm text-center flex flex-col items-center justify-center space-y-3">
            <div className="w-12 h-12 rounded-2xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600 shadow-sm">
              <Loader2 className="w-6 h-6 animate-spin" />
            </div>
            <div className="text-base font-bold text-slate-900">
              Analyzing Email Threat Telemetry...
            </div>
            <p className="text-xs text-slate-500 max-w-md leading-relaxed">
              Tracing server hops &bull; Geocoding sender origin &bull; Checking authentication &bull; OpenRouter AI evaluation
            </p>
          </div>
        )}

        {/* Dashboard Panels (when dossier is ready) */}
        {!isAnalyzing && dossier && (
          <>
            {/* 1. Threat Score & Summary Card */}
            <ThreatScoreCard dossier={dossier} />

            {/* 2. Interactive Map & Server Hop Timeline */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-7">
                <GeoRelayMap relay={dossier.relay} originGeo={dossier.originGeo} />
              </div>
              <div className="lg:col-span-5">
                <RelayTimeline relay={dossier.relay} />
              </div>
            </div>

            {/* 3. AI Security Analysis & Deception Detection */}
            <AIIntelligenceCard aiThreatIntelligence={dossier.aiThreatIntelligence} />

            {/* 4. Sender Identity & Authentication Verifications */}
            <AuthMatrix authentication={dossier.authentication} envelope={dossier.envelope} />

            {/* 5. Indicators of Compromise (IoC) Vault */}
            <IoCVault iocs={dossier.iocs} />

            {/* 6. Raw RFC 5322 Technical Headers Explorer */}
            <HeaderInspector 
              headerLines={dossier.headerLines} 
              rawHeaders={dossier.rawHeaders} 
            />
          </>
        )}

      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white px-4 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-slate-600">
            <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
            <span>AegisMail &bull; Email Threat Intelligence & Incident Response</span>
          </div>
          <div className="font-mono text-[11px] text-slate-400">
            Integrity Hash: <span className="text-blue-600 font-semibold">{dossier?.integrity?.sha256?.slice(0, 16) || 'N/A'}...</span>
          </div>
        </div>
      </footer>

      {/* Upload Modal */}
      <EmailInputModal
        isOpen={isUploadModalOpen}
        onClose={() => setIsUploadModalOpen(false)}
        onAnalyzeCustom={runAnalysis}
        isAnalyzing={isAnalyzing}
      />

      {/* Forensic Report Modal */}
      <ForensicReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        dossier={dossier}
      />

    </div>
  );
}
