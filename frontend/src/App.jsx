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
import { Shield, Loader2, AlertCircle, RefreshCw, Radio } from 'lucide-react';

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
        // Fetch health & model status
        const healthRes = await fetch(`${API_BASE_URL}/api/health`);
        if (healthRes.ok) {
          const healthData = await healthRes.json();
          if (healthData.primaryModel) setOpenrouterModel(healthData.primaryModel);
        }

        // Fetch threat sample datasets
        const samplesRes = await fetch(`${API_BASE_URL}/api/samples`);
        if (samplesRes.ok) {
          const samplesData = await samplesRes.json();
          const list = samplesData.samples || [];
          setSamples(list);

          // Auto-load first sample (BEC Wire Transfer)
          if (list.length > 0) {
            loadAndAnalyzeSample(list[0].id);
          }
        }
      } catch (err) {
        console.error('Initialization error:', err);
        setError('Failed to connect to backend forensic server. Ensure API is running on port 5001.');
      }
    }

    init();
  }, []);

  const loadAndAnalyzeSample = async (sampleId) => {
    setIsAnalyzing(true);
    setError(null);
    setSelectedSampleId(sampleId);

    try {
      // Fetch sample raw content
      const res = await fetch(`${API_BASE_URL}/api/samples/${sampleId}`);
      if (!res.ok) throw new Error('Failed to load sample dataset');
      const sample = await res.json();

      // Analyze email
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
    <div className="min-h-screen flex flex-col bg-[#070a12] text-slate-100 font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      
      {/* Top Application Header */}
      <Header
        samples={samples}
        selectedSampleId={selectedSampleId}
        onSelectSample={loadAndAnalyzeSample}
        onOpenUploadModal={() => setIsUploadModalOpen(true)}
        onOpenReportModal={() => setIsReportModalOpen(true)}
        isAnalyzing={isAnalyzing}
        openrouterModel={openrouterModel}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 lg:px-8 py-6 space-y-6">
        
        {/* Error Alert */}
        {error && (
          <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center justify-between shadow-lg">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-5 h-5 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
            <button
              onClick={() => selectedSampleId && loadAndAnalyzeSample(selectedSampleId)}
              className="px-2.5 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 text-xs transition"
            >
              Retry
            </button>
          </div>
        )}

        {/* Loading State Overlay */}
        {isAnalyzing && (
          <div className="p-8 rounded-xl glass-panel text-center flex flex-col items-center justify-center space-y-3 glow-border-cyan">
            <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
            <div className="font-mono text-sm font-bold text-cyan-300">
              EXECUTING DEEP FORENSIC THREAT PIPELINE...
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Parsing RFC MIME structure &bull; Tracing SMTP relay hops &bull; Geocoding IP origin &bull; OpenRouter LLM Evaluation
            </p>
          </div>
        )}

        {/* Dashboard Panels (when dossier is ready) */}
        {!isAnalyzing && dossier && (
          <>
            {/* 1. Primary Threat Score & Incident Attribution */}
            <ThreatScoreCard dossier={dossier} />

            {/* 2. Interactive Geo Relay Map & Relay Hop Timeline */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-7">
                <GeoRelayMap relay={dossier.relay} originGeo={dossier.originGeo} />
              </div>
              <div className="lg:col-span-5">
                <RelayTimeline relay={dossier.relay} />
              </div>
            </div>

            {/* 3. AI Forensic Intelligence & Social Engineering Analysis */}
            <AIIntelligenceCard aiThreatIntelligence={dossier.aiThreatIntelligence} />

            {/* 4. Sender Authentication Matrix (SPF, DKIM, DMARC, Spoofing, Lookalikes) */}
            <AuthMatrix authentication={dossier.authentication} envelope={dossier.envelope} />

            {/* 5. Indicators of Compromise (IoC) Vault */}
            <IoCVault iocs={dossier.iocs} />

            {/* 6. Raw RFC 5322 Header Explorer */}
            <HeaderInspector 
              headerLines={dossier.headerLines} 
              rawHeaders={dossier.rawHeaders} 
            />
          </>
        )}

      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 px-4 py-4 text-center text-xs font-mono text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-slate-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>AEGIS // Digital Forensics & Incident Response Platform</span>
          </div>
          <div>
            Integrity Hash: <span className="text-cyan-400">{dossier?.integrity?.sha256?.slice(0, 16) || 'N/A'}...</span>
          </div>
        </div>
      </footer>

      {/* Upload / Ingest Modal */}
      <EmailInputModal
        isOpen={isUploadModalOpen}
        onClose={() => setIsUploadModalOpen(false)}
        onAnalyzeCustom={runAnalysis}
        isAnalyzing={isAnalyzing}
      />

      {/* Forensic Report Dossier Modal */}
      <ForensicReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        dossier={dossier}
      />

    </div>
  );
}
