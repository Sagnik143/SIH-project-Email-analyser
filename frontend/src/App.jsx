import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import DashboardView from './components/DashboardView';
import AnalyzeEmailView from './components/AnalyzeEmailView';
import InvestigationsView from './components/InvestigationsView';
import InvestigationWorkspace from './components/InvestigationWorkspace';
import CampaignsView from './components/CampaignsView';
import ThreatIntelView from './components/ThreatIntelView';
import ReportsView from './components/ReportsView';
import SettingsView from './components/SettingsView';

import EvidenceInspectorModal from './components/EvidenceInspectorModal';
import ForensicReportModal from './components/ForensicReportModal';
import { API_BASE_URL } from './config';
import { AlertCircle } from 'lucide-react';

export default function App() {
  const [activeNav, setActiveNav] = useState('dashboard');
  const [samples, setSamples] = useState([]);
  const [selectedSampleId, setSelectedSampleId] = useState('');
  const [cases, setCases] = useState([]);
  const [casesLoading, setCasesLoading] = useState(false);

  const [dossier, setDossier] = useState(null);
  const [activeCase, setActiveCase] = useState(null);
  const [savedCaseNumber, setSavedCaseNumber] = useState(null);
  const [isSavingCase, setIsSavingCase] = useState(false);

  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState(null);

  // Modals state
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [selectedEvidence, setSelectedEvidence] = useState(null);

  // Fetch initial samples & cases on mount
  useEffect(() => {
    async function init() {
      try {
        // 1. Fetch samples
        const samplesRes = await fetch(`${API_BASE_URL}/api/samples`);
        if (samplesRes.ok) {
          const samplesData = await samplesRes.json();
          const list = samplesData.samples || [];
          setSamples(list);

          // Preload first sample into memory
          if (list.length > 0) {
            loadAndAnalyzeSample(list[0].id, false);
          }
        }

        // 2. Fetch cases
        await fetchCases();
      } catch (err) {
        console.error('Initialization error:', err);
        setError('Failed to connect to forensic backend API. Please check your network connection.');
      }
    }

    init();
  }, []);

  const fetchCases = async () => {
    setCasesLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/api/cases`);
      if (res.ok) {
        const data = await res.json();
        setCases(Array.isArray(data) ? data : data.cases || []);
      }
    } catch (err) {
      console.warn('Failed to fetch cases:', err);
    } finally {
      setCasesLoading(false);
    }
  };

  const loadAndAnalyzeSample = async (sampleId, navigateToWorkspace = true) => {
    setIsAnalyzing(true);
    setError(null);
    setSelectedSampleId(sampleId);

    try {
      const res = await fetch(`${API_BASE_URL}/api/samples/${sampleId}`);
      if (!res.ok) throw new Error('Failed to load sample dataset');
      const sample = await res.json();

      await runAnalysis(sample.rawEmail, navigateToWorkspace);
    } catch (err) {
      console.error('Sample analysis error:', err);
      setError(err.message || 'Analysis pipeline failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const runAnalysis = async (rawEmailText, navigateToWorkspace = true) => {
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
      setActiveCase(null);
      setSavedCaseNumber(null);

      if (navigateToWorkspace) {
        setActiveNav('workspace');
      }
    } catch (err) {
      console.error('Analysis error:', err);
      setError(err.message);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleOpenCase = async (caseRecord) => {
    setActiveCase(caseRecord);
    setSavedCaseNumber(caseRecord.caseNumber);

    try {
      const res = await fetch(`${API_BASE_URL}/api/cases/${caseRecord.id}`);
      if (res.ok) {
        const fullCase = await res.json();
        // If the case already has a dossier or emails, analyze or mount it
        if (fullCase.case?.dossier) {
          setDossier(fullCase.case.dossier);
        } else if (fullCase.emails?.[0]) {
          // If we have an email but need full analysis, run it
          const emailRecord = fullCase.emails[0];
          if (emailRecord.raw) {
            await runAnalysis(emailRecord.raw, true);
          } else {
            // Re-use current dossier if already active
            setActiveNav('workspace');
          }
        } else {
          setActiveNav('workspace');
        }
      } else {
        setActiveNav('workspace');
      }
    } catch (err) {
      console.error('Failed to open case details:', err);
      setActiveNav('workspace');
    }
  };

  const handleSaveActiveToCase = async () => {
    if (!dossier || savedCaseNumber || isSavingCase) return;
    setIsSavingCase(true);

    try {
      const caseTitle = dossier.envelope?.subject || 'Forensic Investigation';
      const caseRes = await fetch(`${API_BASE_URL}/api/cases`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: caseTitle, status: 'open' })
      });
      if (!caseRes.ok) throw new Error('Failed to create case');
      const newCase = await caseRes.json();

      const saveRes = await fetch(`${API_BASE_URL}/api/cases/${newCase.id}/save-analysis`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rawEmail: dossier.rawEmail || 'From: ' + (dossier.envelope?.from?.raw || ''),
          dossier,
          filename: `${newCase.caseNumber}.eml`
        })
      });
      if (!saveRes.ok) throw new Error('Failed to associate analysis with case');

      setSavedCaseNumber(newCase.caseNumber);
      setActiveCase(newCase);
      await fetchCases();
    } catch (err) {
      console.error('Case save error:', err);
      setError('Failed to persist investigation to case');
    } finally {
      setIsSavingCase(false);
    }
  };

  const handleSelectEvidence = (evIdOrObj) => {
    if (!dossier) return;
    if (typeof evIdOrObj === 'object' && evIdOrObj !== null) {
      setSelectedEvidence(evIdOrObj);
      return;
    }
    const found = (dossier.evidence || []).find(e => e.id === evIdOrObj);
    if (found) {
      setSelectedEvidence(found);
    } else {
      setSelectedEvidence({
        id: evIdOrObj,
        source: 'INVESTIGATION_ENGINE',
        field: 'Observed Telemetry',
        value: 'Authoritative evidence referenced in findings',
        collectionMethod: 'DIRECT_EXTRACTION',
        timestamp: dossier.timestamp
      });
    }
  };

  // Resolve topbar title
  let activeNavTitle = 'Dashboard';
  if (activeNav === 'analyze') activeNavTitle = 'Analyze Email';
  else if (activeNav === 'investigations') activeNavTitle = 'Investigations Repository';
  else if (activeNav === 'workspace') activeNavTitle = 'Investigation Workspace';
  else if (activeNav === 'campaigns') activeNavTitle = 'Campaigns & Correlated Activity';
  else if (activeNav === 'threat-intel') activeNavTitle = 'Threat Intelligence';
  else if (activeNav === 'reports') activeNavTitle = 'Reports & Audits';
  else if (activeNav === 'settings') activeNavTitle = 'System Settings';

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-slate-100 font-sans text-slate-800 selection:bg-blue-100 selection:text-blue-900">
      
      {/* 1. Left Sidebar Navigation */}
      <Sidebar
        activeNav={activeNav}
        onSelectNav={(navId) => setActiveNav(navId)}
        pendingCasesCount={cases.length}
      />

      {/* 2. Main Content Area */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        
        {/* Top Header */}
        <Topbar
          activeNavTitle={activeNavTitle}
          activeCaseNumber={savedCaseNumber || activeCase?.caseNumber || (dossier?.caseNumber ? dossier.caseNumber : null)}
          samples={samples}
          selectedSampleId={selectedSampleId}
          onSelectSample={(sampleId) => loadAndAnalyzeSample(sampleId, true)}
          onOpenAnalyze={() => setActiveNav('analyze')}
          onOpenReport={() => setIsReportModalOpen(true)}
          isAnalyzing={isAnalyzing}
          hasDossier={Boolean(dossier)}
        />

        {/* Scrollable View Container */}
        <main className="flex-1 overflow-y-auto p-6 md:p-8 space-y-6">
          
          {/* Error Alert */}
          {error && (
            <div className="p-4 rounded-2xl bg-rose-50 border border-rose-200 text-rose-800 text-xs flex items-center justify-between shadow-2xs">
              <div className="flex items-center gap-2.5">
                <AlertCircle className="w-5 h-5 text-rose-600 shrink-0" />
                <span>{error}</span>
              </div>
              <button
                onClick={() => setError(null)}
                className="px-3 py-1 rounded-lg bg-rose-100 hover:bg-rose-200 text-rose-800 text-xs font-semibold transition"
              >
                Dismiss
              </button>
            </div>
          )}

          {/* Active View Router */}
          {activeNav === 'dashboard' && (
            <DashboardView
              cases={cases}
              activeDossier={dossier}
              onOpenInvestigation={(c) => {
                if (c?.dossierId) setActiveNav('workspace');
                else handleOpenCase(c);
              }}
              onNavigateToAnalyze={() => setActiveNav('analyze')}
              onNavigateToReports={() => setActiveNav('reports')}
              onOpenReportModal={() => setIsReportModalOpen(true)}
            />
          )}

          {activeNav === 'analyze' && (
            <AnalyzeEmailView
              samples={samples}
              onAnalyzeRaw={(rawText) => runAnalysis(rawText, true)}
              isAnalyzing={isAnalyzing}
              error={error}
            />
          )}

          {activeNav === 'investigations' && (
            <InvestigationsView
              cases={cases}
              onOpenCase={handleOpenCase}
              onRefresh={fetchCases}
              loading={casesLoading}
            />
          )}

          {activeNav === 'workspace' && (
            <InvestigationWorkspace
              dossier={dossier}
              caseInfo={activeCase}
              onOpenReportModal={() => setIsReportModalOpen(true)}
              onSelectEvidence={handleSelectEvidence}
              onSaveToCase={handleSaveActiveToCase}
              isSavingCase={isSavingCase}
              savedCaseNumber={savedCaseNumber}
            />
          )}

          {activeNav === 'campaigns' && (
            <CampaignsView
              activeCaseNumber={savedCaseNumber || activeCase?.caseNumber || dossier?.caseNumber}
              cases={cases}
              onSelectCase={handleOpenCase}
            />
          )}

          {activeNav === 'threat-intel' && (
            <ThreatIntelView
              dossier={dossier}
            />
          )}

          {activeNav === 'reports' && (
            <ReportsView
              dossier={dossier}
              caseInfo={activeCase}
              onOpenReportModal={() => setIsReportModalOpen(true)}
            />
          )}

          {activeNav === 'settings' && (
            <SettingsView
              casesCount={cases.length}
            />
          )}

        </main>
      </div>

      {/* Global Modals */}
      <EvidenceInspectorModal
        isOpen={Boolean(selectedEvidence)}
        onClose={() => setSelectedEvidence(null)}
        evidence={selectedEvidence}
        allFindings={dossier?.findings || []}
      />

      <ForensicReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        dossier={dossier}
      />

    </div>
  );
}
