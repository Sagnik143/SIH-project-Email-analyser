/**
 * Email Context Provider
 * Global state management for analyzed emails, cases, and reports.
 * Fully connects to Python FastAPI backend & TinyDB database with resilient fallback.
 */

import { createContext, useContext, useReducer, useCallback, useEffect } from 'react';
import api from '../services/api';

// Fallback client-side engine modules
import { parseEmail, extractIPs, reconstructRelayPath, detectHeaderAnomalies } from '../engine/headerParser';
import { validateAuthentication } from '../engine/authValidator';
import { analyzeEmailContent } from '../engine/nlpAnalyzer';
import { analyzeLinks } from '../engine/linkAnalyzer';
import { batchLookupIPs } from '../engine/ipIntelligence';
import { analyzeDomain } from '../engine/domainIntelligence';
import { calculateThreatScore } from '../engine/threatScorer';

const EmailContext = createContext(null);

const initialState = {
  analyzedEmails: [],
  currentAnalysis: null,
  cases: [],
  isAnalyzing: false,
  analysisStep: '',
  error: null,
  backendConnected: false,
};

function emailReducer(state, action) {
  switch (action.type) {
    case 'SET_BACKEND_STATUS':
      return { ...state, backendConnected: action.connected };

    case 'SET_ANALYZING':
      return { ...state, isAnalyzing: true, analysisStep: action.step, error: null };

    case 'SET_ANALYSIS_STEP':
      return { ...state, analysisStep: action.step };

    case 'ANALYSIS_COMPLETE': {
      const newEmail = action.payload;
      const exists = state.analyzedEmails.find(e => e.id === newEmail.id);
      return {
        ...state,
        isAnalyzing: false,
        analysisStep: '',
        currentAnalysis: newEmail,
        analyzedEmails: exists
          ? state.analyzedEmails.map(e => (e.id === newEmail.id ? newEmail : e))
          : [newEmail, ...state.analyzedEmails],
      };
    }

    case 'ANALYSIS_ERROR':
      return { ...state, isAnalyzing: false, analysisStep: '', error: action.error };

    case 'SET_CURRENT_ANALYSIS':
      return { ...state, currentAnalysis: action.payload };

    case 'SET_ANALYZED_EMAILS':
      return {
        ...state,
        analyzedEmails: action.payload,
        currentAnalysis: state.currentAnalysis || (action.payload.length > 0 ? action.payload[0] : null),
      };

    case 'SET_CASES':
      return { ...state, cases: action.payload };

    case 'CREATE_CASE': {
      const newCase = {
        id: action.id || 'CASE-' + Date.now(),
        name: action.name,
        status: action.status || 'new',
        emails: action.emails || action.emailIds || [],
        notes: action.notes || '',
        tags: action.tags || [],
        createdAt: action.createdAt || new Date().toISOString(),
        updatedAt: action.updatedAt || new Date().toISOString(),
      };
      return { ...state, cases: [newCase, ...state.cases] };
    }

    case 'UPDATE_CASE':
      return {
        ...state,
        cases: state.cases.map(c =>
          c.id === action.caseId
            ? { ...c, ...action.updates, updatedAt: new Date().toISOString() }
            : c
        ),
      };

    case 'ADD_EMAIL_TO_CASE':
      return {
        ...state,
        cases: state.cases.map(c =>
          c.id === action.caseId
            ? { ...c, emails: [...(c.emails || []), action.emailId], updatedAt: new Date().toISOString() }
            : c
        ),
      };

    case 'DELETE_CASE':
      return {
        ...state,
        cases: state.cases.filter(c => c.id !== action.caseId),
      };

    case 'DELETE_ANALYSIS':
      return {
        ...state,
        analyzedEmails: state.analyzedEmails.filter(e => e.id !== action.id),
        currentAnalysis: state.currentAnalysis?.id === action.id ? null : state.currentAnalysis,
      };

    default:
      return state;
  }
}

export function EmailProvider({ children }) {
  const [state, dispatch] = useReducer(emailReducer, initialState);

  // Sync with backend & database on startup
  const reloadFromDatabase = useCallback(async () => {
    try {
      const health = await api.checkHealth();
      if (health) {
        dispatch({ type: 'SET_BACKEND_STATUS', connected: true });

        // Load persisted cases from backend database
        try {
          const remoteCases = await api.getCases();
          if (Array.isArray(remoteCases)) {
            dispatch({ type: 'SET_CASES', payload: remoteCases });
          }
        } catch (e) {
          console.warn('Failed to load cases from DB:', e);
        }

        // Load persisted reports from backend database
        try {
          const remoteReports = await api.getReports();
          if (Array.isArray(remoteReports) && remoteReports.length > 0) {
            dispatch({ type: 'SET_ANALYZED_EMAILS', payload: remoteReports });
          }
        } catch (e) {
          console.warn('Failed to load reports from DB:', e);
        }
      }
    } catch {
      dispatch({ type: 'SET_BACKEND_STATUS', connected: false });
    }
  }, []);

  useEffect(() => {
    reloadFromDatabase();
  }, [reloadFromDatabase]);

  const analyzeEmail = useCallback(async (rawEmail) => {
    try {
      dispatch({ type: 'SET_ANALYZING', step: 'Connecting to MailGuard backend...' });

      const steps = [
        'Parsing email headers & MIME structure...',
        'Reconstructing SMTP relay hops...',
        'Validating SPF, DKIM & DMARC alignment...',
        'Running NLP threat pattern analysis...',
        'Scanning URLs and calculating threat vectors...',
        'Querying IP geolocation intelligence...',
      ];

      let stepIndex = 0;
      const stepInterval = setInterval(() => {
        if (stepIndex < steps.length) {
          dispatch({ type: 'SET_ANALYSIS_STEP', step: steps[stepIndex] });
          stepIndex++;
        }
      }, 350);

      let analysis;
      try {
        // Primary: Python FastAPI backend (auto-persists in TinyDB database)
        analysis = await api.analyzeEmail(rawEmail);
        dispatch({ type: 'SET_BACKEND_STATUS', connected: true });
      } catch (backendErr) {
        console.warn('Backend API request failed, falling back to client-side engine:', backendErr);
        dispatch({ type: 'SET_BACKEND_STATUS', connected: false });

        // Fallback: Client-side engine
        const parsed = parseEmail(rawEmail);
        const ips = extractIPs(parsed.receivedHeaders);
        const relayPath = reconstructRelayPath(parsed.receivedHeaders);
        const headerAnomalies = detectHeaderAnomalies(parsed);
        const authResult = validateAuthentication(parsed);
        const nlpResult = analyzeEmailContent(parsed.subject, parsed.body, parsed.from);
        const linkResult = analyzeLinks(parsed.body);
        const ipResults = await batchLookupIPs(ips.slice(0, 5));
        const senderDomain = parsed.from?.email?.split('@')[1] || '';
        const domainResult = analyzeDomain(senderDomain);
        const threatAssessment = calculateThreatScore({
          headerAnomalies,
          authResult,
          nlpResult,
          linkResult,
          ipResults,
          domainResult,
        });

        analysis = {
          id: 'EMAIL-' + Date.now(),
          timestamp: new Date().toISOString(),
          raw: rawEmail,
          parsed,
          ips,
          relayPath,
          headerAnomalies,
          authResult,
          nlpResult,
          linkResult,
          ipResults,
          domainResult,
          threatAssessment,
        };
      } finally {
        clearInterval(stepInterval);
      }

      dispatch({ type: 'ANALYSIS_COMPLETE', payload: analysis });
      return analysis;
    } catch (error) {
      dispatch({ type: 'ANALYSIS_ERROR', error: error.message });
      throw error;
    }
  }, []);

  const createCase = useCallback(async (name, emailIds = [], notes = '', tags = []) => {
    try {
      const created = await api.createCase({ name, emails: emailIds, notes, tags });
      dispatch({ type: 'CREATE_CASE', ...created });
      return created;
    } catch {
      // Local fallback
      dispatch({ type: 'CREATE_CASE', name, emailIds, notes, tags });
    }
  }, []);

  const updateCase = useCallback(async (caseId, updates) => {
    try {
      await api.updateCase(caseId, updates);
    } catch {
      // Local fallback
    }
    dispatch({ type: 'UPDATE_CASE', caseId, updates });
  }, []);

  const deleteCase = useCallback(async (caseId) => {
    try {
      await api.deleteCase(caseId);
    } catch {
      // Local fallback
    }
    dispatch({ type: 'DELETE_CASE', caseId });
  }, []);

  const addEmailToCase = useCallback(async (caseId, emailId) => {
    try {
      await api.addEmailToCase(caseId, emailId);
    } catch {
      // Local fallback
    }
    dispatch({ type: 'ADD_EMAIL_TO_CASE', caseId, emailId });
  }, []);

  const deleteAnalysis = useCallback(async (reportId) => {
    try {
      await api.deleteReport(reportId);
    } catch {
      // Local fallback
    }
    dispatch({ type: 'DELETE_ANALYSIS', id: reportId });
  }, []);

  const value = {
    ...state,
    analyzeEmail,
    createCase,
    updateCase,
    deleteCase,
    addEmailToCase,
    deleteAnalysis,
    reloadFromDatabase,
    dispatch,
  };

  return (
    <EmailContext.Provider value={value}>
      {children}
    </EmailContext.Provider>
  );
}

export function useEmail() {
  const context = useContext(EmailContext);
  if (!context) {
    throw new Error('useEmail must be used within an EmailProvider');
  }
  return context;
}

export default EmailContext;
