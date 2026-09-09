/**
 * MailGuard API Service
 * Connects frontend components to the Python FastAPI backend.
 */

// Base URL from environment variable, sanitized to prevent trailing slashes or duplicate /api segments
const rawBaseUrl = (import.meta.env.VITE_API_URL || '').trim();
const API_BASE_URL = rawBaseUrl.replace(/\/+$/, '').replace(/\/api$/, '');

/**
 * Helper to make JSON HTTP requests with error handling
 */
async function request(endpoint, options = {}) {
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  const url = `${API_BASE_URL}${cleanEndpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  try {
    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (!response.ok) {
      let errDetail = `HTTP ${response.status}: ${response.statusText}`;
      try {
        const errorData = await response.json();
        if (errorData.detail) {
          errDetail = typeof errorData.detail === 'string'
            ? errorData.detail
            : JSON.stringify(errorData.detail);
        }
      } catch {
        // Fallback to status text
      }
      throw new Error(errDetail);
    }

    return await response.json();
  } catch (error) {
    console.error(`API Error on [${options.method || 'GET'} ${endpoint}]:`, error);
    throw error;
  }
}

export const api = {
  // Health check
  checkHealth: () => request('/api/health'),

  // Email Analysis
  analyzeEmail: (rawEmail) =>
    request('/api/analyze', {
      method: 'POST',
      body: JSON.stringify({ raw: rawEmail }),
    }),

  // Geolocation & IP Lookups
  lookupIP: (ip) =>
    request('/api/geo/lookup', {
      method: 'POST',
      body: JSON.stringify({ ip }),
    }),

  batchLookupIPs: (ips) =>
    request('/api/geo/batch', {
      method: 'POST',
      body: JSON.stringify({ ips }),
    }),

  // Case Management
  getCases: () => request('/api/cases'),

  createCase: (data) =>
    request('/api/cases', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  getCase: (caseId) => request(`/api/cases/${caseId}`),

  updateCase: (caseId, updates) =>
    request(`/api/cases/${caseId}`, {
      method: 'PUT',
      body: JSON.stringify(updates),
    }),

  deleteCase: (caseId) =>
    request(`/api/cases/${caseId}`, {
      method: 'DELETE',
    }),

  addEmailToCase: (caseId, emailId) =>
    request(`/api/cases/${caseId}/emails`, {
      method: 'POST',
      body: JSON.stringify({ emailId }),
    }),

  // Forensic Reports
  getReports: () => request('/api/reports'),

  getReport: (reportId) => request(`/api/reports/${reportId}`),

  deleteReport: (reportId) =>
    request(`/api/reports/${reportId}`, {
      method: 'DELETE',
    }),
};

export default api;
