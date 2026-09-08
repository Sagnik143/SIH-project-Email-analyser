/**
 * Email Input Component
 * Robust Drag-and-Drop + File Selector + Paste + Sample Selector
 */

import { useState, useRef, useEffect } from 'react';
import { SAMPLE_EMAILS } from '../data/sampleEmails';

export default function EmailInput({ onAnalyze, isAnalyzing }) {
  const [rawEmail, setRawEmail] = useState('');
  const [isDragOver, setIsDragOver] = useState(false);
  const [loadedFile, setLoadedFile] = useState(null);
  const [readError, setReadError] = useState(null);

  const fileInputRef = useRef(null);
  const dragCounterRef = useRef(0);

  // Handle Drag Events on the drop zone
  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounterRef.current += 1;
    if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
      setIsDragOver(true);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    e.dataTransfer.dropEffect = 'copy';
    if (!isDragOver) setIsDragOver(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounterRef.current -= 1;
    if (dragCounterRef.current <= 0) {
      setIsDragOver(false);
      dragCounterRef.current = 0;
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
    dragCounterRef.current = 0;

    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
      processFile(files[0]);
    }
  };

  const handleFileInputChange = (e) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      processFile(files[0]);
    }
    // Reset file input so re-selecting same file triggers change
    e.target.value = '';
  };

  const processFile = (file) => {
    setReadError(null);

    // Accept common email files or plain text
    const reader = new FileReader();

    reader.onload = (event) => {
      const content = event.target.result;
      if (typeof content === 'string' && content.trim().length > 0) {
        setRawEmail(content);
        setLoadedFile({
          name: file.name,
          size: (file.size / 1024).toFixed(1) + ' KB',
          type: file.type || 'message/rfc822',
        });
      } else {
        setReadError('File appears to be empty or binary.');
      }
    };

    reader.onerror = () => {
      setReadError('Failed to read file. Please ensure it is a valid text or .eml file.');
    };

    reader.readAsText(file);
  };

  const handlePasteFromClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text && text.trim()) {
        setRawEmail(text);
        setLoadedFile({ name: 'Clipboard Content', size: (new Blob([text]).size / 1024).toFixed(1) + ' KB' });
      }
    } catch {
      // Clipboard access denied, user can paste normally
    }
  };

  const loadSample = (sample) => {
    setRawEmail(sample.raw);
    setLoadedFile({
      name: `${sample.name}.eml`,
      size: (new Blob([sample.raw]).size / 1024).toFixed(1) + ' KB',
    });
    setReadError(null);
  };

  const handleClear = () => {
    setRawEmail('');
    setLoadedFile(null);
    setReadError(null);
  };

  const handleAnalyze = () => {
    if (rawEmail.trim() && onAnalyze) {
      onAnalyze(rawEmail.trim());
    }
  };

  return (
    <div className="animate-fade-in email-input-wrapper">
      {/* Sample Quick Selector */}
      <div style={{ marginBottom: '16px' }}>
        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px', fontWeight: '600' }}>
          📬 Try a sample email:
        </div>
        <div className="sample-selector">
          {SAMPLE_EMAILS.map((sample) => (
            <button
              key={sample.id}
              className="sample-btn"
              onClick={() => loadSample(sample)}
              type="button"
            >
              {sample.name}
            </button>
          ))}
        </div>
      </div>

      {/* Main Drag & Drop Zone */}
      <div
        className={`email-dropzone ${isDragOver ? 'drag-over' : ''} ${loadedFile ? 'has-file' : ''}`}
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".eml,.txt,.msg,.log"
          onChange={handleFileInputChange}
          style={{ display: 'none' }}
        />

        <div className="dropzone-content">
          <div className="dropzone-icon">
            {isDragOver ? '📥' : loadedFile ? '📄' : '📨'}
          </div>

          <div className="dropzone-text">
            {isDragOver ? (
              <span style={{ color: 'var(--accent-blue)', fontWeight: 700, fontSize: '1.05rem' }}>
                Release to drop email file...
              </span>
            ) : loadedFile ? (
              <div style={{ textAlign: 'center' }}>
                <div style={{ color: 'var(--accent-green)', fontWeight: 600, fontSize: '0.95rem' }}>
                  ✓ Loaded: {loadedFile.name} ({loadedFile.size})
                </div>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.78rem', marginTop: '4px' }}>
                  Click to choose a different file or drag another .eml file here
                </div>
              </div>
            ) : (
              <div>
                <strong>Drag & drop any .eml, .msg, or .txt file here</strong>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '4px' }}>
                  or click to browse from your computer
                </div>
              </div>
            )}
          </div>
        </div>

        {isDragOver && <div className="dropzone-glow-ring" />}
      </div>

      {readError && (
        <div style={{ marginTop: '10px', color: 'var(--danger)', fontSize: '0.82rem', padding: '8px 12px', background: 'var(--danger-dim)', borderRadius: '6px' }}>
          ⚠️ {readError}
        </div>
      )}

      {/* Raw Email Textarea Area */}
      <div style={{ marginTop: '18px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', flexWrap: 'wrap', gap: '8px' }}>
          <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: '600' }}>
            Email content (paste the full email here):
          </label>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={handlePasteFromClipboard}
              style={{ fontSize: '0.75rem', padding: '4px 10px' }}
            >
              📋 Paste Clipboard
            </button>
            {rawEmail && (
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={handleClear}
                style={{ fontSize: '0.75rem', padding: '4px 10px', color: 'var(--danger)' }}
              >
                Clear
              </button>
            )}
          </div>
        </div>

        <div style={{ position: 'relative' }}>
          <textarea
            className="textarea raw-email-textarea"
            value={rawEmail}
            onChange={(e) => setRawEmail(e.target.value)}
            onDragEnter={handleDragEnter}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            placeholder={`Paste the full email here, including headers and body, or drop a file anywhere on this box...\n\nReceived: from mail-pj1-f43.google.com ...\nFrom: \"Security Team\" <security@account-update.xyz>\nTo: target@victim.com\nSubject: Critical Account Suspension Alert\nDate: Mon, 07 Sep 2026 12:00:00 +0000\nMessage-ID: <threat-12345@domain.com>\nAuthentication-Results: spf=fail; dkim=none\n\nDear User,\nYour account will be suspended. Verify here: https://account-update.xyz/login`}
            style={{ minHeight: '260px', fontFamily: 'var(--font-mono)', fontSize: '0.82rem', lineHeight: '1.6' }}
          />

          {isDragOver && (
            <div className="textarea-drop-overlay">
              <div style={{ fontSize: '1.2rem', marginBottom: '8px' }}>📥</div>
              <strong>Drop file here to load content</strong>
            </div>
          )}
        </div>
      </div>

      {/* Action Bar */}
      <div style={{ marginTop: '16px', display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
        <button
          type="button"
          className="btn btn-primary btn-lg"
          onClick={handleAnalyze}
          disabled={!rawEmail.trim() || isAnalyzing}
          style={{ minWidth: '180px', opacity: (!rawEmail.trim() || isAnalyzing) ? 0.6 : 1 }}
        >
          {isAnalyzing ? (
            <>
              <span className="analyzing-spinner" style={{ width: '16px', height: '16px', borderWidth: '2px', margin: 0 }} />
              <span>Scanning...</span>
            </>
          ) : (
            <>🔍 Scan This Email</>
          )}
        </button>

        {rawEmail && (
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', gap: '12px' }}>
            <span>📄 {rawEmail.split('\n').length} lines</span>
            <span>•</span>
            <span>{(new Blob([rawEmail]).size / 1024).toFixed(1)} KB</span>
            <span>•</span>
            <span style={{ color: 'var(--accent-blue)' }}>Ready to scan</span>
          </div>
        )}
      </div>
    </div>
  );
}
