import React, { useState } from 'react';
import { X, UploadCloud, FileText, Play, AlertCircle } from 'lucide-react';

export default function EmailInputModal({ isOpen, onClose, onAnalyzeCustom, isAnalyzing }) {
  const [rawText, setRawText] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState(null);

  if (!isOpen) return null;

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setError(null);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      setSelectedFile(file);
      setError(null);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = () => {
    setDragOver(false);
  };

  const handleSubmit = () => {
    if (selectedFile) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const text = event.target.result;
        onAnalyzeCustom(text);
        onClose();
      };
      reader.readAsText(selectedFile);
    } else if (rawText.trim()) {
      onAnalyzeCustom(rawText);
      onClose();
    } else {
      setError('Please paste raw email headers/body or select a .eml file to analyze.');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div className="relative w-full max-w-2xl bg-slate-950 border border-slate-700 rounded-xl shadow-2xl p-6 text-slate-200">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <UploadCloud className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold font-mono uppercase tracking-wider text-slate-100">
              Ingest Raw Email Payload
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2 font-mono">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}

        {/* Drag and Drop Zone */}
        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition mb-4 ${
            dragOver ? 'border-cyan-400 bg-cyan-950/20' : 'border-slate-800 hover:border-slate-700 bg-slate-900/30'
          }`}
          onClick={() => document.getElementById('file-upload-input').click()}
        >
          <input
            id="file-upload-input"
            type="file"
            accept=".eml,.msg,.txt"
            onChange={handleFileChange}
            className="hidden"
          />
          <UploadCloud className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
          <p className="text-xs font-mono text-slate-300">
            {selectedFile ? (
              <span className="text-cyan-400 font-bold">Selected: {selectedFile.name} ({Math.round(selectedFile.size / 1024)} KB)</span>
            ) : (
              'Drag & drop an .EML or raw email file here, or click to browse'
            )}
          </p>
          <p className="text-[10px] text-slate-500 font-mono mt-1">
            Supports RFC 822/5322 MIME messages, headers, and attachments
          </p>
        </div>

        <div className="text-center my-2 text-xs font-mono text-slate-500 uppercase">
          &mdash; OR PASTE RAW HEADERS & BODY &mdash;
        </div>

        {/* Raw Text Input */}
        <div className="mb-5">
          <textarea
            rows={8}
            placeholder="Received: from mail.example.com [198.51.100.1] ...&#10;From: &quot;Sender Name&quot; <sender@example.com>&#10;Subject: Urgent Notice&#10;&#10;Dear user, please click here to verify..."
            value={rawText}
            onChange={(e) => {
              setRawText(e.target.value);
              setSelectedFile(null);
            }}
            className="w-full bg-slate-900/80 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
          />
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-end gap-3 border-t border-slate-800 pt-4">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300 transition"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={isAnalyzing}
            className="btn-cyber flex items-center gap-2 px-5 py-2 rounded-lg text-xs font-mono font-bold"
          >
            <Play className="w-3.5 h-3.5" />
            <span>{isAnalyzing ? 'Analyzing Pipeline...' : 'Run Forensic Intelligence Scan'}</span>
          </button>
        </div>

      </div>
    </div>
  );
}
