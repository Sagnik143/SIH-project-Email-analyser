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
    <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs overflow-y-auto">
      <div className="relative w-full max-w-2xl bg-white border border-slate-200 rounded-2xl shadow-2xl p-6 text-slate-800">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-100 pb-3.5 mb-4">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-blue-50 text-blue-600 border border-blue-100 flex items-center justify-center">
              <UploadCloud className="w-5 h-5" />
            </div>
            <h2 className="text-base font-bold text-slate-900">
              Analyze Custom Email Message
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-600" />
            <span>{error}</span>
          </div>
        )}

        {/* Drag and Drop Zone */}
        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          className={`border-2 border-dashed rounded-2xl p-6 text-center cursor-pointer transition mb-4 ${
            dragOver ? 'border-blue-500 bg-blue-50/60' : 'border-slate-200 hover:border-blue-400 bg-slate-50/50'
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
          <UploadCloud className="w-10 h-10 text-blue-600 mx-auto mb-2" />
          <p className="text-sm font-semibold text-slate-800">
            {selectedFile ? (
              <span className="text-blue-700 font-bold">Selected: {selectedFile.name} ({Math.round(selectedFile.size / 1024)} KB)</span>
            ) : (
              'Drag & drop an .EML or raw message file here, or click to browse'
            )}
          </p>
          <p className="text-xs text-slate-500 mt-1">
            Accepts standard RFC 822/5322 MIME messages, headers, and attachments
          </p>
        </div>

        <div className="text-center my-3 text-xs font-bold text-slate-400 uppercase tracking-wider">
          &mdash; OR PASTE RAW HEADERS & BODY &mdash;
        </div>

        {/* Raw Text Input */}
        <div className="mb-5">
          <textarea
            rows={7}
            placeholder="Received: from mail.example.com [198.51.100.1] ...&#10;From: &quot;Sender Name&quot; <sender@example.com>&#10;Subject: Urgent Notice&#10;&#10;Dear user, please click here to verify..."
            value={rawText}
            onChange={(e) => {
              setRawText(e.target.value);
              setSelectedFile(null);
            }}
            className="w-full bg-slate-50 border border-slate-200 rounded-xl p-3.5 text-xs font-mono text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:bg-white transition"
          />
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-end gap-3 border-t border-slate-100 pt-4">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-xs font-semibold text-slate-700 transition"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={isAnalyzing}
            className="flex items-center gap-2 px-5 py-2 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs font-bold shadow-xs transition"
          >
            <Play className="w-3.5 h-3.5" />
            <span>{isAnalyzing ? 'Analyzing Email...' : 'Run Security Scan'}</span>
          </button>
        </div>

      </div>
    </div>
  );
}
