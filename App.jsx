import React, { useState, useEffect } from "react";
import { Shield, AlertTriangle, FileText, CheckCircle, Database, Server, RefreshCw } from 'lucide-react';

// Default state before fetch
const defaultScanData = {
  projectName: "Loading...",
  scannedFiles: 0,
  complianceStatus: "Pending",
  dependencies: []
};

export default function App() {
  const [scanData, setScanData] = useState(defaultScanData);
  const [isScanning, setIsScanning] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [markdownGenerated, setMarkdownGenerated] = useState(false);

  // Fetch actual scan data from our Go backend
  const fetchScanData = async () => {
    setIsScanning(true);
    try {
      const response = await fetch("http://localhost:8080/api/scan");
      const data = await response.json();
      setScanData(data);
    } catch (error) {
      console.error("Failed to fetch scan data:", error);
      setScanData({ ...defaultScanData, projectName: "Error: Is Go Server Running?" });
    } finally {
      setIsScanning(false);
    }
  };

  // Fetch on initial load
  useEffect(() => {
    fetchScanData();
  }, []);

  const handleGenerateAnnexIV = () => {
    setIsGenerating(true);
    // Simulate API call to backend to generate template
    setTimeout(() => {
      setIsGenerating(false);
      setMarkdownGenerated(true);
    }, 1500);
  };

  const getRiskBadge = (level) => {
    switch(level) {
      case 'High': return <span className="px-2 py-1 bg-red-100 text-red-700 text-xs font-bold rounded-full">HIGH RISK (EU AI Act)</span>;
      case 'Medium': return <span className="px-2 py-1 bg-yellow-100 text-yellow-700 text-xs font-bold rounded-full">MEDIUM</span>;
      default: return <span className="px-2 py-1 bg-green-100 text-green-700 text-xs font-bold rounded-full">LOW</span>;
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans p-6">
      {/* Header */}
      <header className="flex items-center justify-between bg-white p-4 rounded-xl shadow-sm border border-slate-200 mb-6">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-indigo-600" />
          <h1 className="text-xl font-bold tracking-tight">AI-BOM Compliance Automator</h1>
        </div>
        <div className="flex items-center gap-4 text-sm font-medium">
          <span className="text-slate-500">Project: <span className="text-slate-900">{scanData.projectName}</span></span>
          <button 
            onClick={fetchScanData}
            disabled={isScanning}
            className="flex items-center gap-2 bg-indigo-50 text-indigo-700 px-4 py-2 rounded-lg hover:bg-indigo-100 transition disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isScanning ? 'animate-spin' : ''}`} /> 
            {isScanning ? 'Scanning...' : 'Rescan Repository'}
          </button>
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Posture & Actions */}
        <div className="space-y-6 lg:col-span-1">
          {/* Status Card */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
            <h2 className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-4">EU AI Act Posture</h2>
            <div className="flex items-center gap-4 mb-4">
              {scanData.complianceStatus === "Passed" ? (
                <CheckCircle className="w-12 h-12 text-emerald-500" />
              ) : (
                <AlertTriangle className="w-12 h-12 text-amber-500" />
              )}
              <div>
                <p className="text-2xl font-bold">{scanData.complianceStatus}</p>
                <p className="text-sm text-slate-500">High-risk dependencies detected in production.</p>
              </div>
            </div>
            
            <div className="mt-6 border-t pt-6">
              <h3 className="text-sm font-bold text-slate-700 mb-3">Required Actions</h3>
              <ul className="space-y-3">
                <li className="flex items-start gap-2 text-sm text-slate-600">
                  <div className="mt-0.5"><div className="w-2 h-2 rounded-full bg-red-500"></div></div>
                  Article 9: Complete continuous risk mitigation matrix.
                </li>
                <li className="flex items-start gap-2 text-sm text-slate-600">
                  <div className="mt-0.5"><div className="w-2 h-2 rounded-full bg-red-500"></div></div>
                  Annex IV: Generate Technical Documentation.
                </li>
              </ul>
            </div>
          </div>

          {/* GitOps Action Card */}
          <div className="bg-indigo-600 p-6 rounded-xl shadow-sm text-white">
            <h2 className="text-lg font-bold mb-2">Automate Annex IV</h2>
            <p className="text-indigo-100 text-sm mb-6">
              Generate the required Markdown templates based on detected AST telemetry and commit them via GitOps.
            </p>
            <button 
              onClick={handleGenerateAnnexIV}
              disabled={isGenerating || markdownGenerated}
              className={`w-full py-3 rounded-lg font-bold flex justify-center items-center gap-2 transition ${
                markdownGenerated ? 'bg-indigo-800 text-indigo-300 cursor-not-allowed' : 'bg-white text-indigo-600 hover:bg-slate-50'
              }`}
            >
              {isGenerating ? <RefreshCw className="w-5 h-5 animate-spin" /> : <FileText className="w-5 h-5" />}
              {markdownGenerated ? 'Documentation Generated' : 'Generate Markdown via GitOps'}
            </button>
          </div>
        </div>

        {/* Right Column: AI-BOM Table */}
        <div className="lg:col-span-2">
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
            <div className="p-6 border-b border-slate-200 flex justify-between items-center">
              <h2 className="text-lg font-bold text-slate-800 flex items-center gap-2">
                <Database className="w-5 h-5 text-slate-400" />
                Discovered AI Bill of Materials (AI-BOM)
              </h2>
              <span className="text-sm text-slate-500">Files scanned: {scanData.scannedFiles}</span>
            </div>
            
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-50 text-slate-500 text-xs uppercase tracking-wider border-b border-slate-200">
                    <th className="p-4 font-semibold">Component</th>
                    <th className="p-4 font-semibold">Version</th>
                    <th className="p-4 font-semibold">Ecosystem</th>
                    <th className="p-4 font-semibold">Context</th>
                    <th className="p-4 font-semibold">Risk Level</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {scanData.dependencies.map((dep, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 transition">
                      <td className="p-4 font-medium text-slate-900">{dep.name}</td>
                      <td className="p-4 text-slate-500 text-sm">{dep.version}</td>
                      <td className="p-4 text-slate-500 text-sm flex items-center gap-1">
                        <Server className="w-3 h-3" /> {dep.ecosystem}
                      </td>
                      <td className="p-4 text-slate-600 text-sm">{dep.description}</td>
                      <td className="p-4">{getRiskBadge(dep.riskLevel)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          
          {/* Mock Annex IV Output Preview */}
          {markdownGenerated && (
            <div className="mt-6 bg-slate-900 rounded-xl shadow-sm border border-slate-700 overflow-hidden text-slate-300 animate-in fade-in slide-in-from-bottom-4 duration-500">
              <div className="px-4 py-2 bg-slate-800 border-b border-slate-700 flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400">docs/compliance/annex-iv.md</span>
                <span className="text-xs text-emerald-400 bg-emerald-400/10 px-2 py-1 rounded">Ready to commit</span>
              </div>
              <div className="p-6 font-mono text-sm overflow-x-auto whitespace-pre">
                {`# EU AI Act Annex IV: Technical Documentation

## 1. System Description
**System Name:** ${scanData.projectName}
**Intended Purpose:** [To be completed by engineer]

## 2. Architecture and Dependencies
The system utilizes the following pre-trained models and libraries identified via automated scan:

${scanData.dependencies.map(d => `- **${d.name}** (v${d.version}): ${d.description}`).join('\n')}

## 3. Article 9: Risk Management Framework
*Automated controls generated via CI/CD pipeline:*
- [x] Dependency version locking enforced.
- [ ] Prompt injection sanitization verified (Pending Test Coverage).
...
`}
              </div>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}