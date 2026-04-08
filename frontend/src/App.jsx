import React, { useState, useEffect } from "react";
import { Shield, AlertTriangle, FileText, CheckCircle, Database, Server, RefreshCw, History, Download, DollarSign } from 'lucide-react';

// Default state before fetch
const defaultScanData = {
  projectName: "Loading...",
  scannedFiles: 0,
  complianceStatus: "Pending",
  dependencies: [],
  finOps: []
};

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8080";

export default function App() {
  const [scanData, setScanData] = useState(defaultScanData);
  const [historyData, setHistoryData] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [markdownGenerated, setMarkdownGenerated] = useState(false);
  const [historicalProof, setHistoricalProof] = useState(null);
  const [dbConfig, setDbConfig] = useState({ enabled: false, url: "", connected: false });
  const [dbConnecting, setDbConnecting] = useState(false);
  const [dbError, setDbError] = useState("");

  // Fetch DB status on load
  const fetchDbStatus = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/db-config`);
      const data = await response.json();
      setDbConfig(prev => ({ ...prev, enabled: data.connected, connected: data.connected }));
      if (data.connected) fetchHistoryData();
    } catch (error) {
      console.error("Failed to fetch DB status:", error);
    }
  };

  // Fetch historical proof drills
  const fetchHistoryData = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/history`);
      if (!response.ok) return;
      const data = await response.json();
      setHistoryData(data || []);
    } catch (error) {
      console.error("Failed to fetch history:", error);
    }
  };

  // Fetch actual scan data from our Go backend
  const fetchScanData = async () => {
    setIsScanning(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/scan`);
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
    fetchDbStatus();
  }, []);

  const fetchHistoricalProof = async (hash) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/proof?hash=${hash}`);
      if (response.ok) {
        const data = await response.json();
        setHistoricalProof({ hash, markdown: data.markdown });
        setMarkdownGenerated(false); // Hide current generated view to show history
      }
    } catch (error) {
      console.error("Failed to fetch historical proof:", error);
    }
  };

  const handleGenerateAnnexIV = async () => {
    setIsGenerating(true);
    
    try {
      if (dbConfig.connected) {
        // Send current state to the Go backend to store in Supabase
        const response = await fetch(`${API_BASE_URL}/api/save-proof`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(scanData)
        });
        
        if (response.ok) {
          setMarkdownGenerated(true);
          setHistoricalProof(null); // Clear any currently viewed history
          fetchHistoryData(); // Refresh history table after saving
        } else {
          console.error("Failed to save proof drill");
        }
      } else {
        // Local generation without database persistence
        setMarkdownGenerated(true);
        setHistoricalProof(null);
      }
    } catch (error) {
      console.error("Error generating documentation:", error);
    } finally {
      setIsGenerating(false);
    }
  };

  const getRiskBadge = (level) => {
    switch(level) {
      case 'High': return <span className="px-2 py-1 bg-red-100 text-red-700 text-xs font-bold rounded-full">HIGH RISK (EU AI Act)</span>;
      case 'Medium': return <span className="px-2 py-1 bg-yellow-100 text-yellow-700 text-xs font-bold rounded-full">MEDIUM</span>;
      default: return <span className="px-2 py-1 bg-green-100 text-green-700 text-xs font-bold rounded-full">LOW</span>;
    }
  };

  const getDisplayedMarkdown = () => {
    if (historicalProof) return historicalProof.markdown;
    return `# EU AI Act Annex IV: Technical Documentation

## 1. System Description
**System Name:** ${scanData.projectName}
**Intended Purpose:** [To be completed by engineer]

## 2. Architecture and Dependencies
The system utilizes the following pre-trained models and libraries identified via automated scan:

${scanData.dependencies.map(d => `- **${d.name}** (v${d.version}): ${d.description}${d.license ? ` [License: ${d.license}]` : ''}`).join('\n')}

## 3. Article 9: Risk Management Framework
*Automated controls generated via CI/CD pipeline:*
- [x] Dependency version locking enforced.
- [ ] Prompt injection sanitization verified (Pending Test Coverage).
...
`;
  };

  const handleDownloadMarkdown = () => {
    const content = getDisplayedMarkdown();
    const blob = new Blob([content], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = historicalProof 
      ? `annex-iv-${historicalProof.hash.substring(0, 8)}.md` 
      : "annex-iv.md";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
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
          
          {/* Database Configuration Card */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-bold text-slate-500 uppercase tracking-wider">Cloud Database</h2>
              <button 
                onClick={async () => {
                  if (dbConfig.enabled) {
                    await fetch(`${API_BASE_URL}/api/db-config`, {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ enabled: false })
                    });
                    setDbConfig({ enabled: false, url: "", connected: false });
                    setHistoryData([]);
                  } else {
                    setDbConfig({ ...dbConfig, enabled: true });
                  }
                }} 
                className={`w-10 h-5 rounded-full relative transition-colors focus:outline-none ${dbConfig.enabled ? 'bg-emerald-500' : 'bg-slate-300'}`}
              >
                <span className={`block w-3.5 h-3.5 bg-white rounded-full absolute top-0.5 transition-all ${dbConfig.enabled ? 'left-6' : 'left-1'}`}></span>
              </button>
            </div>
            
            {dbConfig.enabled && !dbConfig.connected && (
              <div className="space-y-3 mt-4 animate-in fade-in duration-300">
                <input 
                  type="text" 
                  placeholder="postgresql://postgres..."
                  className="w-full text-xs p-2 border border-slate-300 rounded focus:ring-2 focus:ring-indigo-500 outline-none font-mono"
                  value={dbConfig.url}
                  onChange={e => setDbConfig({...dbConfig, url: e.target.value, error: ""})}
                />
                {dbError && <p className="text-red-500 text-xs">{dbError}</p>}
                <button 
                  onClick={async () => {
                    setDbConnecting(true);
                    setDbError("");
                    try {
                    const res = await fetch(`${API_BASE_URL}/api/db-config`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ enabled: true, url: dbConfig.url })
                      });
                      if (!res.ok) throw new Error(await res.text());
                      setDbConfig({ ...dbConfig, connected: true });
                      fetchHistoryData();
                    } catch (e) {
                      setDbError("Invalid connection string");
                    } finally {
                      setDbConnecting(false);
                    }
                  }}
                  disabled={dbConnecting || !dbConfig.url}
                  className="w-full bg-slate-900 text-white text-sm font-medium py-2 rounded hover:bg-slate-800 disabled:opacity-50 transition"
                >
                  {dbConnecting ? 'Connecting...' : 'Connect Database'}
                </button>
              </div>
            )}
            
            {dbConfig.connected && (
              <div className="mt-4 flex items-center gap-2 text-sm text-emerald-700 bg-emerald-50 border border-emerald-100 p-3 rounded animate-in fade-in duration-300">
                <Database className="w-4 h-4" /> 
                <span className="font-medium">Connected to Supabase</span>
              </div>
            )}
            
            {!dbConfig.enabled && (
              <p className="text-xs text-slate-500 mt-2">
                Enable cloud database to persist compliance scans and generate immutable proof drills.
              </p>
            )}
          </div>

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
                    <th className="p-4 font-semibold">Location</th>
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
                      <td className="p-4 text-slate-500 text-sm font-mono">{dep.location || "N/A"}</td>
                      <td className="p-4">{getRiskBadge(dep.riskLevel)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* AI FinOps Table */}
          {scanData.finOps && scanData.finOps.length > 0 && (
            <div className="mt-6 bg-white rounded-xl shadow-sm border border-amber-200 overflow-hidden">
              <div className="p-6 border-b border-amber-100 bg-amber-50 flex justify-between items-center">
                <h2 className="text-lg font-bold text-amber-800 flex items-center gap-2">
                  <DollarSign className="w-5 h-5 text-amber-600" />
                  AI FinOps & Cloud Cost Warnings
                </h2>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-amber-50/50 text-amber-700 text-xs uppercase tracking-wider border-b border-amber-100">
                      <th className="p-4 font-semibold">Manifest / Resource</th>
                      <th className="p-4 font-semibold">Finding</th>
                      <th className="p-4 font-semibold">Location</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-amber-100">
                    {scanData.finOps.map((f, idx) => (
                      <tr key={idx} className="hover:bg-amber-50/30 transition">
                        <td className="p-4 font-medium text-slate-900">{f.resource}</td>
                        <td className="p-4 text-amber-700 text-sm flex items-start gap-2">
                          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                          {f.description}
                        </td>
                        <td className="p-4 text-slate-500 text-sm font-mono">{f.location}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          
          {/* Annex IV Output Preview (Current or Historical) */}
          {(markdownGenerated || historicalProof) && (
            <div className="mt-6 bg-slate-900 rounded-xl shadow-sm border border-slate-700 overflow-hidden text-slate-300 animate-in fade-in slide-in-from-bottom-4 duration-500">
              <div className="px-4 py-2 bg-slate-800 border-b border-slate-700 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono text-slate-400">{historicalProof ? `Historical Record (${historicalProof.hash.substring(0, 8)})` : 'docs/compliance/annex-iv.md'}</span>
                  <span className={`text-xs px-2 py-1 rounded ${historicalProof ? 'text-blue-400 bg-blue-400/10' : 'text-emerald-400 bg-emerald-400/10'}`}>{historicalProof ? 'Immutable Ledger' : 'Ready to commit'}</span>
                </div>
                <button onClick={handleDownloadMarkdown} className="text-xs flex items-center gap-1 text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 px-3 py-1 rounded transition">
                  <Download className="w-3 h-3" /> Download
                </button>
              </div>
              <div className="p-6 font-mono text-sm overflow-x-auto whitespace-pre">
                {getDisplayedMarkdown()}
              </div>
            </div>
          )}

          {/* Proof Drill Audit Ledger */}
          {dbConfig.connected && (
            <div className="mt-6 bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
            <div className="p-6 border-b border-slate-200">
              <h2 className="text-lg font-bold text-slate-800 flex items-center gap-2">
                <History className="w-5 h-5 text-slate-400" />
                Immutable Proof Drills (Audit Ledger)
              </h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-50 text-slate-500 text-xs uppercase tracking-wider border-b border-slate-200">
                    <th className="p-4 font-semibold">Timestamp</th>
                    <th className="p-4 font-semibold">Project</th>
                    <th className="p-4 font-semibold">Commit SHA</th>
                    <th className="p-4 font-semibold">Cryptographic Hash (SHA-256)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {historyData.length === 0 ? (
                    <tr><td colSpan="4" className="p-4 text-center text-slate-500 text-sm">No proof drills recorded yet.</td></tr>
                  ) : (
                    historyData.map((record, idx) => (
                      <tr key={idx} className="hover:bg-slate-100 transition cursor-pointer" onClick={() => fetchHistoricalProof(record.cryptoHash)}>
                        <td className="p-4 text-slate-600 text-sm whitespace-nowrap">{new Date(record.timestamp).toLocaleString()}</td>
                        <td className="p-4 font-medium text-slate-900">{record.projectName}</td>
                        <td className="p-4 text-slate-500 font-mono text-xs">{record.commitSha}</td>
                        <td className="p-4 text-slate-500 font-mono text-xs truncate max-w-xs" title={record.cryptoHash}>
                          {record.cryptoHash}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}