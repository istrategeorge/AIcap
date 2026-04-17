import React, { useState, useEffect } from "react";
import { Shield, AlertTriangle, FileText, CheckCircle, Database, Server, RefreshCw, History, Download, DollarSign, Key, LogOut } from 'lucide-react';
import { createClient } from '@supabase/supabase-js';

// Default state before fetch
const defaultScanData = {
  projectName: "Loading...",
  scannedFiles: 0,
  complianceStatus: "Pending",
  dependencies: [],
  finOps: []
};

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8080";
const IS_CLOUD_SAAS = API_BASE_URL !== "http://localhost:8080";

// Initialize Supabase Client
const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL || "https://placeholder.supabase.co",
  import.meta.env.VITE_SUPABASE_ANON_KEY || "placeholder"
);

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

  // Auth State
  // `session` after Wave 3b never contains a raw API key — only:
  //   accessToken: Supabase session JWT (used for every authenticated backend call)
  //   hasKey:      whether api_keys has a materialised token_hash for this user
  //   tier:        'free' | 'pro' (drives paywall)
  // The one-and-only time we know the raw key is inside `revealedKey`, which
  // is populated by a successful /api/generate-key or /api/rotate-key response
  // and cleared as soon as the user dismisses the reveal modal.
  const [session, setSession] = useState(null);
  const [revealedKey, setRevealedKey] = useState("");
  const [keyBusy, setKeyBusy] = useState(false);
  const [authForm, setAuthForm] = useState({ email: "", password: "", loading: false });
  const [isSignUp, setIsSignUp] = useState(false);
  const [isCheckoutLoading, setIsCheckoutLoading] = useState(false);

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

  // Fetch historical proof drills. Authenticated with the Supabase session
  // JWT (Wave 3b) — the backend derives user_id from the token's `sub`
  // claim and scopes the query to the caller's rows only.
  const fetchHistoryData = async (tokenOverride = "") => {
    try {
      const token = tokenOverride || (session ? session.accessToken : "");
      const headers = {};
      if (token) headers["Authorization"] = `Bearer ${token}`;

      const response = await fetch(`${API_BASE_URL}/api/history`, { headers });
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

  // Fetch and set user session.
  // After Wave 3b we no longer pull the raw token from api_keys — the column
  // doesn't exist anymore. We only read the subscription tier and whether a
  // token_hash is materialised; the plaintext key is only ever visible in
  // the response to /api/generate-key or /api/rotate-key.
  //
  // `supabaseSession` is the object returned by supabase.auth (contains
  // access_token). The backend uses that JWT to authenticate every route
  // — it derives userID from the token's `sub` claim, so request bodies
  // that claim a different user_id are ignored.
  const fetchAndSetUserSession = async (supabaseSession) => {
    const user = supabaseSession.user;
    const accessToken = supabaseSession.access_token;
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const sessionId = urlParams.get('session_id');

      // When returning from Stripe checkout the webhook can lag a few seconds.
      // Poll until subscription_tier = 'pro' appears (up to ~7.5 s) so we
      // don't show the paywall to a user who just paid.
      let row = null;
      const maxAttempts = sessionId ? 6 : 1;
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        if (attempt > 0) await new Promise(r => setTimeout(r, 1500));
        const { data: keys } = await supabase
          .from('api_keys')
          .select('token_hash, subscription_tier')
          .eq('user_id', user.id);
        row = keys && keys.length > 0 ? keys[0] : null;
        if (!sessionId || (row && row.subscription_tier === 'pro')) break;
      }

      const hasKey = !!(row && row.token_hash);
      const tier = row ? (row.subscription_tier || 'free') : 'free';

      let nextSession = { user, accessToken, hasKey, tier };

      // Post-checkout return path: the webhook has marked the user Pro
      // (token_hash still NULL), so materialise the key now and reveal it.
      if (!hasKey && sessionId) {
        try {
          const response = await fetch(`${API_BASE_URL}/api/generate-key`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${accessToken}`,
            },
          });
          if (response.ok) {
            const data = await response.json();
            setRevealedKey(data.apiKey);
            nextSession = { ...nextSession, hasKey: true };
          } else if (response.status === 409) {
            // Key already materialised by a concurrent request — acknowledge it.
            nextSession = { ...nextSession, hasKey: true };
          }
        } catch (keyError) {
          console.error("Failed to materialise API key:", keyError);
        }
        window.history.replaceState({}, document.title, "/"); // Clean up the URL
      }

      setSession(nextSession);
      fetchHistoryData(accessToken);
    } catch (error) {
      console.error("Failed to load user session:", error);
    }
  };

  // Manually materialise a key (free-tier self-signup path). Surfaces the
  // raw key via `revealedKey`; the user must copy it before dismissing.
  const handleGenerateKey = async () => {
    if (!session) return;
    setKeyBusy(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/generate-key`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${session.accessToken}`,
        },
      });
      if (response.status === 409) {
        // Someone already has a key; offer rotate instead.
        alert("An API key already exists. Use 'Rotate Key' to replace it.");
        setSession({ ...session, hasKey: true });
        return;
      }
      if (!response.ok) throw new Error(await response.text());
      const data = await response.json();
      setRevealedKey(data.apiKey);
      setSession({ ...session, hasKey: true });
    } catch (error) {
      alert(`Failed to generate key: ${error.message}`);
    } finally {
      setKeyBusy(false);
    }
  };

  // Rotate: revoke the existing key and issue a new one. One-time reveal.
  const handleRotateKey = async () => {
    if (!session) return;
    if (!window.confirm(
      "Rotating will immediately invalidate your current key. Any CI pipelines using it will start failing until you update the secret. Continue?"
    )) return;
    setKeyBusy(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/rotate-key`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${session.accessToken}`,
        },
      });
      if (!response.ok) throw new Error(await response.text());
      const data = await response.json();
      setRevealedKey(data.apiKey);
      setSession({ ...session, hasKey: true });
    } catch (error) {
      alert(`Failed to rotate key: ${error.message}`);
    } finally {
      setKeyBusy(false);
    }
  };

  // Fetch on initial load
  useEffect(() => {
    if (!IS_CLOUD_SAAS) {
      fetchScanData();
      fetchDbStatus();
    }

    if (IS_CLOUD_SAAS) {
      // onAuthStateChange fires INITIAL_SESSION on mount, covering the initial
      // load. Removing the separate getSession() call eliminates the race where
      // both fire fetchAndSetUserSession simultaneously on the checkout-return
      // URL, which caused a 409 from the second /api/generate-key attempt and
      // left the session in an inconsistent state.
      const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
        if (session && session.user) {
          fetchAndSetUserSession(session);
        } else {
          setSession(null);
        }
      });

      return () => subscription.unsubscribe();
    }
  }, []);

  const fetchHistoricalProof = async (hash) => {
    try {
      const headers = {};
      // Wave 3b: dashboard route, authenticated with the Supabase JWT.
      if (session && session.accessToken) headers["Authorization"] = `Bearer ${session.accessToken}`;

      const response = await fetch(`${API_BASE_URL}/api/proof?hash=${hash}`, { headers });
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
        // This path fires only in LOCAL developer mode (isCloudSaaS=false)
        // where the server runs without auth middleware — so no header is
        // attached. In cloud mode the dashboard never reaches this code
        // because /api/save-proof is a CI-pipeline endpoint and dbConfig
        // is gated on the local-only /api/db-config toggle.
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

  // Handle User Login/Signup
  const handleAuth = async (e) => {
    e.preventDefault();
    setAuthForm({ ...authForm, loading: true });
    
    try {
      let authError = null;
      if (isSignUp) {
        const { error } = await supabase.auth.signUp({
          email: authForm.email,
          password: authForm.password,
        });
        authError = error;
      } else {
        const { error } = await supabase.auth.signInWithPassword({
          email: authForm.email,
          password: authForm.password,
        });
        authError = error;
      }

      if (authError) throw authError;

    } catch (err) {
      alert(err.message);
    } finally {
      setAuthForm({ ...authForm, loading: false });
    }
  };

  const handleCheckout = async () => {
    setIsCheckoutLoading(true);
    try {
      // The backend derives userID + email from the verified Supabase JWT,
      // so there is no need to (and no point in) supplying them in the body.
      const response = await fetch(`${API_BASE_URL}/api/create-checkout-session`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${session.accessToken}`,
        },
      });

      if (!response.ok) {
        const errText = await response.text();
        throw new Error(`Checkout Error: ${errText}`);
      }

      const data = await response.json();
      if (data.url) {
        window.location.href = data.url; // Redirect to Stripe
      }
    } catch (error) {
      alert(error.message);
      setIsCheckoutLoading(false);
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
    return `# EU AI Act - Annex IV Technical Documentation

## 1. General System Description (Annex IV, Section 1)
- **System Name:** ${scanData.projectName}
- **Version / Commit SHA:** \`Pending CI/CD Injection\`
- **Intended Purpose:** \`[REQUIRES MANUAL INPUT: Describe the exact purpose of this AI system]\`

## 2. System Architecture & Components (Annex IV, Section 2)
### 2(a) Pre-trained Systems & Dependencies (AI-BOM)
${scanData.dependencies.length > 0 ? scanData.dependencies.map(d => `- **${d.name}** (v${d.version})${d.license ? ` [License: ${d.license}]` : ''}: ${d.description} (Risk: ${d.riskLevel})`).join('\n') : 'No AI dependencies detected.'}

### 2(c) Hardware Requirements & Deployment (FinOps Telemetry)
${scanData.finOps && scanData.finOps.length > 0 ? scanData.finOps.map(f => `- **Resource:** ${f.resource}\n  - **Finding:** ${f.description}`).join('\n') : 'No specific hardware constraints or GPU requests detected in infrastructure manifests.'}

## 3. Continuous Risk Management (Article 9 & Annex IV, Section 4)
**Current Automated Posture:** ${scanData.complianceStatus}

*Automated CI/CD Pipeline Controls:*
${scanData.complianceStatus === 'Passed' ? '- [x] High-risk dependency constraints validated.' : '- [ ] **BLOCKER:** High-risk AI dependencies detected without explicit mitigation.'}
- [ ] \`[REQUIRES MANUAL INPUT: Detail prompt injection mitigation strategy]\`

## 4. Human Oversight & Data Governance (Annex IV, Section 3)
- **Human-in-the-loop (HITL) Controls:** \`[REQUIRES MANUAL INPUT]\`
- **Training Data Provenance:** \`[REQUIRES MANUAL INPUT]\`
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
          {IS_CLOUD_SAAS && (
            <div className="flex items-center gap-3">
              <span className="px-2 py-1 bg-indigo-100 text-indigo-700 text-xs font-bold rounded">PRO CLOUD</span>
              {session && (
                <button onClick={async () => {
                  await supabase.auth.signOut();
                  setSession(null);
                }} className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-700 transition">
                  <LogOut className="w-3 h-3" /> Sign Out
                </button>
              )}
            </div>
          )}
        </div>
        {!IS_CLOUD_SAAS && (
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
        )}
      </header>

      {/* CLOUD SAAS VIEW */}
      {IS_CLOUD_SAAS ? (
        !session ? (
          /* Public Landing Page & Authentication */
          <div className="max-w-6xl mx-auto mt-8 animate-in fade-in duration-500">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
              
              {/* Marketing Copy */}
              <div className="space-y-6">
                <div className="inline-flex items-center gap-2 px-3 py-1 bg-indigo-100 text-indigo-700 text-sm font-bold rounded-full">
                  <Shield className="w-4 h-4" /> EU AI Act Ready
                </div>
                <h2 className="text-4xl lg:text-5xl font-extrabold text-slate-900 leading-tight">
                  Secure your AI supply chain. <span className="text-indigo-600">Automate compliance.</span>
                </h2>
                <p className="text-lg text-slate-600 leading-relaxed">
                  Every AI system shipped to the EU market must comply with the AI Act by August 2026. AIcap runs natively inside your CI/CD pipeline to generate your AI-BOM, track risks, and maintain an Immutable Audit Ledger.
                </p>
                <div className="space-y-4 pt-4">
                  <div className="flex items-start gap-3">
                    <CheckCircle className="w-6 h-6 text-emerald-500 shrink-0" />
                    <p className="text-slate-700"><strong>Shift-Left Compliance:</strong> Automatic Annex IV documentation generation.</p>
                  </div>
                  <div className="flex items-start gap-3">
                    <CheckCircle className="w-6 h-6 text-emerald-500 shrink-0" />
                    <p className="text-slate-700"><strong>DevSecOps Ready:</strong> Native CycloneDX SBOM & OWASP ML Top 10 enrichment.</p>
                  </div>
                  <div className="flex items-start gap-3">
                    <CheckCircle className="w-6 h-6 text-emerald-500 shrink-0" />
                    <p className="text-slate-700"><strong>FinOps Tracking:</strong> Identify expensive unoptimized GPU requests before deployment.</p>
                  </div>
                </div>
              </div>

              {/* Login/Signup Form */}
              <div className="bg-white p-8 rounded-2xl shadow-[0_8px_30px_rgb(0,0,0,0.12)] border border-slate-100 relative">
                <div className="absolute -top-6 -right-6 text-7xl opacity-5">🛡️</div>
                <div className="text-center mb-8 relative z-10">
                  <h3 className="text-2xl font-bold text-slate-900">{isSignUp ? 'Start your Pro trial' : 'Sign in to AIcap Pro'}</h3>
                  <p className="text-slate-500 text-sm mt-2">{isSignUp ? 'Generate your API key and connect your repositories.' : 'Access your immutable audit ledger.'}</p>
                </div>
                <form onSubmit={handleAuth} className="space-y-5 relative z-10">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1.5">Work Email</label>
                    <input type="email" required value={authForm.email} onChange={e => setAuthForm({...authForm, email: e.target.value})} className="w-full p-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none transition" placeholder="devsecops@company.com" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1.5">Password</label>
                    <input type="password" required value={authForm.password} onChange={e => setAuthForm({...authForm, password: e.target.value})} className="w-full p-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none transition" placeholder="••••••••" />
                  </div>
                  <button type="submit" disabled={authForm.loading} className="w-full bg-indigo-600 text-white font-bold py-3.5 rounded-lg hover:bg-indigo-700 transition disabled:opacity-50 mt-4 shadow-md shadow-indigo-200">
                    {authForm.loading ? 'Authenticating...' : (isSignUp ? 'Create Free Account' : 'Sign In')}
                  </button>
                </form>
                <div className="mt-6 text-center relative z-10">
                  <p className="text-slate-500 text-sm mb-2">
                    {isSignUp ? 'Already have an account?' : "Don't have an account yet?"}
                  </p>
                  <button onClick={() => setIsSignUp(!isSignUp)} className="text-sm text-indigo-600 hover:text-indigo-800 font-bold transition">
                    {isSignUp ? 'Sign In' : 'Sign up for AIcap Pro'}
                  </button>
                </div>
              </div>
            </div>
            
            {/* Trust/Social Proof Section */}
            <div className="mt-20 pt-10 border-t border-slate-200 text-center pb-10">
               <p className="text-sm font-bold text-slate-400 uppercase tracking-widest mb-6">Built for Modern Tech Stacks</p>
               <div className="flex flex-wrap justify-center gap-8 md:gap-16 opacity-60 grayscale filter">
                 <span className="text-xl font-bold font-mono">Python</span>
                 <span className="text-xl font-bold font-mono">Node.js</span>
                 <span className="text-xl font-bold font-mono">Golang</span>
                 <span className="text-xl font-bold font-mono">Kubernetes</span>
                 <span className="text-xl font-bold font-mono">Terraform</span>
               </div>
            </div>
          </div>
        ) : (
          session.tier !== 'pro' ? (
            /* Paywall / Upgrade Screen */
            <div className="max-w-lg mx-auto mt-16 bg-white p-8 rounded-2xl shadow-sm border border-slate-200 text-center animate-in fade-in zoom-in-95 duration-300">
              <div className="w-16 h-16 bg-amber-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <DollarSign className="w-8 h-8 text-amber-600" />
              </div>
              <h2 className="text-2xl font-bold text-slate-900 mb-2">Upgrade to AIcap Pro</h2>
              <p className="text-slate-500 text-sm mb-6">
                Unlock the Immutable Audit Ledger, GitOps pipeline integration, and automated EU AI Act Annex IV documentation sync.
              </p>
              <div className="bg-slate-50 border border-slate-100 rounded-xl p-6 mb-6 text-left">
                <ul className="space-y-3">
                  <li className="flex items-center gap-2 text-sm text-slate-700"><CheckCircle className="w-4 h-4 text-emerald-500"/> Unlimited CI/CD scans</li>
                  <li className="flex items-center gap-2 text-sm text-slate-700"><CheckCircle className="w-4 h-4 text-emerald-500"/> Cryptographic Proof Drills</li>
                  <li className="flex items-center gap-2 text-sm text-slate-700"><CheckCircle className="w-4 h-4 text-emerald-500"/> FinOps & GPU Cost Warnings</li>
                </ul>
              </div>
              <button
                onClick={handleCheckout}
                disabled={isCheckoutLoading}
                className="w-full bg-indigo-600 text-white font-bold py-3 rounded-lg hover:bg-indigo-700 transition disabled:opacity-50"
              >
                {isCheckoutLoading ? 'Redirecting to Stripe...' : 'Subscribe now for $49/mo'}
              </button>
            </div>
          ) : (
          /* Authenticated Pro Dashboard */
          <div className="space-y-6 max-w-5xl mx-auto animate-in fade-in duration-500">
            <div className="bg-indigo-600 p-8 rounded-xl shadow-sm text-white flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
              <div className="max-w-2xl">
                <h2 className="text-2xl font-bold mb-2">Welcome back, {session.user.email.split('@')[0]}</h2>
                <p className="text-indigo-100 text-sm">
                  To maintain EU AI Act compliance without exposing your proprietary source code, the AIcap scanner runs natively inside your own CI/CD infrastructure. Connect your repository using your secret API key.
                </p>
                
                <div className="mt-6 bg-slate-900/80 p-4 rounded-lg font-mono text-sm text-indigo-300 overflow-x-auto border border-indigo-500/30">
                  <p className="text-slate-500 mb-2"># Add this to your .github/workflows/build.yml</p>
                  <p><span className="text-pink-400">-</span> <span className="text-blue-400">name</span>: Run EU AI Act Compliance Scan</p>
                  <p>  <span className="text-blue-400">uses</span>: istrategeorge/AIcap@v1.0.0-beta</p>
                  <p>  <span className="text-blue-400">with</span>:</p>
                  <p>    <span className="text-blue-400">api-key</span>: {'${{ secrets.AICAP_API_KEY }}'}</p>
                </div>
              </div>
              
              {/* API Key Panel — one-time reveal model (Wave 3b).
                 The plaintext key is only ever shown once, immediately after
                 generation or rotation, and is stored nowhere the browser can
                 re-read. If the user loses it, they rotate to issue a new one
                 (which invalidates any key in their CI secrets). */}
              <div className="bg-indigo-800/50 p-5 rounded-xl border border-indigo-400/30 w-full md:w-auto shrink-0 max-w-sm">
                <div className="flex items-center gap-2 mb-3 text-indigo-100">
                  <Key className="w-4 h-4" />
                  <h3 className="text-sm font-bold uppercase tracking-wider">API Key</h3>
                </div>
                {revealedKey ? (
                  <div>
                    <code className="block bg-slate-900 text-emerald-400 px-4 py-2.5 rounded-lg text-xs select-all font-mono border border-emerald-500/40 break-all">
                      {revealedKey}
                    </code>
                    <p className="text-amber-300 text-xs mt-3 font-semibold">
                      Copy this key now. It will not be shown again.
                    </p>
                    <p className="text-indigo-200 text-xs mt-1">
                      Paste it into your GitHub repository secrets as <code className="font-mono">AICAP_API_KEY</code>.
                    </p>
                    <button
                      onClick={() => setRevealedKey("")}
                      className="mt-4 w-full bg-emerald-600 text-white text-sm font-bold py-2 rounded-lg hover:bg-emerald-700 transition"
                    >
                      I've saved the key
                    </button>
                  </div>
                ) : session.hasKey ? (
                  <div>
                    <p className="text-indigo-100 text-xs mb-3">
                      An API key is active. The raw value cannot be shown again —
                      if you lost it, rotate to issue a new one.
                    </p>
                    <button
                      onClick={handleRotateKey}
                      disabled={keyBusy}
                      className="w-full bg-slate-900/60 text-white text-sm font-bold py-2 rounded-lg hover:bg-slate-900 transition disabled:opacity-50 border border-indigo-400/30"
                    >
                      {keyBusy ? 'Rotating…' : 'Rotate Key'}
                    </button>
                  </div>
                ) : (
                  <div>
                    <p className="text-indigo-100 text-xs mb-3">
                      Generate your API key to use the AIcap GitHub Action.
                    </p>
                    <button
                      onClick={handleGenerateKey}
                      disabled={keyBusy}
                      className="w-full bg-emerald-600 text-white text-sm font-bold py-2 rounded-lg hover:bg-emerald-700 transition disabled:opacity-50"
                    >
                      {keyBusy ? 'Generating…' : 'Generate API Key'}
                    </button>
                  </div>
                )}
              </div>
            </div>

          {/* Proof Drill Audit Ledger */}
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
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
                    <tr><td colSpan="4" className="p-4 text-center text-slate-500 text-sm">No proof drills recorded yet. Install the GitHub Action to begin syncing!</td></tr>
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

          {/* Annex IV Output Preview (Historical) */}
          {historicalProof && (
            <div className="mt-6 bg-slate-900 rounded-xl shadow-sm border border-slate-700 overflow-hidden text-slate-300 animate-in fade-in slide-in-from-bottom-4 duration-500">
              <div className="px-4 py-2 bg-slate-800 border-b border-slate-700 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono text-slate-400">Historical Record ({historicalProof.hash.substring(0, 8)})</span>
                  <span className="text-xs px-2 py-1 rounded text-blue-400 bg-blue-400/10">Immutable Ledger</span>
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
        </div>
        )
      )
      ) : (
        /* LOCAL DEVELOPER VIEW */
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
      )}
    </div>
  );
}