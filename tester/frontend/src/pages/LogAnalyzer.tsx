import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  FileText, 
  Upload, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Sparkles, 
  Copy, 
  Check, 
  Download, 
  RefreshCw, 
  Search,
  X,
  Info
} from 'lucide-react';
import { apiClient, describeRequestError } from '../config';

interface Finding {
  severity: 'Critical' | 'Warning' | 'Info';
  message: string;
  recommendation?: string;
  matched_line?: string;
  rule_id?: string;
  category?: string;
  title?: string;
  detail?: string;
  file?: string;
  line?: number;
  count?: number;
  context?: string[];
}

interface AnalysisSummary {
  files_analyzed: number;
  files_skipped: number;
  lines_analyzed: number;
  inputs: { file: string; type: string; lines: number }[];
  counts: { Critical: number; Warning: number; Info: number };
  truncated: boolean;
}

interface AnalysisResult {
  status: string;
  findings: Finding[];
  summary?: AnalysisSummary;
}

// Archives are sent to the server as one text with a header per file.
// Lock files, build output, binaries and documentation are left out; config files
// (.env, .json, .yml) stay in because leaked credentials are often found there.
const ARCHIVE_SKIP_DIRS = ['node_modules/', '.git/', '.next/', 'dist/', 'build/', '.venv/', 'venv/', '__pycache__/', 'coverage/'];
const ARCHIVE_SKIP_FILES = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|composer\.lock|cargo\.lock|go\.sum)$/i;
const ARCHIVE_SKIP_EXT = /\.(png|jpe?g|gif|ico|svg|webp|bmp|pdf|exe|dll|zip|tar|gz|7z|rar|mp4|webm|mp3|wav|woff2?|ttf|eot|otf|bin|iso|dmg|apk|jar|class|pyc|so|dylib|map|md|markdown|min\.js|min\.css|docx?|xlsx?|pptx?)$/i;
const MAX_ARCHIVE_TEXT = 1_500_000;

const SAMPLES: Record<string, { name: string; text: string }> = {
  vulnerableCode: {
    name: 'vulnerable_auth_handler.js',
    text: `// Vulnerable Authentication & User Lookup Module
const express = require('express');
const app = express();

const AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE123";
const JWT_PRIVATE_KEY = "super-secret-unrotated-jwt-token";

app.post('/api/user/query', async (req, res) => {
  const userId = req.body.id;
  // Flaw 1: Raw SQL Injection Concatenation
  const query = "SELECT * FROM users WHERE id = '" + userId + "' AND active = 1";
  const result = await db.query(query);

  // Flaw 2: Reflected Cross-Site Scripting (XSS)
  document.getElementById('profile').innerHTML = req.body.profileHtml;

  // Flaw 3: Dangerous Remote Code Evaluation
  const evaluated = eval(req.body.expression);

  res.json({ status: 'ok', data: result });
});`
  },
  buildLog: {
    name: 'backend_build_and_dep_audit.log',
    text: `[INFO] --- maven-compiler-plugin:3.8.1:compile (default-compile) @ payment-service ---
[WARNING] /src/main/java/SecurityConfig.java:[42,12] deprecated API used: configure(HttpSecurity http)
[WARNING] Found outdated dependency: com.fasterxml.jackson.core:jackson-databind:2.9.10 (CVE-2020-36179 - Critical)
[CRITICAL] Security Scan Failed: Found hardcoded Bearer token in application.properties line 18
[ERROR] Static analysis: Insecure direct object reference (IDOR) detected in /controllers/OrderController.java
[INFO] Compilation finished with 1 error and 2 warnings.`
  },
  authAttackLog: {
    name: 'auth_firewall_audit.log',
    text: `2026-10-16 11:42:01 [WARNING] [AuthService] Failed login attempt for user 'admin' from IP 192.168.1.104
2026-10-16 11:42:02 [WARNING] [AuthService] Rapid password brute-force detected from 192.168.1.104 (5 failed attempts / 3 sec)
2026-10-16 11:42:05 [CRITICAL] [WAF] SQL injection payload detected in query parameter 'username': "' OR '1'='1' --"
2026-10-16 11:42:07 [CRITICAL] [Perimeter] Malicious token leak attempt blocked for /api/v1/internal/secrets`
  }
};

export default function LogAnalyzer() {
  const [logText, setLogText] = useState<string>('');
  const [fileName, setFileName] = useState<string>('');
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string>('');
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isDragging, setIsDragging] = useState<boolean>(false);
  
  // AI Fix state
  const [aiFixModalOpen, setAiFixModalOpen] = useState<boolean>(false);
  const [aiFixText, setAiFixText] = useState<string>('');
  const [aiLoading, setAiLoading] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);

  const processFile = async (file: File) => {
    setFileName(file.name);
    setError('');

    if (file.name.endsWith('.zip')) {
      try {
        setLogText('⚡ Decompressing and filtering code archive in browser...');
        const { unzip } = await import('fflate');
        const buffer = new Uint8Array(await file.arrayBuffer());

        const unzipped = await new Promise<Record<string, Uint8Array>>((resolve, reject) => {
          unzip(
            buffer,
            {
              filter(entry) {
                const name = entry.name.toLowerCase();
                if (name.endsWith('/')) return false;
                if (ARCHIVE_SKIP_DIRS.some((dir) => name.includes(dir))) return false;
                if (ARCHIVE_SKIP_FILES.test(name) || ARCHIVE_SKIP_EXT.test(name)) return false;
                return true;
              }
            },
            (err, data) => {
              if (err) reject(err);
              else resolve(data);
            }
          );
        });

        let extractedText = '';
        const decoder = new TextDecoder('utf-8', { fatal: false });

        for (const [name, u8] of Object.entries(unzipped)) {
          if (!u8 || u8.length === 0) continue;
          try {
            const text = decoder.decode(u8);
            extractedText += `\n--- File: ${name} ---\n` + text;
            if (extractedText.length > MAX_ARCHIVE_TEXT) {
              setError(`The archive is large: only the first ${MAX_ARCHIVE_TEXT.toLocaleString()} characters were analyzed.`);
              break;
            }
          } catch {
            // skip un-decodable binary
          }
        }

        if (!extractedText.trim()) {
          setLogText('No readable source or log text files detected in this zip archive.');
        } else {
          const finalExtracted = extractedText.trim();
          setLogText(finalExtracted);
          runAnalysis(finalExtracted, file.name);
        }
      } catch (err: any) {
        console.error('Error decompressing archive:', err);
        setError('Failed to decompress file. Please ensure it is a standard, unencrypted ZIP.');
      }
    } else {
      const reader = new FileReader();
      reader.onload = (event) => {
        const text = (event.target?.result as string) || '';
        setLogText(text);
        if (text.trim()) {
          runAnalysis(text, file.name);
        }
      };
      reader.readAsText(file);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      await processFile(file);
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      await processFile(file);
    }
  };

  const loadSample = (key: keyof typeof SAMPLES) => {
    const sample = SAMPLES[key];
    if (!sample) return;
    setFileName(sample.name);
    setLogText(sample.text);
    setError('');
    runAnalysis(sample.text, sample.name);
  };

  const runAnalysis = async (customText?: string, nameOverride?: string) => {
    const textToAnalyze = customText !== undefined ? customText : logText;
    if (!textToAnalyze.trim()) return;
    setLoading(true);
    setAnalysis(null);
    setError('');

    // Every analysis runs on the server so the same input always gives the same result.
    // The text is sent base64-encoded so code and attack strings pass through proxies intact.
    try {
      const bytes = new TextEncoder().encode(textToAnalyze);
      let binary = '';
      for (let i = 0; i < bytes.length; i += 0x8000) {
        binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      }
      const res = await apiClient.post<AnalysisResult>('/runs/analyze-manual', {
        log_text_b64: btoa(binary),
        file_name: (nameOverride ?? fileName) || undefined,
      });
      setAnalysis(res.data);
    } catch (err: any) {
      setError(describeRequestError(err, 'The analysis could not be completed. Please try again.'));
    } finally {
      setLoading(false);
    }
  };

  const generateAIFix = async () => {
    if (!analysis || analysis.findings.length === 0) return;
    setAiLoading(true);
    setAiFixModalOpen(true);
    setAiFixText('');

    try {
      const res = await apiClient.post('/runs/generate-fix', {
        findings: analysis.findings.slice(0, 15) // send top 15 findings
      });
      setAiFixText(res.data.response || 'No remediation generated.');
    } catch (err: any) {
      setAiFixText(`Failed to generate AI fix: ${err.message || err}`);
    } finally {
      setAiLoading(false);
    }
  };

  const copyFinding = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  };

  const exportPDF = async () => {
    if (!analysis) return;
    try {
      const { default: jsPDF } = await import('jspdf');
      const { default: autoTable } = await import('jspdf-autotable');

      const doc = new jsPDF();
      doc.setFontSize(18);
      doc.setTextColor(30, 41, 59);
      doc.text('Security Vulnerability & Code Quality Report', 14, 22);

      doc.setFontSize(10);
      doc.setTextColor(100, 116, 139);
      doc.text(`Target File: ${fileName || 'Manual Log Input'}`, 14, 30);
      doc.text(`Generated: ${new Date().toLocaleString()} | Overall Status: ${analysis.status}`, 14, 36);

      const tableData = analysis.findings.map(f => [
        f.severity,
        f.file && f.line ? `${f.file}:${f.line}` : '',
        f.message,
        f.recommendation || 'Review issue'
      ]);

      autoTable(doc, {
        head: [['Severity', 'Location', 'Finding', 'Remediation Advice']],
        body: tableData,
        startY: 44,
        headStyles: { fillColor: [59, 130, 246] },
        styles: { fontSize: 8, cellPadding: 3 }
      });

      doc.save(`security_audit_${Date.now()}.pdf`);
    } catch (err) {
      console.error('PDF export failed:', err);
    }
  };

  const exportCSV = () => {
    if (!analysis) return;
    const rows = [
      ['Severity', 'Rule', 'File', 'Line', 'Count', 'Finding', 'Remediation Guidance'],
      ...analysis.findings.map(f => [
        `"${f.severity}"`,
        `"${f.rule_id || ''}"`,
        `"${(f.file || '').replace(/"/g, '""')}"`,
        `"${f.line ?? ''}"`,
        `"${f.count ?? 1}"`,
        `"${(f.message || '').replace(/"/g, '""')}"`,
        `"${(f.recommendation || '').replace(/"/g, '""')}"`
      ])
    ];

    const csvContent = 'data:text/csv;charset=utf-8,' + rows.map(e => e.join(',')).join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `security_audit_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const filteredFindings = (analysis?.findings || []).filter(f => {
    const matchesSeverity = filterSeverity === 'ALL' || f.severity.toUpperCase() === filterSeverity;
    const matchesSearch = !searchQuery || f.message.toLowerCase().includes(searchQuery.toLowerCase()) || (f.recommendation && f.recommendation.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesSeverity && matchesSearch;
  });

  const criticalCount = (analysis?.findings || []).filter(f => f.severity === 'Critical').length;
  const warningCount = (analysis?.findings || []).filter(f => f.severity === 'Warning').length;
  const infoCount = (analysis?.findings || []).filter(f => f.severity === 'Info').length;
  const summary = analysis?.summary;
  const sevStyle = (sev: string) =>
    sev === 'Critical'
      ? { card: 'border-rose-200 dark:border-rose-900/40 bg-rose-50/20 dark:bg-rose-950/10', badge: 'bg-rose-100 dark:bg-rose-900/40 text-rose-600 dark:text-rose-400' }
      : sev === 'Warning'
        ? { card: 'border-amber-200 dark:border-amber-900/40 bg-amber-50/20 dark:bg-amber-950/10', badge: 'bg-amber-100 dark:bg-amber-900/40 text-amber-600 dark:text-amber-400' }
        : { card: 'border-slate-200 dark:border-slate-800', badge: 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300' };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-2.5">
            <FileText className="w-7 h-7 text-brand-500" />
            Ad-Hoc Log & Codebase Analyzer
          </h2>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            Paste a log or code, or upload a file or ZIP. Reports real errors (stack traces, failed builds and tests, crashes, HTTP 5xx, attacks) and real code risks (leaked keys, injection, XSS), each with its file and line.
          </p>
        </div>
      </div>

      {/* Input Section */}
      <div 
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={`p-6 bg-white dark:bg-slate-900 rounded-xl border transition shadow-sm space-y-4 ${
          isDragging 
            ? 'border-brand-500 bg-brand-50/10 ring-2 ring-brand-500/30 border-dashed' 
            : 'border-slate-200 dark:border-slate-800'
        }`}
      >
        {/* Quick Test Samples */}
        <div className="flex flex-wrap items-center gap-2 pb-1 border-b border-slate-100 dark:border-slate-800/60">
          <span className="text-xs font-semibold text-slate-500 dark:text-slate-400">⚡ 1-Click Test Scenarios:</span>
          <button
            type="button"
            onClick={() => loadSample('vulnerableCode')}
            className="text-xs px-2.5 py-1 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-900 rounded-md hover:bg-rose-100 dark:hover:bg-rose-900/60 transition font-medium flex items-center gap-1.5"
          >
            <span>🚨</span> Vulnerable Code (SQLi / Secrets / XSS)
          </button>
          <button
            type="button"
            onClick={() => loadSample('buildLog')}
            className="text-xs px-2.5 py-1 bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-900 rounded-md hover:bg-amber-100 dark:hover:bg-amber-900/60 transition font-medium flex items-center gap-1.5"
          >
            <span>📦</span> Build Log (CVE & Deprecations)
          </button>
          <button
            type="button"
            onClick={() => loadSample('authAttackLog')}
            className="text-xs px-2.5 py-1 bg-indigo-50 dark:bg-indigo-950/40 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-900 rounded-md hover:bg-indigo-100 dark:hover:bg-indigo-900/60 transition font-medium flex items-center gap-1.5"
          >
            <span>🛡️</span> Security Incident Log
          </button>
        </div>

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          <label className="relative cursor-pointer inline-flex items-center justify-center gap-2 px-4 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-700/60 rounded-lg text-sm font-medium text-slate-700 dark:text-slate-300 transition">
            <Upload className="w-4 h-4 text-brand-500" />
            <span>{fileName ? `File: ${fileName}` : 'Upload Code ZIP or Log File (Drag & Drop)'}</span>
            <input
              type="file"
              onChange={handleFileUpload}
              accept=".zip,.txt,.log,.out,.json,.js,.ts,.jsx,.tsx,.mjs,.cjs,.py,.java,.go,.rb,.php,.cs,.env,.yaml,.yml,.toml,.ini,.properties,.sql,.html,.sh,.ps1"
              className="sr-only"
            />
          </label>

          <div className="flex items-center gap-2">
            {logText && (
              <button
                onClick={() => { setLogText(''); setAnalysis(null); setFileName(''); setError(''); }}
                className="text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 px-2 py-1"
              >
                Clear Input
              </button>
            )}
            <button
              onClick={() => runAnalysis()}
              disabled={loading || !logText.trim()}
              className="inline-flex items-center gap-2 px-6 py-2.5 bg-brand-500 hover:bg-brand-600 text-white font-medium text-sm rounded-lg transition shadow-sm disabled:opacity-50"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" /> Analyzing...
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" /> Analyze
                </>
              )}
            </button>
          </div>
        </div>

        {error && (
          <div className="p-3 bg-rose-50 dark:bg-rose-950/50 border border-rose-200 dark:border-rose-900 text-rose-700 dark:text-rose-300 rounded-lg text-sm flex items-start gap-2">
            <AlertTriangle className="w-5 h-5 shrink-0 text-rose-500 mt-0.5" />
            <div className="flex-1">
              <p className="font-semibold">Analysis Failed</p>
              <p className="text-xs mt-0.5">{error}</p>
            </div>
            <button onClick={() => setError('')} className="text-rose-400 hover:text-rose-600 dark:hover:text-rose-200 text-xs font-bold px-1">✕</button>
          </div>
        )}

        <textarea
          rows={7}
          value={logText}
          onChange={(e) => {
            setLogText(e.target.value);
            // Typed or pasted text is no longer the uploaded file or sample: let the server
            // decide from the content whether it is a log or code.
            if (fileName) setFileName('');
          }}
          placeholder="Paste a server log, build or test output, browser console errors, or source code here (or pick a sample above)..."
          className="w-full p-4 font-mono text-xs bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 resize-y"
        />
      </div>

      {/* Analysis Results */}
      {analysis && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-5 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold uppercase text-slate-400">Scan Status</p>
                <p className={`text-2xl font-bold mt-1 ${analysis.status === 'Pass' ? 'text-emerald-500' : analysis.status === 'Warning' ? 'text-amber-500' : 'text-rose-500'}`}>
                  {analysis.status}
                </p>
              </div>
              {analysis.status === 'Pass' ? (
                <ShieldCheck className="w-10 h-10 text-emerald-500/20" />
              ) : (
                <ShieldAlert className="w-10 h-10 text-rose-500/20" />
              )}
            </div>

            <div className="p-5 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold uppercase text-slate-400">Critical / Errors</p>
                <p className="text-2xl font-bold mt-1 text-rose-500 font-mono">{criticalCount}</p>
              </div>
              <ShieldAlert className="w-10 h-10 text-rose-500/20" />
            </div>

            <div className="p-5 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold uppercase text-slate-400">Warnings</p>
                <p className="text-2xl font-bold mt-1 text-amber-500 font-mono">{warningCount}</p>
              </div>
              <AlertTriangle className="w-10 h-10 text-amber-500/20" />
            </div>
          </div>

          {summary && (
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Checked {summary.lines_analyzed.toLocaleString()} line{summary.lines_analyzed === 1 ? '' : 's'} in {summary.files_analyzed} file{summary.files_analyzed === 1 ? '' : 's'}
              {summary.inputs.length > 0 && ` (read as: ${Array.from(new Set(summary.inputs.filter(i => i.type !== 'skip').map(i => i.type))).join(', ') || 'none'})`}
              {summary.files_skipped > 0 && `; ${summary.files_skipped} lock/asset file${summary.files_skipped === 1 ? '' : 's'} skipped`}
              {infoCount > 0 && `; ${infoCount} informational note${infoCount === 1 ? '' : 's'}`}
              {summary.truncated && '; only the first 500 findings are shown'}.
            </p>
          )}

          {/* Action Toolbar */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold uppercase text-slate-400 mr-2">Filter:</span>
              {(['ALL', 'CRITICAL', 'WARNING', 'INFO'] as const).map((sev) => (
                <button
                  key={sev}
                  onClick={() => setFilterSeverity(sev)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                    filterSeverity === sev
                      ? 'bg-brand-500 text-white shadow-sm'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'
                  }`}
                >
                  {sev}
                </button>
              ))}
              <div className="relative ml-2">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
                <input
                  type="text"
                  placeholder="Search findings..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-8 pr-3 py-1 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-xs text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-brand-500 w-44"
                />
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={generateAIFix}
                disabled={analysis.findings.length === 0}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-gradient-to-r from-brand-600 to-indigo-600 hover:from-brand-500 hover:to-indigo-500 text-white text-xs font-semibold rounded-lg shadow-sm transition"
              >
                <Sparkles className="w-3.5 h-3.5" /> Generate AI Remediation
              </button>
              <button
                onClick={exportPDF}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium rounded-lg transition"
              >
                <Download className="w-3.5 h-3.5" /> PDF
              </button>
              <button
                onClick={exportCSV}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium rounded-lg transition"
              >
                <Download className="w-3.5 h-3.5" /> CSV
              </button>
            </div>
          </div>

          {/* Findings List */}
          <div className="space-y-3">
            {filteredFindings.length === 0 ? (
              <div className="p-8 text-center bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 text-slate-500 text-sm">
                {analysis.findings.length === 0
                  ? 'No errors or risks were found in this input.'
                  : 'No findings match the selected filter.'}
              </div>
            ) : (
              filteredFindings.map((finding, idx) => (
                <div
                  key={`${finding.file}-${finding.line}-${finding.rule_id}-${idx}`}
                  className={`p-4 rounded-xl border bg-white dark:bg-slate-900 shadow-sm transition ${sevStyle(finding.severity).card}`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-3 min-w-0">
                      {finding.severity === 'Critical' ? (
                        <ShieldAlert className="w-5 h-5 text-rose-500 shrink-0 mt-0.5" />
                      ) : finding.severity === 'Warning' ? (
                        <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
                      ) : (
                        <Info className="w-5 h-5 text-slate-400 shrink-0 mt-0.5" />
                      )}
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-1.5 mb-1">
                          <span className={`inline-block px-2 py-0.5 text-[10px] font-bold uppercase rounded ${sevStyle(finding.severity).badge}`}>
                            {finding.severity}
                          </span>
                          {finding.category && (
                            <span className="text-[10px] font-semibold uppercase text-slate-500 dark:text-slate-400">{finding.category}</span>
                          )}
                          {finding.file && finding.line ? (
                            <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{finding.file}:{finding.line}</span>
                          ) : null}
                          {finding.count && finding.count > 1 ? (
                            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">×{finding.count}</span>
                          ) : null}
                        </div>
                        <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                          {finding.title || finding.message}
                          {finding.detail && <span className="font-normal text-slate-700 dark:text-slate-300"> — {finding.detail}</span>}
                        </p>
                        {finding.matched_line && (
                          <pre className="mt-1.5 text-[11px] font-mono text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded px-2 py-1 overflow-x-auto whitespace-pre-wrap break-all">{finding.matched_line}</pre>
                        )}
                        {finding.context && finding.context.length > 0 && (
                          <details className="mt-1.5">
                            <summary className="text-[11px] text-slate-500 cursor-pointer">Stack / context ({finding.context.length} lines)</summary>
                            <pre className="mt-1 text-[11px] font-mono text-slate-600 dark:text-slate-400 whitespace-pre-wrap break-all">{finding.context.join('\n')}</pre>
                          </details>
                        )}
                        {finding.recommendation && (
                          <p className="text-xs text-slate-600 dark:text-slate-400 mt-1.5 leading-relaxed">
                            💡 <span className="font-medium text-slate-700 dark:text-slate-300">What to do:</span> {finding.recommendation}
                          </p>
                        )}
                      </div>
                    </div>

                    <button
                      onClick={() => copyFinding(`${finding.message}\nFix: ${finding.recommendation}`, idx)}
                      className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1.5 rounded transition shrink-0"
                      title="Copy finding details"
                    >
                      {copiedIdx === idx ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* AI Remediation Modal */}
      <AnimatePresence>
        {aiFixModalOpen && (
          <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="max-w-2xl w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]"
            >
              <div className="p-4 px-6 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-slate-800/50">
                <div className="flex items-center gap-2 text-slate-900 dark:text-white font-semibold">
                  <Sparkles className="w-5 h-5 text-brand-500" />
                  AI Security Patch Proposal
                </div>
                <button
                  onClick={() => setAiFixModalOpen(false)}
                  className="p-1 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="p-6 overflow-y-auto flex-1 font-mono text-xs leading-relaxed text-slate-800 dark:text-slate-200 bg-slate-50/50 dark:bg-slate-950/50 whitespace-pre-wrap">
                {aiLoading ? (
                  <div className="py-12 flex flex-col items-center justify-center text-slate-400">
                    <RefreshCw className="w-8 h-8 animate-spin text-brand-500 mb-3" />
                    <span>Analyzing code AST and generating security patch proposal...</span>
                  </div>
                ) : (
                  aiFixText
                )}
              </div>

              <div className="p-4 px-6 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between bg-white dark:bg-slate-900">
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(aiFixText);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 2000);
                  }}
                  disabled={aiLoading || !aiFixText}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold rounded-lg transition"
                >
                  {copied ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
                  {copied ? 'Copied!' : 'Copy Fix Code'}
                </button>
                <button
                  onClick={() => setAiFixModalOpen(false)}
                  className="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold rounded-lg transition shadow-sm"
                >
                  Close
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
