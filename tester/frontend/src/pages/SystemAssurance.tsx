import { useState, useEffect } from 'react';
import { AlertTriangle, XCircle, MinusCircle } from 'lucide-react';
import { 
  Shield, 
  Cpu, 
  Activity, 
  Database, 
  Monitor, 
  CheckCircle2, 
  RefreshCw, 
  Zap, 
  Sparkles,
  Layers,
  ShieldAlert,
  Key,
  Globe,
  Package,
  Download,
  Flame,
  Boxes,
  Cloud,
  FileCheck,
  Bot
} from 'lucide-react';
import { apiClient } from '../config';

type TestStatus = 'passed' | 'warning' | 'failed' | 'skipped';

interface TestItem {
  id: string;
  name: string;
  description: string;
  status: TestStatus;
  badge_color: string;
  metric: string;
  message: string;
  duration_ms: number;
}

interface TestCategory {
  id: string;
  title: string;
  icon: string;
  status: TestStatus;
  badge_color: string;
  tests: TestItem[];
}

interface TestSuiteResponse {
  overall_status: string;
  overall_score: number;
  badge_color: string;
  total_tests: number;
  passed_tests: number;
  warning_tests?: number;
  failed_tests?: number;
  skipped_tests?: number;
  measured_tests?: number;
  duration_ms: number;
  categories: TestCategory[];
}

const STATUS_STYLES: Record<TestStatus, { label: string; badge: string; text: string; footer: string }> = {
  passed: { label: 'PASSED', badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30', text: 'text-emerald-400', footer: 'Measured this run' },
  warning: { label: 'WARNING', badge: 'bg-amber-500/20 text-amber-300 border-amber-500/30', text: 'text-amber-400', footer: 'Needs attention' },
  failed: { label: 'FAILED', badge: 'bg-red-500/20 text-red-300 border-red-500/30', text: 'text-red-400', footer: 'Check failed' },
  skipped: { label: 'NOT MEASURED', badge: 'bg-slate-500/20 text-slate-300 border-slate-500/30', text: 'text-slate-400', footer: 'Not measured here' },
};

const statusStyle = (status: string) => STATUS_STYLES[(status as TestStatus)] ?? STATUS_STYLES.skipped;

function StatusIcon({ status, className }: { status: string; className?: string }) {
  if (status === 'passed') return <CheckCircle2 className={className} />;
  if (status === 'warning') return <AlertTriangle className={className} />;
  if (status === 'failed') return <XCircle className={className} />;
  return <MinusCircle className={className} />;
}

export default function SystemAssurance() {
  const [data, setData] = useState<TestSuiteResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [lastRunTime, setLastRunTime] = useState<string>('');
  const [downloadingSbom, setDownloadingSbom] = useState<boolean>(false);
  const [loadError, setLoadError] = useState<string>('');

  const runSuite = async () => {
    setLoading(true);
    setLoadError('');
    try {
      const res = await apiClient.get<TestSuiteResponse>('/system-tests/run-all');
      setData(res.data);
      setLastRunTime(new Date().toLocaleTimeString());
    } catch (err) {
      console.error('Failed to run system test suite', err);
      setData(null);
      setLoadError('The test suite could not be run. No results are shown.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runSuite();
  }, []);

  const downloadSbom = async () => {
    setDownloadingSbom(true);
    try {
      const res = await apiClient.get('/system-tests/sbom');
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cyclonedx-sbom-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (e) {
      console.error('Failed to download SBOM', e);
    } finally {
      setDownloadingSbom(false);
    }
  };

  const getCategoryIcon = (id: string) => {
    switch (id) {
      case 'code_security':
        return <Shield className="w-5 h-5 text-emerald-400" />;
      case 'env_dependencies':
        return <Cpu className="w-5 h-5 text-emerald-400" />;
      case 'performance_stress':
        return <Activity className="w-5 h-5 text-emerald-400" />;
      case 'database_health':
        return <Database className="w-5 h-5 text-emerald-400" />;
      case 'frontend_assurance':
        return <Monitor className="w-5 h-5 text-emerald-400" />;
      case 'dast_runtime':
        return <ShieldAlert className="w-5 h-5 text-emerald-400" />;
      case 'crypto_secrets':
        return <Key className="w-5 h-5 text-emerald-400" />;
      case 'network_perimeter':
        return <Globe className="w-5 h-5 text-emerald-400" />;
      case 'supply_chain':
        return <Package className="w-5 h-5 text-emerald-400" />;
      case 'load_concurrency':
        return <Zap className="w-5 h-5 text-emerald-400" />;
      case 'chaos_resilience':
        return <Flame className="w-5 h-5 text-emerald-400" />;
      case 'container_assurance':
        return <Boxes className="w-5 h-5 text-emerald-400" />;
      case 'cloud_posture':
        return <Cloud className="w-5 h-5 text-emerald-400" />;
      case 'data_privacy':
        return <FileCheck className="w-5 h-5 text-emerald-400" />;
      case 'ai_safety':
        return <Bot className="w-5 h-5 text-emerald-400" />;
      default:
        return <Layers className="w-5 h-5 text-emerald-400" />;
    }
  };

  const overall = statusStyle(data?.overall_status ?? 'skipped');
  const headline = loadError
    ? loadError
    : !data
      ? (loading ? 'Running tests…' : 'Not run yet')
      : `${data.passed_tests} passed · ${data.warning_tests ?? 0} warnings · ${data.failed_tests ?? 0} failed · ${data.skipped_tests ?? 0} not measured`;
  const stateLabel = !data ? '—' : data.overall_status === 'passed' ? 'ALL CHECKS PASSED' : data.overall_status === 'warning' ? 'WARNINGS FOUND' : data.overall_status === 'failed' ? 'CHECKS FAILED' : 'NOT MEASURED';

  const filteredCategories = data?.categories.filter(c => 
    selectedCategory === 'all' ? true : c.id === selectedCategory
  ) || [];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-8 space-y-8">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border flex items-center gap-1.5 ${overall.badge}`}>
              {headline}
            </span>
            {lastRunTime && (
              <span className="text-xs text-slate-500">
                Last checked at {lastRunTime}
              </span>
            )}
          </div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
            System Assurance & Diagnostic Test Suite
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Live checks of this deployment. Each test reports what it measured: passed, warning, failed, or not measured.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={downloadSbom}
            disabled={downloadingSbom}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl font-medium text-sm text-slate-200 bg-slate-900 hover:bg-slate-800 border border-slate-700 transition-all shadow-sm disabled:opacity-50"
            title="Download CycloneDX v1.5 JSON Software Bill of Materials"
          >
            <Download className="w-4 h-4 text-emerald-400" />
            {downloadingSbom ? 'Generating...' : 'Export CycloneDX SBOM'}
          </button>

          <button
            onClick={runSuite}
            disabled={loading}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl font-medium text-sm text-white bg-emerald-600 hover:bg-emerald-500 transition-all shadow-lg shadow-emerald-950/40 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Executing Suite...' : 'Re-run all tests'}
          </button>
        </div>
      </div>

      {/* Hero Overview Banner (Vibrant Green) */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Overall Status Card */}
        <div className="p-6 rounded-2xl bg-gradient-to-br from-emerald-950/40 to-slate-900 border border-emerald-500/30 flex items-center gap-4">
          <div className="w-14 h-14 rounded-2xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shadow-inner">
            <CheckCircle2 className="w-8 h-8" />
          </div>
          <div>
            <div className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">System State</div>
            <div className="text-2xl font-bold text-white flex items-center gap-2">
              {stateLabel}
            </div>
            <div className="text-xs text-emerald-400/80">{data ? `${data.measured_tests ?? data.total_tests} checks measured this run` : 'No results yet'}</div>
          </div>
        </div>

        {/* Score Card */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 flex items-center gap-4">
          <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Zap className="w-7 h-7" />
          </div>
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Assurance Score</div>
            <div className="text-2xl font-bold text-emerald-400">
              {data ? `${data.overall_score}%` : '—'}
            </div>
            <div className="text-xs text-slate-400">{data ? `${data.failed_tests ?? 0} failed · ${data.warning_tests ?? 0} warnings` : 'No results yet'}</div>
          </div>
        </div>

        {/* Total Tests Card */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 flex items-center gap-4">
          <div className="w-14 h-14 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
            <Layers className="w-7 h-7" />
          </div>
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Tests Passed</div>
            <div className="text-2xl font-bold text-white">
              {data ? `${data.passed_tests} / ${data.measured_tests ?? data.total_tests}` : '—'}
            </div>
            <div className="text-xs text-slate-400">{data ? `${data.skipped_tests ?? 0} of ${data.total_tests} not measured` : 'No results yet'}</div>
          </div>
        </div>

        {/* Latency Card */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 flex items-center gap-4">
          <div className="w-14 h-14 rounded-2xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
            <Sparkles className="w-7 h-7" />
          </div>
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Suite Runtime</div>
            <div className="text-2xl font-bold text-white">
              {data?.duration_ms ?? 0} ms
            </div>
            <div className="text-xs text-slate-400">Measured this run</div>
          </div>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-2 border-b border-slate-800/80">
        <button
          onClick={() => setSelectedCategory('all')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'all'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          All Tests (35)
        </button>
        <button
          onClick={() => setSelectedCategory('chaos_resilience')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'chaos_resilience'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          📉 Chaos & Resilience (2)
        </button>
        <button
          onClick={() => setSelectedCategory('container_assurance')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'container_assurance'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          🐳 Container & Docker (2)
        </button>
        <button
          onClick={() => setSelectedCategory('cloud_posture')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'cloud_posture'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          ☁️ Cloud & IAM (2)
        </button>
        <button
          onClick={() => setSelectedCategory('data_privacy')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'data_privacy'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          🛡️ Privacy & PII (2)
        </button>
        <button
          onClick={() => setSelectedCategory('ai_safety')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'ai_safety'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          🤖 AI Safety & Patches (3)
        </button>
        <button
          onClick={() => setSelectedCategory('dast_runtime')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'dast_runtime'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          🛡️ DAST & Fuzzing (3)
        </button>
        <button
          onClick={() => setSelectedCategory('crypto_secrets')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'crypto_secrets'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          🔑 Secrets & Crypto (2)
        </button>
        <button
          onClick={() => setSelectedCategory('network_perimeter')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'network_perimeter'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          🌐 Network & Traceroute (2)
        </button>
        <button
          onClick={() => setSelectedCategory('supply_chain')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'supply_chain'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          📦 Supply Chain & SBOM (2)
        </button>
        <button
          onClick={() => setSelectedCategory('load_concurrency')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'load_concurrency'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          ⏳ Concurrency & Bottlenecks (2)
        </button>
        <button
          onClick={() => setSelectedCategory('code_security')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'code_security'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          🛡️ Code SAST (3)
        </button>
        <button
          onClick={() => setSelectedCategory('env_dependencies')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'env_dependencies'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          ⚙️ Environment (3)
        </button>
        <button
          onClick={() => setSelectedCategory('performance_stress')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'performance_stress'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          🧪 Disk I/O & Memory (3)
        </button>
        <button
          onClick={() => setSelectedCategory('database_health')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'database_health'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          🧹 Database (2)
        </button>
        <button
          onClick={() => setSelectedCategory('frontend_assurance')}
          className={`px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
            selectedCategory === 'frontend_assurance'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          🖥️ UI Assets (2)
        </button>
      </div>

      {/* Category Sections & Test Cards */}
      <div className="space-y-8">
        {filteredCategories.map((category) => (
          <div key={category.id} className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-slate-900 border border-slate-800">
                  {getCategoryIcon(category.id)}
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">{category.title}</h2>
                  <p className="text-xs text-slate-400">
                    {category.tests.length} automated tests verifying this subsystem
                  </p>
                </div>
              </div>
              <span className={`px-3 py-1 rounded-full text-xs font-semibold border flex items-center gap-1.5 ${statusStyle(category.status).badge}`}>
                <StatusIcon status={category.status} className="w-3.5 h-3.5" />
                {statusStyle(category.status).label}
              </span>
            </div>

            {/* Test Cards Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {category.tests.map((test) => (
                <div
                  key={test.id}
                  className="p-5 rounded-2xl bg-slate-900/90 border border-emerald-500/30 hover:border-emerald-400/50 transition-all flex flex-col justify-between shadow-sm relative overflow-hidden group"
                >
                  {/* Subtle green glow accent */}
                  <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-500/5 rounded-full blur-2xl group-hover:bg-emerald-500/10 transition-all pointer-events-none"></div>

                  <div className="space-y-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <div className={`w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center font-bold ${statusStyle(test.status).text}`}>
                          <StatusIcon status={test.status} className="w-5 h-5" />
                        </div>
                        <h3 className="font-semibold text-white text-sm leading-snug">
                          {test.name}
                        </h3>
                      </div>
                      <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold border whitespace-nowrap ${statusStyle(test.status).badge}`}>
                        {statusStyle(test.status).label}
                      </span>
                    </div>

                    <p className="text-xs text-slate-400 leading-relaxed">
                      {test.description}
                    </p>

                    {/* Metric pill */}
                    <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800/80">
                      <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
                        Observed Metric
                      </div>
                      <div className={`text-xs font-bold font-mono mt-0.5 ${statusStyle(test.status).text}`}>
                        {test.metric}
                      </div>
                    </div>

                    <p className="text-[12px] text-slate-300 bg-slate-950/40 p-2.5 rounded-lg border border-slate-800/50">
                      {test.message}
                    </p>
                  </div>

                  <div className="pt-4 mt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-500">
                    <span>Duration: {test.duration_ms} ms</span>
                    <span className={`font-medium ${statusStyle(test.status).text}`}>
                      {statusStyle(test.status).footer}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
