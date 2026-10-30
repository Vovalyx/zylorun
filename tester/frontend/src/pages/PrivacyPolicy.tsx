import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Shield, Lock, CheckCircle2, Mail, ExternalLink } from 'lucide-react';

export default function PrivacyPolicy() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-brand-500/30 selection:text-brand-300">
      {/* Top Navigation Bar */}
      <header className="sticky top-0 z-50 bg-slate-900/80 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => navigate('/')}>
            <img src="/zylorun-logo.svg" alt="ZyloRun Logo" className="w-8 h-8 rounded-lg shadow-sm" />
            <span className="font-extrabold text-lg tracking-tight text-white flex items-center gap-1.5">
              ZyloRun <span className="text-xs px-2 py-0.5 rounded-full bg-brand-500/10 text-brand-400 border border-brand-500/20 font-mono font-normal">Security Cloud</span>
            </span>
          </div>

          <div className="flex items-center gap-4 text-sm">
            <button
              onClick={() => navigate('/')}
              className="inline-flex items-center gap-1.5 text-slate-400 hover:text-white transition-colors"
            >
              <ArrowLeft className="w-4 h-4" /> Back to Home
            </button>
            <button
              onClick={() => navigate('/contact')}
              className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-brand-500 hover:bg-brand-600 text-white font-medium text-xs transition-colors shadow-sm"
            >
              Contact Support
            </button>
          </div>
        </div>
      </header>

      {/* Hero Banner */}
      <div className="border-b border-slate-800/80 bg-gradient-to-b from-slate-900/50 via-slate-950 to-slate-950 py-14 px-4 sm:px-6">
        <div className="max-w-4xl mx-auto text-center space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono font-medium">
            <Shield className="w-3.5 h-3.5" /> GDPR, CCPA & ISO 27001 Aligned
          </div>
          <h1 className="text-3xl sm:text-4xl md:text-5xl font-extrabold tracking-tight text-white">
            Privacy Policy
          </h1>
          <p className="text-slate-400 text-sm sm:text-base max-w-2xl mx-auto">
            Your code, repositories, and credentials are your intellectual property. At ZyloRun, privacy and confidentiality are engineered into every layer of our security platform.
          </p>
          <div className="text-xs text-slate-500 font-mono pt-2">
            Last Updated: October 2026 • Effective Date: October 2026
          </div>
        </div>
      </div>

      {/* Main Content Body */}
      <main className="max-w-4xl mx-auto px-4 sm:px-6 py-12 flex-1 space-y-12 text-slate-300 leading-relaxed text-sm sm:text-base">
        
        {/* Code Confidentiality Callout */}
        <div className="p-6 rounded-2xl bg-slate-900 border border-brand-500/30 shadow-lg relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-64 bg-brand-500/5 rounded-full blur-3xl pointer-events-none" />
          <div className="flex items-start gap-4">
            <div className="w-10 h-10 rounded-xl bg-brand-500/10 text-brand-400 border border-brand-500/20 flex items-center justify-center shrink-0 mt-0.5">
              <Lock className="w-5 h-5" />
            </div>
            <div className="space-y-2">
              <h3 className="text-lg font-bold text-white">Our Zero-Retention Source Code Guarantee</h3>
              <p className="text-sm text-slate-300">
                ZyloRun operates a strict stateless scanning philosophy: your source code is analyzed strictly in transient memory execution sandboxes. 
                <strong> We never store your full source code on disk, we never sell your data, and we strictly never use your proprietary source code to train public machine learning or AI models.</strong>
              </p>
            </div>
          </div>
        </div>

        {/* Section 1 */}
        <section className="space-y-4">
          <h2 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2">
            1. Information We Collect
          </h2>
          <p>
            ZyloRun collects only the minimal information strictly necessary to provide automated autonomous security analysis, code risk passports, and verification services:
          </p>
          <ul className="list-disc pl-6 space-y-2 text-slate-300">
            <li>
              <strong className="text-white">Account Information:</strong> When you register or sign in, we record your username, business email address, and a cryptographically salted password hash (via bcrypt).
            </li>
            <li>
              <strong className="text-white">GitHub Connection Metadata:</strong> When you connect repositories via OAuth or Personal Access Tokens, access tokens are encrypted at rest using AES-256 before database storage. We collect repository identifiers, branch names, commit hashes, and commit messages necessary to detect changes.
            </li>
            <li>
              <strong className="text-white">Security Findings & Metrics:</strong> Vulnerability classifications, file path locations, line numbers of detected flaws, CVE descriptors, and risk scores generated during analysis.
            </li>
            <li>
              <strong className="text-white">System & Visitor Telemetry:</strong> Anonymized IP addresses, browser user agent strings, and request path latency to maintain platform availability, prevent brute-force attacks, and uphold service SLAs.
            </li>
          </ul>
        </section>

        {/* Section 2 */}
        <section className="space-y-4">
          <h2 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2">
            2. How We Use Your Information
          </h2>
          <p>
            We process data exclusively for lawful business purposes:
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1.5">
              <div className="flex items-center gap-2 text-brand-400 font-semibold text-sm">
                <CheckCircle2 className="w-4 h-4" /> Continuous Auditing
              </div>
              <p className="text-xs text-slate-400">
                To run automated SAST, secret detection, and dependency risk scans against your designated repositories.
              </p>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1.5">
              <div className="flex items-center gap-2 text-brand-400 font-semibold text-sm">
                <CheckCircle2 className="w-4 h-4" /> Risk Passport Verification
              </div>
              <p className="text-xs text-slate-400">
                To issue mathematical risk scores, release readiness gates, and automated security advisory reports.
              </p>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1.5">
              <div className="flex items-center gap-2 text-brand-400 font-semibold text-sm">
                <CheckCircle2 className="w-4 h-4" /> Abuse Prevention & Rate Limiting
              </div>
              <p className="text-xs text-slate-400">
                To defend against credential stuffing, DDoS attacks, and unauthorized target testing.
              </p>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1.5">
              <div className="flex items-center gap-2 text-brand-400 font-semibold text-sm">
                <CheckCircle2 className="w-4 h-4" /> Support & Communications
              </div>
              <p className="text-xs text-slate-400">
                To respond to inquiries directed to our official support team at <span className="text-white font-mono">zylorun.vovalyx@gmail.com</span>.
              </p>
            </div>
          </div>
        </section>

        {/* Section 3 */}
        <section className="space-y-4">
          <h2 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2">
            3. Data Retention & Right to Erasure
          </h2>
          <p>
            We adhere strictly to the principle of storage limitation:
          </p>
          <ul className="list-disc pl-6 space-y-2 text-slate-300">
            <li>
              <strong className="text-white">Transient Scans:</strong> Temporary cloned repositories in scan containers are wiped immediately upon scan completion.
            </li>
            <li>
              <strong className="text-white">User-Controlled Deletion:</strong> You may delete any repository, commit scan history, or custom target at any time from your dashboard. Deletion cascades through all related findings immediately.
            </li>
            <li>
              <strong className="text-white">Account Erasure (GDPR Article 17):</strong> Upon request to <a href="mailto:zylorun.vovalyx@gmail.com" className="text-brand-400 hover:underline">zylorun.vovalyx@gmail.com</a>, all user credentials, tokens, logs, and database records will be permanently purged within 7 business days.
            </li>
          </ul>
        </section>

        {/* Section 4 */}
        <section className="space-y-4">
          <h2 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2">
            4. Security Safeguards & Encryption
          </h2>
          <p>
            ZyloRun implements enterprise defense-in-depth security measures to protect your data:
          </p>
          <ul className="list-disc pl-6 space-y-2 text-slate-300">
            <li><strong>In Transit:</strong> All HTTP and WebSocket communications enforce TLS 1.3 encryption with modern cipher suites and HSTS headers.</li>
            <li><strong>At Rest:</strong> GitHub OAuth access tokens are stored in the database using industry-standard AES-256-GCM symmetric encryption.</li>
            <li><strong>Access Controls:</strong> Role-Based Access Control (Admin, Analyst, Viewer) isolates tenant workspaces, ensuring users cannot view other organizations' findings.</li>
          </ul>
        </section>

        {/* Section 5 */}
        <section className="space-y-4">
          <h2 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2">
            5. Cookies & Local Storage
          </h2>
          <p>
            ZyloRun utilizes browser <code className="text-brand-400 bg-slate-900 px-1.5 py-0.5 rounded text-xs font-mono">localStorage</code> solely to maintain user authentication session tokens (<code className="text-brand-400 bg-slate-900 px-1.5 py-0.5 rounded text-xs font-mono">access_token</code>) and user theme preferences. We do not use intrusive third-party cross-site advertising tracking cookies.
          </p>
        </section>

        {/* Section 6 - Official Contact Card */}
        <section className="p-8 rounded-2xl bg-gradient-to-br from-slate-900 to-slate-900/60 border border-slate-800 space-y-4">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Mail className="w-5 h-5 text-brand-400" /> 6. Privacy Inquiries & Data Protection Contact
          </h2>
          <p className="text-sm text-slate-300">
            If you have questions regarding this Privacy Policy, wish to exercise your rights under GDPR or CCPA, or need a signed Data Processing Agreement (DPA), please contact our dedicated security and compliance team:
          </p>
          <div className="pt-2 flex flex-col sm:flex-row sm:items-center gap-4">
            <a
              href="mailto:zylorun.vovalyx@gmail.com"
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-brand-500 hover:bg-brand-600 text-white font-medium text-sm transition-colors shadow-sm w-fit"
            >
              <Mail className="w-4 h-4" /> Email: zylorun.vovalyx@gmail.com
            </a>
            <a
              href="https://www.vovalyx.in"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors"
            >
              Platform Partner: Vovalyx (www.vovalyx.in) <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </section>

      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-900/60 py-8 px-4 text-center text-xs text-slate-500 space-y-2">
        <p>© 2026 ZyloRun Security Platform. Developed in partnership with Vovalyx. All rights reserved.</p>
        <div className="flex items-center justify-center gap-4 text-slate-400">
          <button onClick={() => navigate('/privacy')} className="hover:text-white underline">Privacy Policy</button>
          <span>•</span>
          <button onClick={() => navigate('/terms')} className="hover:text-white underline">Terms of Service</button>
          <span>•</span>
          <button onClick={() => navigate('/security')} className="hover:text-white underline">Security & Trust</button>
          <span>•</span>
          <button onClick={() => navigate('/contact')} className="hover:text-white underline">Contact Us</button>
        </div>
      </footer>
    </div>
  );
}
