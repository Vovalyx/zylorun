import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Shield, CheckCircle2, Mail, Key, Cpu, Server } from 'lucide-react';

export default function SecurityPolicy() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-brand-500/30 selection:text-brand-300">
      {/* Top Navigation Bar */}
      <header className="sticky top-0 z-50 bg-slate-900/80 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => navigate('/')}>
            <img src="/zylorun-logo.svg" alt="ZyloRun Logo" className="w-8 h-8 rounded-lg shadow-sm" />
            <span className="font-extrabold text-lg tracking-tight text-white flex items-center gap-1.5">
              ZyloRun <span className="text-xs px-2 py-0.5 rounded-full bg-brand-500/10 text-brand-400 border border-brand-500/20 font-mono font-normal">Trust & Security</span>
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
              Report a Vulnerability
            </button>
          </div>
        </div>
      </header>

      {/* Hero Banner */}
      <div className="border-b border-slate-800/80 bg-gradient-to-b from-slate-900/50 via-slate-950 to-slate-950 py-14 px-4 sm:px-6">
        <div className="max-w-4xl mx-auto text-center space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono font-medium">
            <Shield className="w-3.5 h-3.5" /> Security & Trust Center
          </div>
          <h1 className="text-3xl sm:text-4xl md:text-5xl font-extrabold tracking-tight text-white">
            Security & Vulnerability Disclosure
          </h1>
          <p className="text-slate-400 text-sm sm:text-base max-w-2xl mx-auto">
            Security is not just a feature at ZyloRun; it is the core foundation of our software architecture.
          </p>
          <div className="text-xs text-slate-500 font-mono pt-2">
            Last Updated: October 2026 • Security SLA: 24h Response
          </div>
        </div>
      </div>

      {/* Main Content Body */}
      <main className="max-w-4xl mx-auto px-4 sm:px-6 py-12 flex-1 space-y-12 text-slate-300 leading-relaxed text-sm sm:text-base">
        
        {/* Core Pillars */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="w-10 h-10 rounded-xl bg-brand-500/10 text-brand-400 border border-brand-500/20 flex items-center justify-center">
              <Key className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white">End-to-End Encryption</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              TLS 1.3 encryption in transit with forward secrecy. AES-256 symmetric encryption at rest for all integration tokens and secrets.
            </p>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="w-10 h-10 rounded-xl bg-brand-500/10 text-brand-400 border border-brand-500/20 flex items-center justify-center">
              <Cpu className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white">Stateless Sandboxes</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Code analysis runs inside ephemeral, hardened execution containers that are wiped immediately upon scan completion.
            </p>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="w-10 h-10 rounded-xl bg-brand-500/10 text-brand-400 border border-brand-500/20 flex items-center justify-center">
              <Server className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white">Multi-Tenant Isolation</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Strict database row-level security and JWT cryptographic identity bounds completely isolate tenant data and repositories.
            </p>
          </div>
        </div>

        {/* Responsible Disclosure Program */}
        <section className="space-y-4">
          <h2 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2">
            Responsible Vulnerability Disclosure Program (VDP)
          </h2>
          <p>
            ZyloRun welcomes contributions from independent security researchers, ethical hackers, and academic institutions. If you discover a potential vulnerability in our platform or APIs, we appreciate your help in disclosing it to us responsibly.
          </p>
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Researcher Safe Harbor Commitment
            </h3>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              We consider research conducted under our VDP guidelines to be authorized and protected under our safe harbor. We will not pursue legal action against researchers who make a good-faith effort to avoid privacy violations, data destruction, and service degradation.
            </p>
          </div>
        </section>

        {/* How to Report a Vulnerability */}
        <section className="p-8 rounded-2xl bg-gradient-to-br from-slate-900 to-slate-900/60 border border-slate-800 space-y-4">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Mail className="w-5 h-5 text-brand-400" /> Reporting Security Flaws
          </h2>
          <p className="text-sm text-slate-300">
            Please email full proof-of-concept details, reproduction steps, and severity impact directly to our dedicated security response team:
          </p>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs sm:text-sm text-brand-400 flex flex-wrap items-center justify-between gap-3">
            <span>zylorun.vovalyx@gmail.com</span>
            <div className="flex items-center gap-2">
              <a
                href="https://mail.google.com/mail/?view=cm&fs=1&to=zylorun.vovalyx@gmail.com&su=SECURITY%20VULNERABILITY%20REPORT"
                target="_blank"
                rel="noopener noreferrer"
                className="px-3 py-1.5 rounded-lg bg-brand-500 hover:bg-brand-600 text-white font-sans text-xs font-medium transition-colors"
              >
                Open in Gmail
              </a>
              <span className="text-xs text-slate-500 font-sans">SLA: 24h Triage</span>
            </div>
          </div>
          <p className="text-xs text-slate-400">
            Please include a summary of the vulnerability, affected endpoints, step-by-step reproduction instructions, and your preferred public handle for security advisory credit.
          </p>
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
