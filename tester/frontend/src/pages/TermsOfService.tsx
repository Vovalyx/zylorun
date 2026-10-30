import { useNavigate } from 'react-router-dom';
import { ArrowLeft, FileText, AlertTriangle, Mail, ExternalLink } from 'lucide-react';

export default function TermsOfService() {
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
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-brand-500/10 border border-brand-500/20 text-brand-400 text-xs font-mono font-medium">
            <FileText className="w-3.5 h-3.5" /> Platform Governance Agreement
          </div>
          <h1 className="text-3xl sm:text-4xl md:text-5xl font-extrabold tracking-tight text-white">
            Terms of Service
          </h1>
          <p className="text-slate-400 text-sm sm:text-base max-w-2xl mx-auto">
            Please read these Terms of Service carefully before utilizing the ZyloRun Autonomous Risk & Assurance platform.
          </p>
          <div className="text-xs text-slate-500 font-mono pt-2">
            Last Updated: October 2026 • Effective Date: October 2026
          </div>
        </div>
      </div>

      {/* Main Content Body */}
      <main className="max-w-4xl mx-auto px-4 sm:px-6 py-12 flex-1 space-y-12 text-slate-300 leading-relaxed text-sm sm:text-base">
        
        {/* Acceptable Use Security Warning */}
        <div className="p-6 rounded-2xl bg-amber-500/5 border border-amber-500/20 shadow-lg relative overflow-hidden">
          <div className="flex items-start gap-4">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20 flex items-center justify-center shrink-0 mt-0.5">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div className="space-y-2">
              <h3 className="text-lg font-bold text-white">Authorized Testing Requirement</h3>
              <p className="text-sm text-slate-300">
                ZyloRun is engineered exclusively for defensive software assurance, vulnerability remediation, and authorized penetration diagnostics. 
                <strong> You strictly agree to only test, scan, or audit source code, network endpoints, and repositories that you own or have explicit, documented authorization to assess.</strong>
              </p>
            </div>
          </div>
        </div>

        {/* Section 1 */}
        <section className="space-y-4">
          <h2 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2">
            1. Acceptance of Terms
          </h2>
          <p>
            By accessing, creating an account, or interacting with ZyloRun (the "Service"), you agree to be bound by these Terms of Service and our Privacy Policy. If you are entering into this agreement on behalf of a company or legal entity, you represent that you possess the authority to bind such entity.
          </p>
        </section>

        {/* Section 2 */}
        <section className="space-y-4">
          <h2 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2">
            2. Permitted Use & Prohibited Activities
          </h2>
          <p>
            You agree to use the Service in full compliance with all applicable local, national, and international cybersecurity regulations. You strictly agree NOT to:
          </p>
          <ul className="list-disc pl-6 space-y-2 text-slate-300">
            <li>Launch denial of service (DoS/DDoS) attacks or deliberately overload third-party network services.</li>
            <li>Scan, probe, or fuzz any domain, API, or infrastructure without explicit permission from the target owner.</li>
            <li>Use the Service to reverse engineer, clone, or build competitive commercial exploit tools.</li>
            <li>Attempt to bypass API rate limits, authentication barriers, or tenant isolation controls.</li>
          </ul>
        </section>

        {/* Section 3 */}
        <section className="space-y-4">
          <h2 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2">
            3. Intellectual Property & Code Ownership
          </h2>
          <p>
            <strong className="text-white">You retain complete ownership:</strong> You and your licensors retain 100% of all right, title, and interest (including all patent, copyright, and trade secret rights) in and to your source code, configuration files, and repository contents analyzed through ZyloRun. 
            ZyloRun acquires no intellectual property rights in your customer software.
          </p>
        </section>

        {/* Section 4 */}
        <section className="space-y-4">
          <h2 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2">
            4. Service Availability & Rate Limits
          </h2>
          <p>
            To maintain service resilience across thousands of concurrent organizations, ZyloRun enforces automated request rate limits and fair-use quotas on API routes and background scans. We strive to maintain 99.9% uptime, excluding planned maintenance windows.
          </p>
        </section>

        {/* Section 5 */}
        <section className="space-y-4">
          <h2 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2">
            5. Disclaimer of Warranties & Limitation of Liability
          </h2>
          <p>
            ZyloRun provides static application security testing (SAST), software composition analysis (SCA), and diagnostic risk passports on an "AS IS" and "AS AVAILABLE" basis. While our algorithms provide rigorous vulnerability detection, no automated security scanner can guarantee the absence of all zero-day vulnerabilities or security flaws. 
            ZyloRun recommends a defense-in-depth posture including peer review and manual penetration testing.
          </p>
        </section>

        {/* Section 6 - Contact Support */}
        <section className="p-8 rounded-2xl bg-gradient-to-br from-slate-900 to-slate-900/60 border border-slate-800 space-y-4">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Mail className="w-5 h-5 text-brand-400" /> 6. Inquiries & Legal Notices
          </h2>
          <p className="text-sm text-slate-300">
            For all questions regarding these Terms, enterprise service level agreements (SLAs), or customized licensing:
          </p>
          <div className="pt-2 flex flex-col sm:flex-row sm:items-center gap-4">
            <a
              href="https://mail.google.com/mail/?view=cm&fs=1&to=zylorun.vovalyx@gmail.com&su=ZyloRun%20Terms%20%26%20Licensing%20Inquiry"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-brand-500 hover:bg-brand-600 text-white font-medium text-sm transition-colors shadow-sm w-fit"
            >
              <Mail className="w-4 h-4" /> Open in Gmail: zylorun.vovalyx@gmail.com
            </a>
            <a
              href="mailto:zylorun.vovalyx@gmail.com"
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-sm transition-colors border border-slate-700 w-fit"
            >
              Default Mail App
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
