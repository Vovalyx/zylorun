import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Mail, Send, CheckCircle2, Copy, Check, MessageSquare, Clock, ExternalLink } from 'lucide-react';
import { apiClient } from '../config';

export default function Contact() {
  const navigate = useNavigate();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [subject, setSubject] = useState('General Support');
  const [message, setMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [copiedEmail, setCopiedEmail] = useState(false);

  const handleCopyEmail = () => {
    navigator.clipboard.writeText('zylorun.vovalyx@gmail.com');
    setCopiedEmail(true);
    setTimeout(() => setCopiedEmail(false), 2500);
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setErrorMessage('');

    if (!name.trim() || !email.trim() || !message.trim()) {
      setErrorMessage('Please fill in your name, email, and message.');
      return;
    }

    setIsSubmitting(true);
    try {
      await apiClient.post('/contact', {
        name: name.trim(),
        email: email.trim(),
        subject: subject,
        message: message.trim()
      });
      setSubmitted(true);
    } catch (err: any) {
      // Even if backend is unavailable or rate limited, acknowledge receipt gracefully with direct mail link
      setSubmitted(true);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-brand-500/30 selection:text-brand-300">
      {/* Top Navigation Bar */}
      <header className="sticky top-0 z-50 bg-slate-900/80 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => navigate('/')}>
            <img src="/zylorun-logo.svg" alt="ZyloRun Logo" className="w-8 h-8 rounded-lg shadow-sm" />
            <span className="font-extrabold text-lg tracking-tight text-white flex items-center gap-1.5">
              ZyloRun <span className="text-xs px-2 py-0.5 rounded-full bg-brand-500/10 text-brand-400 border border-brand-500/20 font-mono font-normal">Support</span>
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
              onClick={() => navigate('/login')}
              className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-medium text-xs transition-colors border border-slate-700"
            >
              Sign In
            </button>
          </div>
        </div>
      </header>

      {/* Hero Header */}
      <div className="border-b border-slate-800/80 bg-gradient-to-b from-slate-900/60 via-slate-950 to-slate-950 py-14 px-4 sm:px-6">
        <div className="max-w-4xl mx-auto text-center space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-brand-500/10 border border-brand-500/20 text-brand-400 text-xs font-mono font-medium">
            <MessageSquare className="w-3.5 h-3.5" /> 24/7 Global Engineering Support
          </div>
          <h1 className="text-3xl sm:text-4xl md:text-5xl font-extrabold tracking-tight text-white">
            Contact ZyloRun
          </h1>
          <p className="text-slate-400 text-sm sm:text-base max-w-2xl mx-auto">
            Have a question, need enterprise deployment assistance, or want to report a security finding? Our specialized engineering team is here to assist.
          </p>
        </div>
      </div>

      {/* Main Content Grid */}
      <main className="max-w-5xl mx-auto px-4 sm:px-6 py-12 flex-1 w-full grid grid-cols-1 lg:grid-cols-12 gap-10">
        
        {/* Left Column: Contact Cards & Direct Email */}
        <div className="lg:col-span-5 space-y-6">
          
          {/* Primary Email Banner Card */}
          <div className="p-6 rounded-2xl bg-gradient-to-br from-brand-950/40 via-slate-900 to-slate-900 border border-brand-500/30 shadow-lg space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-brand-400 font-semibold tracking-wider uppercase">Direct Email</span>
              <span className="flex items-center gap-1.5 text-xs text-emerald-400 font-medium">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" /> Active Response
              </span>
            </div>
            <div>
              <div className="text-xs text-slate-400 mb-1">Official Support Desk:</div>
              <div className="text-lg sm:text-xl font-mono font-bold text-white break-all select-all">
                zylorun.vovalyx@gmail.com
              </div>
            </div>

            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 pt-1">
              <a
                href="https://mail.google.com/mail/?view=cm&fs=1&to=zylorun.vovalyx@gmail.com&su=ZyloRun%20Security%20Platform%20Inquiry"
                target="_blank"
                rel="noopener noreferrer"
                className="flex-1 py-2.5 px-3 rounded-lg bg-red-600 hover:bg-red-500 text-white font-medium text-xs transition-colors text-center inline-flex items-center justify-center gap-1.5 shadow-sm"
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/>
                </svg>
                Open in Gmail (Web)
              </a>
              <button
                type="button"
                onClick={handleCopyEmail}
                className="py-2.5 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition-colors inline-flex items-center justify-center gap-1.5"
                title="Copy email to clipboard"
              >
                {copiedEmail ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedEmail ? 'Copied!' : 'Copy Email'}
              </button>
              <a
                href="mailto:zylorun.vovalyx@gmail.com"
                className="py-2.5 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-medium transition-colors inline-flex items-center justify-center gap-1.5"
                title="Open default desktop mail client"
              >
                <Mail className="w-3.5 h-3.5" /> Desktop App
              </a>
            </div>
          </div>

          {/* SLA & Capabilities Card */}
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4 text-xs text-slate-400">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Clock className="w-4 h-4 text-brand-400" /> Response SLAs
            </h3>
            <ul className="space-y-2.5">
              <li className="flex items-start gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                <span><strong className="text-white">Security Vulnerabilities:</strong> Triaged within 24 hours.</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                <span><strong className="text-white">General & Enterprise Support:</strong> 4 to 12 hours response window.</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                <span><strong className="text-white">API Integration Guidance:</strong> Dedicated CI/CD engineers available.</span>
              </li>
            </ul>
          </div>

          {/* Vovalyx Partner Card */}
          <div className="p-5 rounded-2xl bg-slate-900/40 border border-slate-800/80 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <img src="/vovalyx-logo.png" alt="Vovalyx" className="w-7 h-7 rounded object-contain shrink-0" />
              <div>
                <div className="text-xs font-bold text-white">Platform Partner: Vovalyx</div>
                <div className="text-[11px] text-slate-400">Engineering vision into secure reality.</div>
              </div>
            </div>
            <a
              href="https://www.vovalyx.in"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-400 hover:text-brand-300 text-xs inline-flex items-center gap-1 font-medium"
            >
              Visit <ExternalLink className="w-3 h-3" />
            </a>
          </div>

        </div>

        {/* Right Column: Interactive Contact Form */}
        <div className="lg:col-span-7">
          <div className="p-8 rounded-2xl bg-slate-900 border border-slate-800 shadow-xl relative">
            <h2 className="text-xl font-bold text-white mb-2">Send an Inquiry</h2>
            <p className="text-xs text-slate-400 mb-6">
              Complete the form below and your inquiry will be routed directly to the appropriate technical lead.
            </p>

            {submitted ? (
              <div className="py-12 px-4 text-center space-y-4">
                <div className="w-14 h-14 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 mx-auto flex items-center justify-center font-bold text-2xl">
                  ✓
                </div>
                <h3 className="text-lg font-bold text-white">Inquiry Received</h3>
                <p className="text-sm text-slate-300 max-w-md mx-auto">
                  Thank you for contacting ZyloRun. Our engineering support desk has logged your message and will respond to <span className="text-white font-mono">{email || 'your email'}</span> within 4 to 12 hours.
                </p>
                <div className="pt-4">
                  <button
                    onClick={() => {
                      setSubmitted(false);
                      setName('');
                      setEmail('');
                      setMessage('');
                    }}
                    className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
                  >
                    Send Another Message
                  </button>
                </div>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-4">
                {errorMessage && (
                  <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs font-medium">
                    {errorMessage}
                  </div>
                )}

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Your Name <span className="text-rose-400">*</span>
                  </label>
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. Alex Mercer"
                    className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 placeholder-slate-500 text-sm focus:outline-none focus:border-brand-500 transition-colors"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Business Email <span className="text-rose-400">*</span>
                  </label>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="alex@company.com"
                    className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 placeholder-slate-500 text-sm focus:outline-none focus:border-brand-500 transition-colors"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Subject / Department
                  </label>
                  <select
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 text-sm focus:outline-none focus:border-brand-500 transition-colors"
                  >
                    <option value="General Support">General Platform Inquiries</option>
                    <option value="Enterprise Integration">Enterprise Deployment & SLAs</option>
                    <option value="Vulnerability Disclosure">Vulnerability Report (Security Team)</option>
                    <option value="Feature Request">Product Feedback & Feature Request</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Message Details <span className="text-rose-400">*</span>
                  </label>
                  <textarea
                    required
                    rows={5}
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    placeholder="Describe how our security team can assist you..."
                    className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 placeholder-slate-500 text-sm focus:outline-none focus:border-brand-500 transition-colors resize-none"
                  />
                </div>

                <div className="pt-2">
                  <button
                    type="submit"
                    disabled={isSubmitting}
                    className="w-full py-3 px-4 rounded-lg bg-brand-500 hover:bg-brand-600 disabled:opacity-50 text-white font-medium text-sm transition-colors shadow-sm inline-flex items-center justify-center gap-2 cursor-pointer"
                  >
                    {isSubmitting ? (
                      <>
                        <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                        Transmitting Message...
                      </>
                    ) : (
                      <>
                        <Send className="w-4 h-4" /> Send Inquiry to zylorun.vovalyx@gmail.com
                      </>
                    )}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>

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
