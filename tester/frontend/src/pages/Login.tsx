import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Eye, EyeOff, KeyRound, CheckCircle2, ArrowRight, ArrowLeft, X } from 'lucide-react';
import { apiClient } from '../config';

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Forgot password modal state
  const [resetModalOpen, setResetModalOpen] = useState(false);
  const [resetEmail, setResetEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [resetLoading, setResetLoading] = useState(false);
  const [resetSuccess, setResetSuccess] = useState('');
  const [resetError, setResetError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);
    try {
      const u = username.trim();
      const p = password;
      
      // Send form-urlencoded for OAuth2 compatibility
      const formData = new URLSearchParams();
      formData.append('username', u);
      formData.append('password', p);
      
      const res = await apiClient.post(`/auth/login`, formData);
      localStorage.setItem('access_token', res.data.access_token);
      if (res.data.username) {
        localStorage.setItem('zylorun_username', res.data.username);
      }
      navigate('/dashboard');
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      setError(typeof detail === 'string' ? detail : 'Sign in failed. Check your details and try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setResetError('');
    setResetSuccess('');
    setResetLoading(true);
    try {
      const res = await apiClient.post('/auth/reset-password', {
        email: resetEmail.trim(),
        new_password: newPassword
      });
      setResetSuccess(res.data?.message || 'Password successfully updated! You can now sign in.');
      setUsername(resetEmail.trim());
      setPassword(newPassword);
      setTimeout(() => {
        setResetModalOpen(false);
        setResetSuccess('');
      }, 2500);
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      setResetError(typeof detail === 'string' ? detail : 'Failed to update password. Please check the email.');
    } finally {
      setResetLoading(false);
    }
  };

  const fillAdmin = () => {
    setUsername('admin@vovalyx.in');
    setPassword('VovalyxAdmin2026!');
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 relative overflow-hidden bg-background-light dark:bg-background-dark">
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-brand-500/10 blur-[100px] rounded-full pointer-events-none" />
      
      {/* Top Left Floating Back to Home Button */}
      <Link
        to="/"
        className="absolute top-6 left-6 z-20 flex items-center gap-2 px-3.5 py-2 rounded-xl bg-surface-light/80 dark:bg-slate-900/80 backdrop-blur-md border border-border-light dark:border-slate-800 text-xs font-semibold text-slate-700 dark:text-slate-300 hover:text-brand-500 dark:hover:text-white hover:border-brand-500/40 transition-all shadow-sm group"
        title="Return to Zylorun homepage"
      >
        <ArrowLeft className="w-4 h-4 transition-transform group-hover:-translate-x-1 text-brand-500" />
        <span>Back to Home</span>
      </Link>

      <div className="w-full max-w-md p-8 rounded-2xl bg-surface-light dark:bg-surface-dark border border-border-light dark:border-border-dark shadow-xl shadow-black/5 dark:shadow-black/20 z-10">
        {/* In-Card Back Link Header */}
        <div className="mb-4 flex items-center justify-between">
          <Link
            to="/"
            className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white transition-colors group"
          >
            <ArrowLeft className="w-3.5 h-3.5 transition-transform group-hover:-translate-x-1 text-brand-500" />
            <span>Back to Home</span>
          </Link>
          <span className="text-[11px] font-mono text-slate-400 dark:text-slate-500 uppercase tracking-wider">
            Zylorun Auth
          </span>
        </div>

        <div className="flex flex-col items-center mb-8 text-center">
          <div className="w-16 h-16 rounded-2xl flex items-center justify-center mb-4 bg-slate-900 border border-slate-700/60 shadow-xl shadow-cyan-950/20">
            <img src="/zylorun-logo.svg" alt="Zylorun Logo" className="w-full h-full object-contain p-2" />
          </div>
          <h2 className="text-2xl font-bold tracking-tight mb-1 text-white">Welcome to Zylorun</h2>
          <p className="text-sm text-slate-400">Sign in to your account to continue</p>
        </div>

        {error && (
          <div role="alert" aria-live="polite" className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-xs text-center space-y-1">
            <p>{error}</p>
            {error.toLowerCase().includes('password') && (
              <button 
                type="button" 
                onClick={() => { setResetModalOpen(true); setResetEmail(username); }} 
                className="underline text-brand-400 font-semibold text-xs mt-1 block w-full text-center hover:text-brand-300"
              >
                Click here to reset your password
              </button>
            )}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="login-username" className="block text-sm font-medium mb-1.5 text-slate-700 dark:text-slate-300">Email or Username</label>
            <input 
              id="login-username"
              type="text" 
              required
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border border-border-light dark:border-border-dark bg-background-light dark:bg-background-dark focus:outline-none focus:ring-2 focus:ring-brand-500/50 transition-shadow text-slate-900 dark:text-white"
              placeholder="you@company.com or username"
            />
          </div>
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label htmlFor="login-password" className="block text-sm font-medium text-slate-700 dark:text-slate-300">Password</label>
              <button
                type="button"
                onClick={() => { setResetModalOpen(true); setResetEmail(username); }}
                className="text-xs text-brand-500 hover:text-brand-400 font-medium hover:underline"
              >
                Forgot password?
              </button>
            </div>
            <div className="relative">
              <input 
                id="login-password"
                type={showPassword ? 'text' : 'password'} 
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-3 py-2 pr-10 rounded-lg border border-border-light dark:border-border-dark bg-background-light dark:bg-background-dark focus:outline-none focus:ring-2 focus:ring-brand-500/50 transition-shadow text-slate-900 dark:text-white font-mono"
                placeholder="••••••••"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 p-1"
                title={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <button 
            type="submit" 
            disabled={isSubmitting} 
            className="w-full py-2.5 rounded-lg bg-brand-500 hover:bg-brand-600 disabled:opacity-60 disabled:cursor-not-allowed text-white font-medium transition-colors mt-2 shadow-lg shadow-brand-500/25 flex items-center justify-center space-x-2"
          >
            <span>{isSubmitting ? 'Signing in…' : 'Sign In'}</span>
            {!isSubmitting && <ArrowRight className="w-4 h-4" />}
          </button>
        </form>

        <div className="mt-4 pt-3 border-t border-slate-200 dark:border-slate-800/80 flex items-center justify-between text-xs text-slate-500">
          <button
            type="button"
            onClick={fillAdmin}
            className="text-slate-400 hover:text-brand-400 transition"
          >
            ⚡ Quick-fill Admin
          </button>
          <Link to="/admin" className="text-slate-400 hover:text-brand-400 transition">
            Admin Portal &rarr;
          </Link>
        </div>

        <div className="mt-4 text-center text-sm text-slate-500">
          Don't have an account?{' '}
          <Link to="/register" className="text-brand-600 dark:text-brand-400 font-medium hover:underline">
            Sign up
          </Link>
        </div>

        <div className="mt-6 pt-4 border-t border-slate-200 dark:border-slate-800/80 text-center">
          <a
            href="https://www.vovalyx.in/"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 text-xs text-slate-500 hover:text-brand-500 transition"
          >
            <img src="/vovalyx-logo.png" alt="Vovalyx" className="w-4 h-4 rounded object-contain" />
            <span className="font-semibold text-slate-700 dark:text-slate-300">Vovalyx</span>
            <span>— Engineer your vision.</span>
          </a>
        </div>
      </div>

      {/* Forgot Password Modal */}
      {resetModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative space-y-4">
            <button
              onClick={() => setResetModalOpen(false)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white p-1"
            >
              <X className="w-4 h-4" />
            </button>
            <div className="flex items-center space-x-2 text-white">
              <KeyRound className="w-5 h-5 text-brand-400" />
              <h3 className="font-bold text-base">Reset Your Password</h3>
            </div>
            <p className="text-xs text-slate-400">
              Enter your account email and choose a new password. Your account will be immediately updated.
            </p>

            {resetError && (
              <div className="p-2.5 bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg text-xs">
                {resetError}
              </div>
            )}
            {resetSuccess && (
              <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded-lg text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>{resetSuccess}</span>
              </div>
            )}

            <form onSubmit={handleResetPassword} className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Email Address</label>
                <input
                  type="email"
                  required
                  value={resetEmail}
                  onChange={(e) => setResetEmail(e.target.value)}
                  placeholder="you@company.com"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-brand-500"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">New Password</label>
                <input
                  type="password"
                  required
                  minLength={4}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="At least 4 characters"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-brand-500 font-mono"
                />
              </div>
              <button
                type="submit"
                disabled={resetLoading}
                className="w-full py-2 bg-brand-500 hover:bg-brand-600 disabled:opacity-50 text-white font-bold rounded-lg text-xs transition shadow-md"
              >
                {resetLoading ? 'Updating password…' : 'Update Password & Sign In'}
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
