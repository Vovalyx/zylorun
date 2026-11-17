import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { CheckCircle2, KeyRound } from 'lucide-react';
import { apiClient, describeRequestError } from '../config';

const MIN_PASSWORD_LENGTH = 8;

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const token = searchParams.get('token') || '';

  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }
    if (password !== confirm) {
      setError('The two passwords do not match.');
      return;
    }
    setLoading(true);
    try {
      await apiClient.post('/auth/reset-password', { token, new_password: password });
      setDone(true);
      setTimeout(() => navigate('/login'), 2500);
    } catch (err: any) {
      setError(describeRequestError(err, 'This reset link is invalid or has expired. Please request a new one.'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-sm w-full p-6 shadow-2xl space-y-4">
        <div className="flex items-center space-x-2 text-white">
          <KeyRound className="w-5 h-5 text-brand-400" />
          <h1 className="font-bold text-base">Choose a new password</h1>
        </div>

        {!token && (
          <div className="p-2.5 bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg text-xs">
            This page needs the link from your password reset email. Request a new link from the sign-in page.
          </div>
        )}
        {error && (
          <div className="p-2.5 bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg text-xs">{error}</div>
        )}
        {done && (
          <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded-lg text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>Password updated. Taking you to sign in…</span>
          </div>
        )}

        {token && !done && (
          <form onSubmit={handleSubmit} className="space-y-3">
            <div>
              <label htmlFor="new-password" className="block text-xs font-semibold text-slate-300 mb-1">New password</label>
              <input
                id="new-password"
                type="password"
                required
                minLength={MIN_PASSWORD_LENGTH}
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={`At least ${MIN_PASSWORD_LENGTH} characters`}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-brand-500"
              />
            </div>
            <div>
              <label htmlFor="confirm-password" className="block text-xs font-semibold text-slate-300 mb-1">Confirm new password</label>
              <input
                id="confirm-password"
                type="password"
                required
                minLength={MIN_PASSWORD_LENGTH}
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-brand-500"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2 bg-brand-500 hover:bg-brand-600 disabled:opacity-50 text-white font-bold rounded-lg text-xs transition shadow-md"
            >
              {loading ? 'Updating password…' : 'Update password'}
            </button>
          </form>
        )}

        <Link to="/login" className="block text-center text-xs text-slate-400 hover:text-white">
          Back to sign in
        </Link>
      </div>
    </div>
  );
}
