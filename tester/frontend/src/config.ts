import axios from 'axios';

export const API_URL = 
  import.meta.env.VITE_API_URL || 
  import.meta.env.VITE_API_BASE_URL || 
  (typeof window !== 'undefined' && (window.location.hostname.includes('vercel.app') || window.location.hostname.includes('zylorun') || window.location.hostname.includes('onrender.com'))
    ? 'https://zylorun.onrender.com'
    : (typeof window !== 'undefined' && window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1')
      ? `http://${window.location.hostname}:8000`
      : 'http://localhost:8000');

export const apiClient = axios.create({
  baseURL: API_URL
});

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers['Authorization'] = `Bearer ${token}`;
  }
  return config;
});

const NETWORK_RETRY_DELAY_MS = 1500;
const NETWORK_ERROR_MESSAGE =
  'Could not reach the server. Check your internet connection and try again. ' +
  'If you are on a VPN or just switched Wi-Fi, wait a moment first.';

/** True when the request never got an answer (offline, Wi-Fi/VPN change, DNS, server unreachable). */
export const isNetworkError = (error: any): boolean =>
  !!error && !error.response && (error.code === 'ERR_NETWORK' || error.code === 'ECONNABORTED' || error.message === 'Network Error');

/** Turns a failed request into text that is safe to show: the server's own message when
 *  there is one, a clear connection message when there was no answer, else the fallback. */
export const describeRequestError = (error: any, fallback: string): string => {
  const detail = error?.response?.data?.detail;
  if (typeof detail === 'string' && detail) return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  if (isNetworkError(error)) return NETWORK_ERROR_MESSAGE;
  return fallback;
};

// A request that failed before any answer arrived cannot have changed anything on the
// server only when it is a read or a sign-in, so only those are repeated automatically.
const isSafeToRetry = (config: any): boolean => {
  const method = String(config?.method || 'get').toLowerCase();
  const url = String(config?.url || '');
  return method === 'get' || /\/(auth|admin)\/login$/.test(url);
};

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const config = error?.config;
    if (config && !config.__networkRetried && isNetworkError(error) && isSafeToRetry(config)) {
      config.__networkRetried = true;
      await new Promise((resolve) => setTimeout(resolve, NETWORK_RETRY_DELAY_MS));
      return apiClient(config);
    }
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('access_token');
      localStorage.removeItem('gitflow_active_repo');
      localStorage.removeItem('user');
      // If we're not already on the login page, redirect
      if (window.location.pathname !== '/login' && window.location.pathname !== '/') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);
