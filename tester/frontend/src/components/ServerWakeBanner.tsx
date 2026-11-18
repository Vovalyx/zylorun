import { useEffect, useState } from 'react';
import { API_URL } from '../config';

const SHOW_AFTER_MS = 2500;
const GIVE_UP_AFTER_MS = 180_000;

/**
 * The API runs on a host that may be starting up after a quiet period. Instead of
 * pages that silently hang, show a short notice while the first health check is
 * still pending, and hide it as soon as the server answers.
 */
export default function ServerWakeBanner() {
  const [waiting, setWaiting] = useState(false);
  const [seconds, setSeconds] = useState(0);

  useEffect(() => {
    let done = false;
    const started = Date.now();
    const showTimer = window.setTimeout(() => {
      if (!done) setWaiting(true);
    }, SHOW_AFTER_MS);
    const tick = window.setInterval(() => {
      if (!done) setSeconds(Math.round((Date.now() - started) / 1000));
    }, 1000);

    const controller = new AbortController();
    const giveUp = window.setTimeout(() => controller.abort(), GIVE_UP_AFTER_MS);
    fetch(`${API_URL}/health`, { signal: controller.signal, cache: 'no-store' })
      .catch(() => undefined)
      .finally(() => {
        done = true;
        setWaiting(false);
      });

    return () => {
      done = true;
      controller.abort();
      window.clearTimeout(showTimer);
      window.clearTimeout(giveUp);
      window.clearInterval(tick);
    };
  }, []);

  if (!waiting) return null;
  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed bottom-4 left-1/2 -translate-x-1/2 z-[60] max-w-md w-[calc(100%-2rem)] px-4 py-3 rounded-xl border border-amber-300/60 bg-amber-50 dark:bg-amber-950/80 dark:border-amber-800 text-amber-900 dark:text-amber-100 text-sm shadow-lg flex items-center gap-3"
    >
      <span className="inline-block w-3 h-3 rounded-full bg-amber-500 animate-pulse shrink-0" />
      <span>
        Starting the server… this can take up to a minute after a quiet period ({seconds}s).
      </span>
    </div>
  );
}
