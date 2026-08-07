// mona.expert — Lightweight event bus for live dashboard
// Provides push-based SSE broadcasts from proxy → dashboard

const subscribers = new Set();

export function subscribe(res) {
  subscribers.add(res);
  return () => subscribers.delete(res);
}

export function broadcast(type, payload) {
  const msg = `event: ${type}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const res of subscribers) {
    try { res.write(msg); } catch { subscribers.delete(res); }
  }
}

export function subscriberCount() {
  return subscribers.size;
}

export function clearSubscribers() {
  subscribers.clear();
}
