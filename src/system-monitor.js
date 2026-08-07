// mona.expert — System Resource Monitor
// Periodically captures CPU, memory, process info and broadcasts to live dashboard

import os from "node:os";
import { broadcast } from "./event-bus.js";

let intervalHandle = null;
let previousCpuTimes = null;

function getCpuUsage() {
  const cpus = os.cpus();
  const total = { user: 0, nice: 0, sys: 0, idle: 0, irq: 0 };
  for (const cpu of cpus) {
    total.user += cpu.times.user;
    total.nice += cpu.times.nice;
    total.sys += cpu.times.sys;
    total.idle += cpu.times.idle;
    total.irq += cpu.times.irq;
  }

  const now = { ...total };
  let percent = 0;
  if (previousCpuTimes) {
    const idleDelta = now.idle - previousCpuTimes.idle;
    const totalDelta =
      (now.user - previousCpuTimes.user) +
      (now.nice - previousCpuTimes.nice) +
      (now.sys - previousCpuTimes.sys) +
      (now.idle - previousCpuTimes.idle) +
      (now.irq - previousCpuTimes.irq);
    percent = totalDelta > 0 ? Math.min(100, Math.round(((totalDelta - idleDelta) / totalDelta) * 100)) : 0;
  }
  previousCpuTimes = now;
  return percent;
}

function collectMetrics() {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memPercent = Math.round((usedMem / totalMem) * 100);

  const memUsage = process.memoryUsage();
  return {
    cpu: getCpuUsage(),
    cpus: os.cpus().length,
    memory: {
      totalBytes: totalMem,
      freeBytes: freeMem,
      usedBytes: usedMem,
      percent: memPercent,
      freePercent: Math.round((freeMem / totalMem) * 100),
    },
    loadavg: os.loadavg(),
    uptime: os.uptime(),
    process: {
      pid: process.pid,
      memoryRss: memUsage.rss,
      heapUsed: memUsage.heapUsed,
      heapTotal: memUsage.heapTotal,
      external: memUsage.external,
      arrayBuffers: memUsage.arrayBuffers || 0,
      uptime: process.uptime(),
      cpuUser: process.cpuUsage().user,
      cpuSystem: process.cpuUsage().system,
      version: process.version,
      title: process.title,
    },
    at: new Date().toISOString(),
  };
}

export function startSystemMonitor(intervalMs = 10000) {
  if (intervalHandle) return;
  // Broadcast immediately, then on interval
  broadcast("system-metrics", collectMetrics());
  intervalHandle = setInterval(() => {
    broadcast("system-metrics", collectMetrics());
  }, intervalMs).unref();
}

export function stopSystemMonitor() {
  if (intervalHandle) {
    clearInterval(intervalHandle);
    intervalHandle = null;
  }
}

export function getCurrentMetrics() {
  return collectMetrics();
}
