/**
 * license.js — Open-core license check.
 *
 * The open-source build runs freely under the MIT license (see LICENSE).
 * Commercial/on-prem builds may substitute an enforcing implementation that
 * validates a signed, machine-bound key. This default never blocks startup.
 *
 * Set MONA_LICENSE_MODE=commercial together with a MONA_LICENSE_KEY to opt
 * into stricter behavior in downstream builds.
 */

export function checkLicense() {
  const mode = process.env.MONA_LICENSE_MODE || "open-source";

  if (mode === "open-source") {
    return { ok: true, mode, reason: "open-source build" };
  }

  // Downstream commercial builds replace this module with an enforcing one.
  // If they don't, we still fail open here — the open-core repo must run.
  const key = process.env.MONA_LICENSE_KEY || "";
  return {
    ok: true,
    mode,
    reason: key ? "license key present" : "no key (fail-open in open core)",
  };
}
