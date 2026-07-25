'use strict';

/**
 * STEP 7 — Desktop notification on any SUSPICIOUS finding.
 * node-notifier is loaded lazily so that headless/CI environments (which set
 * CARGO_WITNESS_NO_NOTIFY or simply lack a notification daemon) never crash.
 */
function notifySuspicious(suspicious) {
  if (!suspicious || suspicious.length === 0) return;
  if (process.env.CARGO_WITNESS_NO_NOTIFY) return;

  let notifier;
  try {
    notifier = require('node-notifier');
  } catch {
    return;
  }

  const message = suspicious
    .map((p) => {
      const flags = (p.flags || [])
        .map((f) => (typeof f === 'string' ? f : f.flag))
        .join(', ');
      return `${p.name}@${p.version}: ${flags}`;
    })
    .join('\n');

  try {
    notifier.notify({
      title: 'cargo-witness ALERT',
      message,
    });
  } catch {
    /* non-fatal */
  }
}

module.exports = { notifySuspicious };
