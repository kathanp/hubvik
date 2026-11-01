'use strict';

/**
 * Live detectors outside the core list are off. An explicit enabled flag wins.
 * Shadow detectors stay on the shadow option.
 * @param {any} det
 * @param {any} opts
 * @returns {{ active: false, reason: 'profile' } | null}
 */
function profileStatus(det, opts) {
  if (!opts || opts.profile !== 'core') return null;
  if (det.meta && det.meta.mode === 'shadow') return null;
  const over = opts.detectors && opts.detectors[det.id];
  if (over && over.enabled != null) return null;
  if (opts.coreIds && opts.coreIds.has(det.id)) return null;
  return { active: false, reason: 'profile' };
}

module.exports = { profileStatus };
