'use strict';

const FLOW =
  /^(tcp|udp|icmp|gre)\s+\d+\s+\d+\s+(?:([A-Za-z0-9_]+)\s+)?src=(\S+)\s+dst=(\S+)\s+sport=(\d+)\s+dport=(\d+)(?:\s+packets=(\d+))?(?:\s+bytes=(\d+))?(?:\s+src=\S+\s+dst=\S+\s+sport=\d+\s+dport=\d+(?:\s+packets=(\d+))?(?:\s+bytes=(\d+))?)?/i;

const OPEN = new Set(['ESTABLISHED', 'FIN_WAIT', 'CLOSE_WAIT', 'LAST_ACK', 'TIME_WAIT']);
const SILENT = new Set(['SYN_SENT', 'SYN_RECV', 'SYN_SENT2', 'NONE', 'LISTEN']);

/**
 * Stream parser for `conntrack -L` and `conntrack -E` lines.
 * The first src/dst pair is the original direction. The second pair, when present, is the reply.
 * With no `direction` function, a private address decides out, in, or lan (D-99).
 * `bytesOut` is the device's bytes, so an inbound flow swaps the two counters (D-100).
 * TCP state becomes `tcpOutcome` (D-101). UDP omits it.
 * @param {{ device?: (ip: string) => string, direction?: (srcIp: string, dstIp: string) => 'out'|'in'|'lan', now?: () => number }} [opts]
 */
function createParser(opts = {}) {
  const device = opts.device || ((ip) => ip);
  const directionOf = opts.direction;
  const now = opts.now || (() => 0);
  return {
    /**
     * @param {string} line
     * @returns {object[]}
     */
    write(line) {
      if (typeof line !== 'string') return [];
      const match = FLOW.exec(line.trim());
      if (!match) return [];
      const proto = match[1].toLowerCase();
      const state = match[2];
      const srcIp = match[3];
      const dstIp = match[4];
      const srcPort = Number(match[5]);
      const dstPort = Number(match[6]);
      const origPkts = match[7] ? Number(match[7]) : 1;
      const origBytes = match[8] ? Number(match[8]) : 0;
      const replyPkts = match[9] ? Number(match[9]) : 0;
      const replyBytes = match[10] ? Number(match[10]) : 0;
      const guessed = addressSide(srcIp, dstIp);
      const direction = directionOf ? directionOf(srcIp, dstIp) : guessed.direction;
      const inbound = direction === 'in';
      const deviceIp = directionOf ? srcIp : guessed.deviceIp;
      /** @type {Record<string, any>} */
      const event = {
        type: 'flow',
        device: device(deviceIp),
        ts: now(),
        srcIp,
        srcPort,
        dstIp,
        dstPort,
        proto,
        direction,
        bytesOut: inbound ? replyBytes : origBytes,
        bytesIn: inbound ? origBytes : replyBytes,
        pktsOut: inbound ? replyPkts : origPkts,
        pktsIn: inbound ? origPkts : replyPkts,
        durationMs: 0,
      };
      const outcome = tcpOutcome(proto, state, /\[UNREPLIED\]/i.test(line), replyPkts);
      if (outcome) event.tcpOutcome = outcome;
      return [event];
    },
  };
}

/**
 * @param {string} proto
 * @param {string | undefined} state
 * @param {boolean} unreplied
 * @param {number} replyPkts
 * @returns {'established' | 'no-response' | undefined}
 */
function tcpOutcome(proto, state, unreplied, replyPkts) {
  if (proto !== 'tcp' || !state) return undefined;
  const name = state.toUpperCase();
  if (SILENT.has(name) || unreplied) return 'no-response';
  if (name === 'CLOSE' && replyPkts === 0) return 'no-response';
  if (OPEN.has(name) || name === 'CLOSE') return 'established';
  return undefined;
}

/**
 * @param {string} src
 * @param {string} dst
 * @returns {{ deviceIp: string, direction: 'out' | 'in' | 'lan' }}
 */
function addressSide(src, dst) {
  const srcLocal = isLocalAddress(src);
  const dstLocal = isLocalAddress(dst);
  if (srcLocal && dstLocal) return { deviceIp: src, direction: 'lan' };
  if (dstLocal && !srcLocal) return { deviceIp: dst, direction: 'in' };
  return { deviceIp: src || dst, direction: 'out' };
}

/**
 * @param {string} ip
 * @returns {boolean}
 */
function isLocalAddress(ip) {
  if (typeof ip !== 'string' || ip.length === 0) return false;
  let lower = ip.toLowerCase();
  if (lower.startsWith('[') && lower.endsWith(']')) lower = lower.slice(1, -1);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(lower);
  if (mapped) lower = mapped[1];
  if (
    lower.startsWith('10.') ||
    lower.startsWith('192.168.') ||
    lower.startsWith('127.') ||
    lower.startsWith('169.254.')
  ) {
    return true;
  }
  const part = /^172\.(\d+)\./.exec(lower);
  if (part) {
    const octet = Number(part[1]);
    if (octet >= 16 && octet <= 31) return true;
  }
  if (lower === '::' || lower === '::1') return true;
  if (/^fe[89ab][0-9a-f]/i.test(lower)) return true;
  return lower.startsWith('fc') || lower.startsWith('fd');
}

module.exports = { createParser };
