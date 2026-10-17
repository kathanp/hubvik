'use strict';

const { domainFamily } = require('./net');

const DAY = 24 * 3600e3;

/**
 * Learning-quality warnings. These do not become anomalies.
 * @param {any} engine
 * @param {any} device
 * @param {any} event
 */
function noteLearning(engine, device, event) {
  if (device.mode !== 'learning' || device.learnStart == null) return;
  const families = device.learnFamilies || (device.learnFamilies = new Set());
  const family = domainFamily(event.dst);
  if (family && !families.has(family)) {
    families.add(family);
    const day = Math.floor((event.ts - device.learnStart) / DAY);
    if (day !== device.learnFamilyDay) {
      device.learnFamilyDay = day;
      device.learnFamilyNew = 0;
    }
    device.learnFamilyNew = (device.learnFamilyNew || 0) + 1;
    if (day >= 2 && device.learnFamilyNew > 20) {
      mark(
        engine,
        device,
        event,
        'family-churn',
        `${device.learnFamilyNew} new destination families on learning day ${day}`,
      );
    }
  }
  if (event.proto === 'gre' || event.proto === 47) {
    mark(engine, device, event, 'gre', 'GRE traffic during learning');
  }
  if (
    event.type === 'flow' &&
    event.direction === 'out' &&
    (event.dstPort === 23 || event.dstPort === 2323)
  ) {
    mark(engine, device, event, 'telnet-out', 'outbound telnet during learning');
  }
  if (
    event.type === 'flow' &&
    event.proto === 'tcp' &&
    (event.dstPort === 5555 || event.srcPort === 5555)
  ) {
    mark(engine, device, event, 'adb', 'TCP 5555 during learning');
  }
  if (event.type === 'dns' && String(event.rcode).toUpperCase() === 'NXDOMAIN') {
    if (device.nxWindow !== event.ts - (event.ts % engine.opts.windowMs)) {
      device.nxWindow = event.ts - (event.ts % engine.opts.windowMs);
      device.nxCount = 0;
      device.nxWarned = false;
    }
    device.nxCount += 1;
    if (device.nxCount >= 10) {
      mark(engine, device, event, 'nxdomain-burst', 'NXDOMAIN burst during learning');
    }
  }
  proxyShape(engine, device, event);
}

/**
 * @param {any} engine
 * @param {any} device
 * @param {any} event
 * @param {string} reason
 * @param {string} message
 */
function mark(engine, device, event, reason, message) {
  const reasons = device.suspicious || (device.suspicious = []);
  if (reasons.includes(reason)) return;
  reasons.push(reason);
  engine._warn('SUSPICIOUS_LEARNING', message, device.id, { reason, ts: event.ts });
}

/**
 * @param {any} engine
 * @param {any} device
 * @param {any} event
 */
function proxyShape(engine, device, event) {
  if ((device.suspicious || []).includes('proxy-shape')) return;
  const shadow = device.proxyShadow || (device.proxyShadow = Object.create(null));
  const ctx = engine._ctx(device, true, event.ts);
  ctx.window = device.open;
  for (const id of ['proxy-relay', 'proxy-backconnect', 'p2p-pattern']) {
    const det = engine.byId.get(id);
    if (!det) continue;
    if (!shadow[id]) shadow[id] = det.createState(engine.opts);
    ctx.options = engine._optionsFor(det);
    if (det.check(shadow[id], event, ctx)) {
      mark(engine, device, event, 'proxy-shape', 'proxy shape during learning');
      return;
    }
  }
}

module.exports = { noteLearning, mark };
