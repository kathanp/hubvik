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
    if (day >= 2 && device.learnFamilyNew > 20 && device.learnFamilyWarned !== day) {
      device.learnFamilyWarned = day;
      engine._warn(
        'SUSPICIOUS_LEARNING',
        `${device.learnFamilyNew} new destination families on learning day ${day}`,
        device.id,
      );
    }
  }
  if (!device.greWarned && (event.proto === 'gre' || event.proto === 47)) {
    device.greWarned = true;
    engine._warn('SUSPICIOUS_LEARNING', 'GRE traffic during learning', device.id);
  }
  if (
    !device.telnetWarned &&
    event.type === 'flow' &&
    event.direction === 'out' &&
    (event.dstPort === 23 || event.dstPort === 2323)
  ) {
    device.telnetWarned = true;
    engine._warn('SUSPICIOUS_LEARNING', 'outbound telnet during learning', device.id);
  }
  if (event.type === 'dns' && String(event.rcode).toUpperCase() === 'NXDOMAIN') {
    if (device.nxWindow !== event.ts - (event.ts % engine.opts.windowMs)) {
      device.nxWindow = event.ts - (event.ts % engine.opts.windowMs);
      device.nxCount = 0;
      device.nxWarned = false;
    }
    device.nxCount += 1;
    if (device.nxCount >= 10 && !device.nxWarned) {
      device.nxWarned = true;
      engine._warn('SUSPICIOUS_LEARNING', 'NXDOMAIN burst during learning', device.id);
    }
  }
}

module.exports = { noteLearning };
