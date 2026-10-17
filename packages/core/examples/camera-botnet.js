'use strict';
// Simulates a camera behind a gateway: one normal week, then it gets hijacked.
const { createEngine } = require('../src/index.js');

const H = 3600e3,
  DAY = 24 * H;
const T0 = Date.UTC(2026, 0, 5);
const engine = createEngine({ learnMs: 7 * DAY });

engine.on('anomaly', (a) =>
  console.log(
    `[${a.severity.toUpperCase()}] ${a.device} ${a.detector}: ${a.actual} (expected ${a.expected})`,
  ),
);
/** @type {any} */
let incident = null;
engine.on('incident', (item) => {
  incident = item;
});

// Learn: active 08:00-20:00, two vendor hosts
for (let day = 0; day < 7; day++)
  for (let h = 8; h < 20; h++)
    for (let m = 0; m < 60; m += 5)
      engine.feed({
        device: 'cam-1',
        dst: m % 10 ? 'video.vendor.com' : 'time.vendor.com',
        bytes: 2000,
        ts: T0 + day * DAY + h * H + m * 60e3,
      });

console.log('Learned. Camera is now hijacked at 03:00 the next night...\n');
const awake = T0 + 7 * DAY + 10 * H;
engine.feed({ device: 'cam-1', dst: 'video.vendor.com', bytes: 2000, ts: awake });
engine.tick(awake + 2 * H);
const t = T0 + 8 * DAY + 3 * H;
engine.feed({ device: 'cam-1', dst: 'c2.botnet.example', bytes: 300, ts: t }); // calls control server
for (let i = 0; i < 400; i++)
  // starts scanning
  engine.feed({ device: 'cam-1', dst: `203.0.113.${i % 250}-${i}`, bytes: 60, ts: t + 1000 + i });
engine.feed({ device: 'cam-1', dst: 'c2.botnet.example', bytes: 80e6, ts: t + 2000 }); // floods
engine.flush();
if (incident) {
  console.log(
    `\nINCIDENT ${incident.severity} score ${incident.score} stages ${incident.stages.join(', ')}: ${incident.summary}`,
  );
}
