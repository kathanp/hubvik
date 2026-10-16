'use strict';

const ALL_HOURS = Array.from({ length: 24 }, (_, hour) => hour);

/**
 * Benign schedules. Byte jitter stays inside ±3% so a later window cannot
 * exceed twice the learned maximum. Hosts repeat every day, so week two
 * adds no destinations and no new hours.
 */
const PROFILES = {
  camera: {
    device: 'camera-1',
    hours: ALL_HOURS,
    everyMs: 60_000,
    bytes: 15_000_000,
    jitter: 0.03,
    hosts: ['video.vendor.com', 'time.vendor.com'],
    hostPick: 'tenth',
  },
  thermostat: {
    device: 'thermostat-1',
    hours: ALL_HOURS,
    everyMs: 600_000,
    bytes: 400,
    jitter: 0.03,
    hosts: ['mqtt.vendor.com', 'weather.vendor.com', 'time.vendor.com'],
    hostPick: 'mod',
  },
  plug: {
    device: 'plug-1',
    hours: ALL_HOURS,
    everyMs: 30_000,
    bytes: 300,
    jitter: 0.03,
    hosts: ['plug.vendor.com'],
    hostPick: 'first',
  },
  'tv-box': {
    device: 'tv-1',
    hours: [18, 19, 20, 21, 22, 23],
    everyMs: 60_000,
    bytes: 2_000_000,
    jitter: 0.03,
    hosts: Array.from({ length: 40 }, (_, i) => `cdn-${i}.video.example`),
    hostPick: 'mod',
  },
  'hvac-controller': {
    device: 'hvac-1',
    hours: [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
    everyMs: 10_000,
    bytes: 250,
    jitter: 0.03,
    hosts: ['bms.local'],
    hostPick: 'first',
  },
  hub: {
    device: 'hub-1',
    hours: ALL_HOURS,
    everyMs: 60_000,
    bytes: 2_000,
    jitter: 0.03,
    hosts: [
      'cloud-a.hub.example',
      'cloud-b.hub.example',
      'cloud-c.hub.example',
      'cloud-d.hub.example',
      'cloud-e.hub.example',
    ],
    hostPick: 'mod',
  },
  printer: {
    device: 'printer-1',
    hours: [9, 15],
    minutes: 5,
    everyMs: 60_000,
    bytes: 1_500_000,
    jitter: 0.02,
    hosts: ['print.vendor.com'],
    hostPick: 'first',
  },
};

const CLASS_NAMES = Object.keys(PROFILES);

module.exports = { PROFILES, CLASS_NAMES };
