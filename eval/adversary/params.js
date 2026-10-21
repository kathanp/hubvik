'use strict';

/**
 * Published adaptive-adversary parameters (G8).
 * Magnitudes are the spec goals. `eval/adversary-holdout/params.js` uses another seed.
 */

const DAY = 24 * 60 * 60 * 1000;

const SEED = 20261021;
const DEVICE = 'controller-1';
const RATE = 0.9;
const EXFIL_BYTES = 500 * 1024 * 1024;
const SCAN_HOSTS = 1000;
const BEACON_DAYS = 7;
const SPAN_DAYS = 7;
const OT_OFFSET = 1;
const LEARN_DAYS = 2;
const LEARN_BYTES = 8_000_000;
const ACTIVE_HOURS = [8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
const BEACON_IP = '45.2.1.10';
const SCAN_A = 45;
const SCAN_B = 10;
const JA4 = 't13d1516h2_8daaf6152771_02713d6af862';
const OT_VALUES = [20, 21, 22, 21];
const OT_TARGET = 'zone-1';
const OT_PEER = '10.0.0.50';
const SRC_IP = '10.0.0.8';
const CDN_HOSTS = ['img1.cloudfront.net', 'img2.cloudfront.net'];
const VENDOR_HOST = 'api.vendor.example';

module.exports = {
  DAY,
  SEED,
  DEVICE,
  RATE,
  EXFIL_BYTES,
  SCAN_HOSTS,
  BEACON_DAYS,
  SPAN_DAYS,
  OT_OFFSET,
  LEARN_DAYS,
  LEARN_BYTES,
  ACTIVE_HOURS,
  BEACON_IP,
  SCAN_A,
  SCAN_B,
  JA4,
  OT_VALUES,
  OT_TARGET,
  OT_PEER,
  SRC_IP,
  CDN_HOSTS,
  VENDOR_HOST,
};
