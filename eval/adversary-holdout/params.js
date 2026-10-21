'use strict';

/**
 * Holdout parameters for the adaptive adversary. Different seed and different
 * magnitudes from `eval/adversary/params.js`. A detector that claims to close a
 * published blind spot is judged here, with these numbers fixed first.
 */

const DAY = 24 * 60 * 60 * 1000;

const SEED = 881122;
const DEVICE = 'holdout-controller-1';
const RATE = 0.75;
const EXFIL_BYTES = 750 * 1024 * 1024;
const SCAN_HOSTS = 2500;
const BEACON_DAYS = 11;
const SPAN_DAYS = 9;
const OT_OFFSET = 4;
const LEARN_DAYS = 3;
const LEARN_BYTES = 3_000_000;
const ACTIVE_HOURS = [6, 7, 8, 9, 10, 11, 12];
const BEACON_IP = '47.8.9.20';
const SCAN_A = 47;
const SCAN_B = 11;
const JA4 = 't13d1715h2_5b57614c22b0_3d5424432f57';
const OT_VALUES = [10, 12, 14, 16];
const OT_TARGET = 'loop-4';
const OT_PEER = '10.2.0.50';
const SRC_IP = '10.2.0.8';
const CDN_HOSTS = ['edge1.cloudfront.net', 'edge2.cloudfront.net', 'edge3.cloudfront.net'];
const VENDOR_HOST = 'gw.plant.example';

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
