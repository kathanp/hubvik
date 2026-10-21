'use strict';

const { createEngine, createShardedEngine, Engine } = require('./engine/engine');
const { BY_ID } = require('./detectors');
const { SEVERITY } = require('./engine/constants');
const { HubvikError } = require('./errors');

module.exports = {
  createEngine,
  createShardedEngine,
  Engine,
  detectors: BY_ID,
  SEVERITY,
  HubvikError,
};
