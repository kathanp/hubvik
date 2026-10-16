'use strict';

const { createEngine, Engine } = require('./engine/engine');
const { BY_ID } = require('./detectors');
const { SEVERITY } = require('./engine/constants');

module.exports = { createEngine, Engine, detectors: BY_ID, SEVERITY };
