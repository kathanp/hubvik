import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const api = require('./index.js');

export const createEngine = api.createEngine;
export const createShardedEngine = api.createShardedEngine;
export const Engine = api.Engine;
export const detectors = api.detectors;
export const SEVERITY = api.SEVERITY;
export default api;
