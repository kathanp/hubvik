import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const api = require('./index.js');

export const parseDecisions = api.parseDecisions;
export const loadDecisionsFile = api.loadDecisionsFile;
export default api;
