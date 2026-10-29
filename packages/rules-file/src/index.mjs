import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const api = require('./index.js');

export const parseRules = api.parseRules;
export const loadRulesFile = api.loadRulesFile;
export default api;
