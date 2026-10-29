import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const api = require('./index.js');

export const parseTrail = api.parseTrail;
export const loadTrailFile = api.loadTrailFile;
export default api;
