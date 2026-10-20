import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const api = require('./index.js');

export const toFinding = api.toFinding;
export default api;
