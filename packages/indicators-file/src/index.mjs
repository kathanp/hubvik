import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const api = require('./index.js');

export const parseIndicators = api.parseIndicators;
export const loadIndicatorFile = api.loadIndicatorFile;
export default api;
