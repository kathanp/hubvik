import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const api = require('./index.js');

export const createRunner = api.createRunner;
export const writeReport = api.writeReport;
export const queueLabel = api.queueLabel;
export default api;
