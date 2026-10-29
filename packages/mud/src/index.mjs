import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const api = require('./index.js');

export const parseMud = api.parseMud;
export const loadMudFile = api.loadMudFile;
export default api;
