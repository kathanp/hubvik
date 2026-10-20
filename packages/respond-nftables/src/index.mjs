import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const api = require('./index.js');

export const render = api.render;
export default api;
