import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const api = require('./index.js');

export const toMessages = api.toMessages;
export const publishWith = api.publishWith;
export default api;
