import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const api = require('./lib.js');

export const checkRule = api.checkRule;
export const replay = api.replay;
export const doctor = api.doctor;
export const reportHtml = api.reportHtml;
export const diffBaseline = api.diffBaseline;
export const verifyBaseline = api.verifyBaseline;
export default api;
