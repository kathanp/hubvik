import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { main } = require('./cli.js');

try {
  main(process.argv.slice(2));
} catch (err) {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
}
