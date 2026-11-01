'use strict';

const fs = require('node:fs');
const path = require('node:path');

/**
 * Write a temp file in the same directory, then rename it.
 * @param {string} file
 * @param {string} text
 * @returns {void}
 */
function writeAtomic(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, text);
  fs.renameSync(tmp, file);
}

/**
 * @param {string} file
 * @returns {{ ino: number, size: number }}
 */
function fileStat(file) {
  const stat = fs.statSync(file);
  return { ino: stat.ino, size: stat.size };
}

module.exports = { writeAtomic, fileStat };
