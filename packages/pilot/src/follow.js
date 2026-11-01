'use strict';

const fs = require('node:fs');
const { fileStat } = require('./files.js');

/**
 * Read complete new lines. A partial last line is kept until the next read.
 * A shrink or a new inode starts again at byte 0.
 * @param {string} file
 * @param {{ offset: number, ino: number | null, partial: string }} cursor
 * @returns {string[]}
 */
function readNewLines(file, cursor) {
  const stat = fileStat(file);
  if (cursor.ino != null && (stat.ino !== cursor.ino || stat.size < cursor.offset)) {
    cursor.offset = 0;
    cursor.partial = '';
  }
  cursor.ino = stat.ino;
  if (stat.size <= cursor.offset) return [];
  const length = stat.size - cursor.offset;
  const buf = Buffer.alloc(length);
  const fd = fs.openSync(file, 'r');
  fs.readSync(fd, buf, 0, length, cursor.offset);
  fs.closeSync(fd);
  cursor.offset = stat.size;
  const parts = `${cursor.partial}${buf.toString('utf8')}`.split('\n');
  cursor.partial = parts.pop() || '';
  return parts.filter((line) => line.length > 0);
}

/**
 * @returns {{ offset: number, ino: number | null, partial: string }}
 */
function emptyCursor() {
  return { offset: 0, ino: null, partial: '' };
}

module.exports = { readNewLines, emptyCursor };
