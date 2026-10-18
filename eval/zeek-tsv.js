'use strict';

const fs = require('node:fs');

/**
 * Read one Zeek ASCII log. `#separator`, `#fields`, and `#types` are required.
 * `-` and `(empty)` are unset, including the values from `#unset_field` and `#empty_field`.
 * When `tunnel_parents`, `label`, and `detailed-label` were appended with spaces, the
 * header and the short row are split back into those columns.
 * @param {string} file
 * @param {{ requireLabels?: boolean }} [opts]
 * @returns {{ fields: string[], types: string[], rows: Record<string, string>[] }}
 */
function readZeekTsv(file, opts = {}) {
  const text = fs.readFileSync(file, 'utf8');
  /** @type {string[]} */
  let fields = [];
  /** @type {string[]} */
  let types = [];
  let separator = '\t';
  let empty = '(empty)';
  let unset = '-';
  let sawTypes = false;
  /** @type {Record<string, string>[]} */
  const rows = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.length === 0) continue;
    if (line.startsWith('#')) {
      if (line.startsWith('#separator '))
        separator = decodeSeparator(line.slice('#separator '.length));
      else if (line.startsWith('#empty_field ')) empty = line.slice('#empty_field '.length).trim();
      else if (line.startsWith('#unset_field ')) unset = line.slice('#unset_field '.length).trim();
      else if (line.startsWith('#fields')) {
        fields = expandSpacedTail(line.split(separator).slice(1));
        if (
          opts.requireLabels &&
          (!fields.includes('label') || !fields.includes('detailed-label'))
        ) {
          throw new Error(`${file} is missing label or detailed-label`);
        }
      } else if (line.startsWith('#types')) {
        types = expandToLength(line.split(separator).slice(1), fields.length);
        sawTypes = true;
      }
      continue;
    }
    if (fields.length === 0) throw new Error(`${file} has no #fields header`);
    if (!sawTypes) throw new Error(`${file} has no #types header`);
    if (types.length !== fields.length)
      throw new Error(`${file} #types length does not match #fields`);
    const values = splitColumns(line, separator, fields.length, file);
    /** @type {Record<string, string>} */
    const row = {};
    for (let i = 0; i < fields.length; i += 1) {
      const value = values[i];
      if (value === empty || value === unset) continue;
      row[fields[i]] = value;
    }
    rows.push(row);
  }
  if (!sawTypes) throw new Error(`${file} has no #types header`);
  if (opts.requireLabels && (!fields.includes('label') || !fields.includes('detailed-label'))) {
    throw new Error(`${file} is missing label or detailed-label`);
  }
  return { fields, types, rows };
}

/**
 * @param {string} line
 * @param {string} separator
 * @param {number} fieldCount
 * @param {string} file
 * @returns {string[]}
 */
function splitColumns(line, separator, fieldCount, file) {
  const parts = line.split(separator);
  if (parts.length === fieldCount) return parts;
  const missing = fieldCount - parts.length;
  if (missing >= 1 && missing <= 2) {
    const tail = parts[parts.length - 1];
    const bits = tail.split(/ +/);
    if (bits.length === missing + 1) return parts.slice(0, -1).concat(bits);
  }
  throw new Error(`${file} has a row with ${parts.length} fields, expected ${fieldCount}`);
}

/**
 * Official IoT-23 headers glue `tunnel_parents`, `label`, and `detailed-label` into the last
 * tab column with spaces. A header that already lists those names stays as it is.
 * @param {string[]} parts
 * @returns {string[]}
 */
function expandSpacedTail(parts) {
  if (parts.length === 0) return parts;
  const bits = parts[parts.length - 1].trim().split(/ +/);
  if (bits.length > 1 && bits.includes('label') && bits.includes('detailed-label')) {
    return parts.slice(0, -1).concat(bits);
  }
  return parts;
}

/**
 * @param {string[]} parts
 * @param {number} length
 * @returns {string[]}
 */
function expandToLength(parts, length) {
  if (parts.length === 0 || parts.length >= length) return parts;
  const bits = parts[parts.length - 1].trim().split(/ +/);
  if (bits.length === length - parts.length + 1) return parts.slice(0, -1).concat(bits);
  return parts;
}

/**
 * @param {string} raw
 * @returns {string}
 */
function decodeSeparator(raw) {
  const text = raw.trim();
  if (text === '\\x09') return '\t';
  return text;
}

/**
 * Outbound rows use `id.orig_h`. Inbound rows (`local_orig` F and `local_resp` T) use `id.resp_h`.
 * A capture with no `local_orig` column is outbound.
 * @param {Record<string, string>} row
 * @returns {string}
 */
function deviceOf(row) {
  const inbound = row.local_orig === 'F' && row.local_resp === 'T';
  const ip = inbound ? row['id.resp_h'] : row['id.orig_h'];
  if (!ip) throw new Error('conn row has no device address');
  return ip;
}

module.exports = { readZeekTsv, deviceOf };
