'use strict';

/**
 * Stable error for rejected input and broken state.
 * `code` does not change. The message may include the offending value.
 */
class HubvikError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {ErrorOptions} [options]
   */
  constructor(code, message, options) {
    super(message, options);
    this.name = 'HubvikError';
    this.code = code;
  }
}

module.exports = { HubvikError };
