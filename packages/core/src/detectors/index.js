'use strict';

const newDestination = require('./new-destination');
const fanOut = require('./fan-out');
const volumeSpike = require('./volume-spike');
const wrongTime = require('./wrong-time');

/** @type {any[]} */
const ALL = [newDestination, fanOut, volumeSpike, wrongTime];

/** @type {Record<string, any>} */
const BY_ID = Object.create(null);
for (const detector of ALL) BY_ID[detector.id] = detector;

module.exports = { ALL, BY_ID };
