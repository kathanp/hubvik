'use strict';

const plug = require('../data/classes/plug.json');
const thermostat = require('../data/classes/thermostat.json');
const camera = require('../data/classes/camera.json');
const tvBox = require('../data/classes/tv-box.json');
const hub = require('../data/classes/hub.json');
const printer = require('../data/classes/printer.json');
const hvac = require('../data/classes/hvac-controller.json');
const nas = require('../data/classes/nas.json');
const smartTv = require('../data/classes/smart-tv.json');

/** @type {Record<string, { id: string, maxFamilies: number, maxUploadBytesPerHour: number, allowsInboundLan: boolean }>} */
const CLASSES = Object.create(null);
for (const item of [plug, thermostat, camera, tvBox, hub, printer, hvac, nas, smartTv]) {
  CLASSES[item.id] = item;
}

module.exports = { CLASSES };
