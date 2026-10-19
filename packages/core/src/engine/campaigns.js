'use strict';

const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const OPEN_CAP = 256;
const EDGE_CAP = 64;
const PENDING_CAP = 1024;

/**
 * Link live anomalies into a campaign. Shadow anomalies never reach this function.
 * @param {any} engine
 * @param {any} device
 * @param {any} anomaly
 * @param {any} event
 * @returns {void}
 */
function noteCampaign(engine, device, anomaly, event) {
  if (!engine.opts.campaigns || engine.opts.identity !== 'auto') return;
  const rank = /** @type {Record<string, number>} */ (RANK);
  if ((rank[anomaly.severity] ?? -1) < rank.medium) return;
  closeOld(engine, anomaly.ts);
  for (const ip of targetsOf(event, anomaly)) {
    const other = engine.resolve(ip);
    if (!other || other === device.id) continue;
    const pending = engine._pendingLinks || (engine._pendingLinks = []);
    pending.push({
      from: device.id,
      to: other,
      via: anomaly.detector,
      ts: anomaly.ts,
      incident: device.incident,
    });
    while (pending.length > PENDING_CAP) pending.shift();
  }
  const links = (engine._pendingLinks || []).filter(
    (/** @type {any} */ link) =>
      link.to === device.id && anomaly.ts - link.ts <= engine.opts.linkMs && link.incident,
  );
  if (links.length === 0) return;
  let campaign = findOpen(engine, device.id, links[0].from);
  const opened = !campaign;
  if (!campaign) {
    const open = openCampaigns(engine);
    if (open.length >= OPEN_CAP) open.shift();
    engine._campaignSeq = (engine._campaignSeq || 0) + 1;
    campaign = {
      id: `c${engine._campaignSeq}`,
      devices: [],
      edges: [],
      stages: new Set(),
      anomalyIds: [],
      incidents: [],
      score: 0,
      severity: 'medium',
      firstTs: anomaly.ts,
      lastTs: anomaly.ts,
    };
    open.push(campaign);
  }
  const before = campaign.severity;
  absorb(campaign, links[0].incident);
  absorb(campaign, device.incident);
  for (const link of /** @type {any[]} */ (links)) {
    if (campaign.edges.length >= EDGE_CAP) break;
    campaign.edges.push({ from: link.from, to: link.to, via: link.via, ts: link.ts });
  }
  engine._pendingLinks = (engine._pendingLinks || []).filter(
    (/** @type {any} */ link) => !links.includes(link),
  );
  score(campaign);
  campaign.lastTs = anomaly.ts;
  if (opened || rankOf(campaign.severity) > rankOf(before)) {
    engine.emit('campaign', payload(campaign));
  }
}

/**
 * @param {any} event
 * @param {any} anomaly
 * @returns {string[]}
 */
function targetsOf(event, anomaly) {
  /** @type {string[]} */
  const out = [];
  if (event && event.direction === 'lan' && typeof event.dstIp === 'string') out.push(event.dstIp);
  const data = anomaly.data || {};
  if (Array.isArray(data.targets)) {
    for (const item of data.targets) if (typeof item === 'string') out.push(item);
  }
  return out;
}

/**
 * @param {any} campaign
 * @param {any} incident
 */
function absorb(campaign, incident) {
  if (!incident) return;
  if (!campaign.devices.includes(incident.device)) campaign.devices.push(incident.device);
  if (!campaign.incidents.includes(incident)) campaign.incidents.push(incident);
  for (const stage of incident.stages) campaign.stages.add(stage);
  for (const id of incident.anomalyIds) {
    if (!campaign.anomalyIds.includes(id)) campaign.anomalyIds.push(id);
  }
  if (incident.firstTs < campaign.firstTs) campaign.firstTs = incident.firstTs;
}

/**
 * @param {any} campaign
 */
function score(campaign) {
  let best = 0;
  for (const incident of campaign.incidents) best = Math.max(best, incident.score || 0);
  const extra = Math.max(0, campaign.devices.length - 1);
  campaign.score = Math.min(100, best + 10 * extra);
  campaign.severity =
    campaign.devices.length >= 3 || campaign.stages.size >= 3
      ? 'critical'
      : campaign.score >= 70
        ? 'high'
        : 'medium';
}

/**
 * @param {string} severity
 */
function rankOf(severity) {
  return /** @type {Record<string, number>} */ (RANK)[severity] || 0;
}

/**
 * @param {any} engine
 * @param {string} left
 * @param {string} right
 */
function findOpen(engine, left, right) {
  for (const campaign of openCampaigns(engine)) {
    if (campaign.devices.includes(left) && campaign.devices.includes(right)) return campaign;
  }
  for (const campaign of openCampaigns(engine)) {
    if (campaign.devices.includes(left) || campaign.devices.includes(right)) return campaign;
  }
  return null;
}

/**
 * @param {any} engine
 */
function openCampaigns(engine) {
  if (!engine._campaigns) engine._campaigns = [];
  return engine._campaigns;
}

/**
 * @param {any} engine
 * @param {number} ts
 */
function closeOld(engine, ts) {
  const windowMs = engine.opts.incidentWindowMs;
  engine._campaigns = openCampaigns(engine).filter(
    (/** @type {any} */ campaign) => ts - campaign.lastTs <= windowMs,
  );
}

/**
 * @param {any} campaign
 */
function payload(campaign) {
  const stages = [...campaign.stages];
  return {
    id: campaign.id,
    devices: campaign.devices.slice(),
    edges: campaign.edges.map((/** @type {any} */ edge) => ({ ...edge })),
    stages,
    score: campaign.score,
    severity: campaign.severity,
    firstTs: campaign.firstTs,
    lastTs: campaign.lastTs,
    summary: `${campaign.devices.join(', ')} ${stages.join(', ')}`,
    anomalyIds: campaign.anomalyIds.slice(),
  };
}

module.exports = { noteCampaign };
