# Errors

`HubvikError` is what `packages/core` throws. `code` is stable. The message may name the field or the value that failed.

Catch `HubvikError` and branch on `code`. A host that only needs the text can read `message`.

## AGG_IS_INVALID

Cause: '${}.agg is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## AGG_IS_INVALID_2

Cause: '${}.agg.${} is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ALERTED_MUST_BE_AN_ARRAY

Cause: 'alerted must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ALLOWED_MUST_BE_AN_ARRAY

Cause: 'allowed must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ALLOWED_MUST_BE_STRINGS

Cause: 'allowed must be strings'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ALLOW_KIND_IS_INVALID

Cause: 'allow kind is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ALLOW_VALUE_IS_INVALID

Cause: 'allow value is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ANOMALY_ID_IS_INVALID

Cause: 'anomaly id is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ANNOTATION_INVALID

Cause: 'annotation is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ANSWER_DRIFT_ANSWERS_MUST_BE_AN_ARRAY

Cause: 'answer-drift answers must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## APP_PROTO_IS_INVALID

Cause: 'app proto is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## APP_ROLE_IS_INVALID

Cause: 'app role is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_ALERTED_EXCEEDS_CAP

Cause: 'array alerted exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_ALLOWED_EXCEEDS_CAP

Cause: 'array allowed exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_ANSWER_DRIFT_ANSWERS_EXCEEDS_CAP

Cause: 'array answer-drift.answers exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_BEACON_CHANGE_LEARNED_EXCEEDS_CAP

Cause: 'array beacon-change.learned exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_BINDINGS_EXCEEDS_CAP

Cause: 'array bindings exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_BSSIDS_EXCEEDS_CAP

Cause: 'array bssids exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_BUCKETS_EXCEEDS_CAP

Cause: 'array buckets exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_EXCEEDS_CAP

Cause: 'array ${} exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_FAMILIES_EXCEEDS_CAP

Cause: 'array families exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_FEEDBACK_EXCEEDS_CAP

Cause: 'array feedback exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_FIRED_EXCEEDS_CAP

Cause: 'array fired exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_GRAPH_EXCEEDS_CAP

Cause: 'array graph exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_GROUPS_EXCEEDS_CAP

Cause: 'array groups exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_HOURS_EXCEEDS_CAP

Cause: 'array hours exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_IDENTITY_EXCEEDS_CAP

Cause: 'array identity exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_INDICATORS_EXCEEDS_CAP

Cause: 'array indicators exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_ISSUERS_EXCEEDS_CAP

Cause: 'array issuers exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_KEYS_EXCEEDS_CAP

Cause: 'array keys exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_LEARNED_EXCEEDS_CAP

Cause: 'array learned exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_MACS_EXCEEDS_CAP

Cause: 'array macs exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_MAX_EXCEEDS_CAP

Cause: 'array max exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_OT_SPOOF_OWNERS_EXCEEDS_CAP

Cause: 'array ot-spoof.owners exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_OT_VALUE_OUT_OF_RANGE_RANGES_EXCEEDS_CAP

Cause: 'array ot-value-out-of-range.ranges exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_PAIRS_EXCEEDS_CAP

Cause: 'array pairs exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_PARTIALS_EXCEEDS_CAP

Cause: 'array partials exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_ROWS_EXCEEDS_CAP

Cause: 'array rows exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_RULES_EXCEEDS_CAP

Cause: 'array rules exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_SAMPLES_EXCEEDS_CAP

Cause: 'array samples exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_SEEN_EXCEEDS_CAP

Cause: 'array seen exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_SESSIONS_EXCEEDS_CAP

Cause: 'array sessions exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_SOURCES_EXCEEDS_CAP

Cause: 'array sources exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_SSIDS_EXCEEDS_CAP

Cause: 'array ssids exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_SUMMARIES_EXCEEDS_CAP

Cause: 'array summaries exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ARRAY_TRACKS_EXCEEDS_CAP

Cause: 'array tracks exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## AT_MOST_4_CANARIES

Cause: 'at most 4 canaries'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## AUDIT_ARGS_ARE_INVALID

Cause: 'audit args are invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## AUDIT_KEY_IS_INVALID

Cause: 'audit key is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## AUDIT_KIND_IS_INVALID

Cause: 'audit kind is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## AUDIT_LOG_IS_INVALID

Cause: 'audit log is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## AUDIT_RECORD_IS_INVALID

Cause: 'audit record is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## AUDIT_SEQ_IS_INVALID

Cause: 'audit seq is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## AUDIT_STATE_IS_INVALID

Cause: 'audit state is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## AUDIT_TS_IS_INVALID

Cause: 'audit ts is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## BASELINE_DETECTORS_ARE_INVALID

Cause: 'baseline detectors are invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## BASELINE_DEVICES_ARE_INVALID

Cause: 'baseline devices are invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## BASELINE_DEVICE_IS_INVALID

Cause: 'baseline device is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## BASELINE_IS_INVALID

Cause: '${}.${}.baseline is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## BASELINE_SIGNATURE_MISMATCH

Cause: 'baseline signature mismatch'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## BEACON_CHANGE_LEARNED_MUST_BE_AN_ARRAY

Cause: 'beacon-change learned must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## BINDINGS_MUST_BE_PAIRS

Cause: 'bindings must be pairs'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## BUCKETS_MUST_BE_AN_ARRAY

Cause: 'buckets must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## BUCKET_IS_INVALID

Cause: 'bucket is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## BUDGET_CLOCK_MUST_BE_A_FUNCTION

Cause: 'budget.clock must be a function'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## BUDGET_MUST_BE_AN_OBJECT

Cause: 'budget must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## BY_IS_INVALID

Cause: '${}.by is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CAP_MUST_BE_A_POSITIVE_INTEGER

Cause: 'cap must be a positive integer'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CATEGORY_IS_INVALID

Cause: '${}.category is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_DELTA_HASH_DOES_NOT_MATCH

Cause: 'checkpoint delta hash does not match'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_DELTA_IS_INVALID

Cause: 'checkpoint delta is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_DELTA_IS_OUT_OF_ORDER

Cause: 'checkpoint delta is out of order'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_FEEDBACK_IS_INVALID

Cause: 'checkpoint feedback is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_GRAPH_IS_INVALID

Cause: 'checkpoint graph is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_HORIZON_IS_INVALID

Cause: 'checkpoint horizon is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_LIVE_STATE_IS_INVALID

Cause: 'checkpoint live state is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_REORDER_BUFFER_EXCEEDS_CAP

Cause: 'checkpoint reorder buffer exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_REORDER_BUFFER_IS_INVALID

Cause: 'checkpoint reorder buffer is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_SCRATCH_ARP_SPOOF_IS_INVALID

Cause: 'checkpoint scratch arp-spoof is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_SCRATCH_DHCP_STARVATION_IS_INVALID

Cause: 'checkpoint scratch dhcp-starvation is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_SCRATCH_FLEET_WAVE_IS_INVALID

Cause: 'checkpoint scratch fleet-wave is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_SCRATCH_IDENTITY_CHANGE_IS_INVALID

Cause: 'checkpoint scratch identity-change is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_SCRATCH_IDENTITY_IS_INVALID

Cause: 'checkpoint scratch identity is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_SCRATCH_IS_INVALID

Cause: 'checkpoint scratch is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_SCRATCH_IS_INVALID_2

Cause: 'checkpoint scratch ${} is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_SCRATCH_ND_SPOOF_IS_INVALID

Cause: 'checkpoint scratch nd-spoof is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_SCRATCH_WIFI_DEAUTH_FLOOD_IS_INVALID

Cause: 'checkpoint scratch wifi-deauth-flood is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_STATE_IS_INVALID

Cause: 'checkpoint state is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_WATERMARK_IS_INVALID

Cause: 'checkpoint watermark is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CMS_STATE_MUST_BE_AN_OBJECT

Cause: 'cms state must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CONSUMES_MUST_BE_AN_ARRAY

Cause: '${} consumes must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CONSUMES_UNKNOWN_EVENT_TYPE

Cause: '${} consumes unknown event type'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## COUNT_IS_INVALID

Cause: '${} count is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CUSUM_ALARMED_IS_INVALID

Cause: 'cusum.alarmed is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CUSUM_H_IS_INVALID

Cause: 'cusum.h is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CUSUM_K_IS_INVALID

Cause: 'cusum.k is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CUSUM_MEAN_IS_INVALID

Cause: 'cusum.mean is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CUSUM_OPTIONS_MUST_BE_AN_OBJECT

Cause: 'cusum options must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CUSUM_SIDE_IS_INVALID

Cause: 'cusum side is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CUSUM_STATE_MUST_BE_AN_OBJECT

Cause: 'cusum state must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DAYOF_MUST_BE_A_FUNCTION

Cause: 'dayOf must be a function'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DETECTORS_CANARY_MUST_BE_AN_OBJECT

Cause: 'detectors.${}.canary must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DETECTORS_ENABLED_MUST_BE_BOOLEAN

Cause: 'detectors.${}.enabled must be boolean'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DETECTORS_MODE_MUST_BE_LIVE_OR_SHADOW

Cause: 'detectors.${}.mode must be live or shadow'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DETECTORS_MUST_BE_AN_ARRAY

Cause: 'detectors must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DETECTORS_MUST_BE_AN_OBJECT

Cause: 'detectors must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DETECTORS_MUST_BE_AN_OBJECT_2

Cause: 'detectors.${} must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DETECTORS_SEVERITY_IS_INVALID

Cause: 'detectors.${}.severity is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DETECTOR_DEFAULTS_IS_INVALID

Cause: 'detector.defaults is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DETECTOR_ID_IS_INVALID

Cause: 'detector.id is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DETECTOR_IS_ALREADY_REGISTERED

Cause: 'detector ${} is already registered'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DETECTOR_MUST_BE_AN_OBJECT

Cause: 'detector must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DETECTOR_REQUIRES_IS_INVALID

Cause: 'detector.requires is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DETECTOR_STATE_VERSION_MISMATCH_FOR

Cause: 'detector state version mismatch for ${}'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DETECTOR_VERSION_IS_INVALID

Cause: 'detector.version is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DEVICE_CLASS_IS_INVALID

Cause: 'device class is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DEVICE_ID_IS_INVALID

Cause: 'device id is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ATTACKS_SINCE_IS_INVALID

Cause: 'attacks sinceTs is invalid'.
Fix: pass a finite number of milliseconds. The library does not modify traffic.

## DIGEST_SINCE_IS_INVALID

Cause: 'digest sinceTs is invalid'.
Fix: pass a finite number of milliseconds. The library does not modify traffic.

## COUNTS_SINCE_IS_INVALID

Cause: 'counts sinceTs is invalid'.
Fix: pass a finite number of milliseconds. The library does not modify traffic.

## HINTS_SINCE_IS_INVALID

Cause: 'hints sinceTs is invalid'.
Fix: pass a finite number of milliseconds. The library does not modify traffic.

## QUIET_MS_IS_INVALID

Cause: 'quiet ms is invalid'.
Fix: pass a finite number of milliseconds that is zero or greater. The library does not modify traffic.

## OPEN_INCIDENTS_NOW_IS_INVALID

Cause: 'open incidents now is invalid'.
Fix: pass a finite timestamp in milliseconds. The library does not modify traffic.

## QUIET_NOW_IS_INVALID

Cause: 'quiet now is invalid'.
Fix: pass a finite timestamp in milliseconds. The library does not modify traffic.

## SHADOW_SINCE_IS_INVALID

Cause: 'shadow sinceTs is invalid'.
Fix: pass a finite number of milliseconds. The library does not modify traffic.

## CAMPAIGNS_NOW_IS_INVALID

Cause: 'campaigns now is invalid'.
Fix: pass a finite timestamp in milliseconds. The library does not modify traffic.

## OVERVIEW_NOW_IS_INVALID

Cause: 'overview now is invalid'.
Fix: pass a finite timestamp in milliseconds. The library does not modify traffic.

## OVERVIEW_SINCE_IS_INVALID

Cause: 'overview sinceTs is invalid'.
Fix: pass a finite number of milliseconds, or leave it out. The library does not modify traffic.

## WAVES_SINCE_IS_INVALID

Cause: 'waves sinceTs is invalid'.
Fix: pass a finite number of milliseconds. The library does not modify traffic.

## DNS_QNAME_IS_INVALID

Cause: 'dns qname is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DRIFT_DAY_IS_INVALID

Cause: 'drift day is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DRIFT_DEVICE_IS_INVALID

Cause: 'drift device is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DRIFT_SERIES_IS_INVALID

Cause: 'drift series is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DRIFT_SIGMA_IS_INVALID

Cause: 'drift sigma is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DRIFT_STATE_IS_INVALID

Cause: 'drift state is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## DRIFT_VALUE_IS_INVALID

Cause: 'drift value is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## EVENTS_MUST_BE_AN_ARRAY

Cause: 'events must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## EVENT_DEVICE_IS_REQUIRED

Cause: 'event.device is required'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## EVENT_DEVICE_IS_RESERVED

Cause: 'event.device is reserved'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## EVENT_MUST_BE_AN_OBJECT

Cause: 'event must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## EVENT_REQUIRES

Cause: '${} event requires ${}'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## EVENT_TYPE_IS_INVALID

Cause: 'event.type is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## EWMA_ALPHA_IS_INVALID

Cause: 'ewma.alpha is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## EWMA_COUNT_IS_INVALID

Cause: 'ewma.count is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## EWMA_HALFLIFE_IS_INVALID

Cause: 'ewma.halfLife is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## EWMA_MEAN_IS_INVALID

Cause: 'ewma.mean is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## EWMA_OPTIONS_MUST_BE_AN_OBJECT

Cause: 'ewma options must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## EWMA_STATE_MUST_BE_AN_OBJECT

Cause: 'ewma state must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## EWMA_VARIANCE_IS_INVALID

Cause: 'ewma.variance is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## FAMILIES_MUST_BE_AN_ARRAY

Cause: 'families must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## FAMILIES_MUST_BE_OBJECTS

Cause: 'families must be objects'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## FAMILIES_MUST_BE_STRINGS

Cause: 'families must be strings'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## FAMILY_TIME_IS_INVALID

Cause: 'family time is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## FEEDBACK_OPTIONS_MUST_BE_AN_OBJECT

Cause: 'feedback options must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## FIRED_MUST_BE_STRINGS

Cause: 'fired must be strings'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## FLOW_DIRECTION_IS_INVALID

Cause: 'flow direction is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## FLOW_PROTO_IS_INVALID

Cause: 'flow proto is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## FLUSH_TIME_IS_INVALID

Cause: 'flush time is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## FORBIDDEN_KEY

Cause: 'forbidden key ${}'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## FORBIDDEN_KEY_AT

Cause: 'forbidden key ${} at ${}'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## GATEWAYID_IS_INVALID

Cause: 'gatewayId is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## GROUPBY_IS_INVALID

Cause: '${}.groupBy is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## HLL_PRECISION_MISMATCH

Cause: 'hll precision mismatch'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## HLL_P_IS_INVALID

Cause: 'hll.p is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## HLL_STATE_MUST_BE_AN_OBJECT

Cause: 'hll state must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## HOUROF_MUST_BE_A_FUNCTION

Cause: 'hourOf must be a function'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## HOURS_MUST_BE_0_23

Cause: 'hours must be 0..23'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## HOURS_MUST_BE_24_ARRAYS

Cause: 'hours must be 24 arrays'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## HOURS_MUST_BE_AN_ARRAY

Cause: 'hours must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## HOURS_MUST_BE_NUMBERS

Cause: 'hours must be numbers'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## IDENTITY_MUST_BE_OFF_OR_AUTO

Cause: 'identity must be off or auto'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ID_IS_INVALID

Cause: '${}.id is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## INDICATORS_MUST_BE_AN_ARRAY

Cause: 'indicators must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## INDICATOR_CIDR_IS_INVALID

Cause: 'indicator cidr is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## INDICATOR_IP_IS_INVALID

Cause: 'indicator ip is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## INDICATOR_MUST_BE_AN_OBJECT

Cause: 'indicator must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## INDICATOR_SOURCE_IS_INVALID

Cause: 'indicator.source is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## INDICATOR_TYPE_IS_INVALID

Cause: 'indicator.type is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## INDICATOR_VALUE_IS_INVALID

Cause: 'indicator.value is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ISSUERS_MUST_BE_PAIRS

Cause: 'issuers must be pairs'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## IS_INVALID

Cause: '${} ${} is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## IS_INVALID_2

Cause: '${} is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## IS_INVALID_3

Cause: '${}.${} is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## IS_INVALID_4

Cause: '${}.${}.${} is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## IS_NOT_A_MULTIPLE_OF_WINDOWMS

Cause: '${} is not a multiple of windowMs'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## KEYS_MUST_BE_AN_ARRAY

Cause: 'keys must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## KEYS_MUST_BE_OBJECTS

Cause: 'keys must be objects'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## KEYS_MUST_BE_STRINGS

Cause: 'keys must be strings'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## KEY_TIME_IS_INVALID

Cause: 'key time is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## LEARNED_MUST_BE_AN_ARRAY

Cause: 'learned must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## LEARNED_MUST_BE_A_DESTINATION_AND_A_COUNT

Cause: 'learned must be a destination and a count'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## LEARNED_MUST_BE_PAIRS

Cause: 'learned must be pairs'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## LENGTH_MISMATCH

Cause: '${} length mismatch'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## LOOKUP_MUST_BE_A_FUNCTION

Cause: 'lookup must be a function'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MACS_MUST_BE_AN_ARRAY

Cause: 'macs must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MACS_MUST_BE_PAIRS

Cause: 'macs must be pairs'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MACS_MUST_BE_STRINGS

Cause: 'macs must be strings'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MAPPING_PROTO_IS_INVALID

Cause: 'mapping proto is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MATCH_IS_INVALID

Cause: 'match is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MAXGAP_IS_INVALID

Cause: 'maxGap is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MAX_ENTRIES_ARE_INVALID

Cause: 'max entries are invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MAX_IS_INVALID

Cause: '${} max is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MAX_MUST_BE_AN_ARRAY

Cause: 'max must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MAX_MUST_BE_A_NUMBER

Cause: 'max must be a number'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MODE_IS_INVALID

Cause: '${}.mode is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MUD_ACL_IS_INVALID

Cause: 'mud acl is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MUD_ALLOWS_IS_INVALID

Cause: 'mud allows is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MUD_ALLOW_IS_INVALID

Cause: 'mud allow is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MUD_DIRECTION_IS_INVALID

Cause: 'mud direction is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MUD_DOMAIN_IS_INVALID

Cause: 'mud domain is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MUD_DSTPORT_IS_INVALID

Cause: 'mud dstPort is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MUD_PROTO_IS_INVALID

Cause: 'mud proto is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MUST_BE_AN_ARRAY

Cause: '${} must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MUST_BE_AN_INTEGER

Cause: '${} must be an integer'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MUST_BE_A_BOOLEAN

Cause: '${} must be a boolean'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MUST_BE_A_FINITE_NUMBER

Cause: '${} must be a finite number >= ${}'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MUST_BE_BASE64

Cause: '${} must be base64'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MUST_BE_STRINGS

Cause: '${} must be strings'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ND_IP_MUST_BE_IPV6

Cause: 'nd.ip must be IPv6'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ND_MAC_IS_INVALID

Cause: 'nd.mac is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ND_OP_IS_INVALID

Cause: 'nd.op is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## NEW_DESTINATION_STATE_IS_INVALID

Cause: 'new-destination state is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## NOTE_IS_INVALID

Cause: 'note is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## OPERATOR_IS_INVALID

Cause: 'operator is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## OPTIONS_MUST_BE_AN_OBJECT

Cause: 'options must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## OT_SPOOF_OWNERS_MUST_BE_AN_ARRAY

Cause: 'ot-spoof owners must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## OT_VALUE_OUT_OF_RANGE_RANGES_MUST_BE_AN_ARRAY

Cause: 'ot-value-out-of-range ranges must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## P2_COUNT_IS_INVALID

Cause: 'p2.count is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## P2_MARKERS_IS_INVALID

Cause: 'p2.markers is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## P2_P_IS_INVALID

Cause: 'p2.p is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## P2_STATE_MUST_BE_AN_OBJECT

Cause: 'p2 state must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## PAGEHINKLEY_ALARMED_IS_INVALID

Cause: 'pagehinkley.alarmed is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## PAGEHINKLEY_COUNT_IS_INVALID

Cause: 'pagehinkley.count is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## PAGEHINKLEY_DELTA_IS_INVALID

Cause: 'pagehinkley.delta is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## PAGEHINKLEY_LAMBDA_IS_INVALID

Cause: 'pagehinkley.lambda is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## PAGEHINKLEY_OPTIONS_MUST_BE_AN_OBJECT

Cause: 'pagehinkley options must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## PAGEHINKLEY_STATE_MUST_BE_AN_OBJECT

Cause: 'pagehinkley state must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## PEER_GROUP_IS_INVALID

Cause: 'peer group is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## POLICY_EXCEEDS_CAP

Cause: 'policy exceeds cap'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## POLICY_ID_IS_INVALID

Cause: 'policy id is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## POLICY_MATCH_IS_INVALID

Cause: 'policy match is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## POLICY_MUST_BE_AN_ARRAY

Cause: 'policy must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## POLICY_RULE_IS_INVALID

Cause: 'policy rule is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## POLICY_SEVERITY_IS_INVALID

Cause: 'policy severity is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## PROMOTE_MUST_BE_FALSE_OR_AN_OBJECT

Cause: 'promote must be false or an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## REDACT_FIELDS_IS_INVALID

Cause: 'redact.fields is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## REDACT_KEY_IS_INVALID

Cause: 'redact.key is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## REDACT_MUST_BE_AN_OBJECT

Cause: 'redact must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## REDACT_REDACTMAP_MUST_BE_A_FUNCTION

Cause: 'redact.redactMap must be a function'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## RULES_ID_IS_DUPLICATED

Cause: 'rules[${}].id is duplicated'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## RULES_MUST_BE_AN_ARRAY

Cause: 'rules must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SAMPLES_MUST_BE_AN_ARRAY

Cause: 'samples must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SAMPLES_MUST_BE_A_NON_NEGATIVE_INTEGER

Cause: 'samples must be a non-negative integer'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SAMPLES_MUST_BE_NON_NEGATIVE_NUMBERS

Cause: 'samples must be non-negative numbers'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SEEN_MUST_BE_AN_ARRAY

Cause: 'seen must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SEEN_MUST_BE_STRINGS

Cause: 'seen must be strings'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SEQUENCE_IS_INVALID

Cause: '${}.sequence is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SEVERITY_IS_INVALID

Cause: '${}.severity is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SHADOW_ID_IS_INVALID

Cause: 'shadow id is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SHADOW_MUST_BE_FALSE_TRUE_OR_AN_ARRAY_OF_IDS

Cause: 'shadow must be false, true, or an array of ids'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SHARDS_MUST_BE_AN_INTEGER_FROM_1_TO_64

Cause: 'shards must be an integer from 1 to 64'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SINCESEQ_IS_INVALID

Cause: 'sinceSeq is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## STATE_IS_INVALID

Cause: '${} state is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## STRING_TOO_LONG

Cause: 'string too long'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SUMMARIES_MUST_BE_AN_ARRAY

Cause: 'summaries must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SUMMARY_GROUPS_ARE_INVALID

Cause: 'summary groups are invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SUMMARY_GROUP_IS_INVALID

Cause: 'summary group is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SUMMARY_IS_INVALID

Cause: 'summary is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SUMMARY_KEY_IS_INVALID

Cause: 'summary key is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SUMMARY_SIGNATURE_IS_INVALID

Cause: 'summary signature is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## TICK_TIME_IS_INVALID

Cause: 'tick time is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## TIERSILENTBYTIER_IS_INVALID

Cause: 'tierSilentByTier.${} is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## TIERSILENTBYTIER_MUST_BE_AN_OBJECT

Cause: 'tierSilentByTier must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## TIERS_MUST_LIST_ONE_OR_MORE_OF_T0_T5

Cause: 'tiers must list one or more of T0..T5'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## TIME_ZONE_IS_INVALID

Cause: 'time zone is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## UNKNOWN_ANOMALY

Cause: 'unknown anomaly'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## UNKNOWN_DETECTOR

Cause: 'unknown detector ${}'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## UNKNOWN_DEVICE

Cause: 'unknown device ${}'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## UNKNOWN_DEVICE_CLASS

Cause: 'unknown device class'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## UNKNOWN_EVENT_TYPE

Cause: 'unknown event type ${}'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## UNKNOWN_SCRATCH_TABLE

Cause: 'unknown scratch table ${}'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## UNSUPPORTED_BASELINE

Cause: 'unsupported baseline'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## UNSUPPORTED_CHECKPOINT

Cause: 'unsupported checkpoint'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## UNTILTS_IS_INVALID

Cause: 'untilTs is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## VERDICT_IS_INVALID

Cause: 'verdict is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## WELFORD_EMPTY_STATE_IS_INVALID

Cause: 'welford empty state is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## WELFORD_M2_IS_INVALID

Cause: 'welford.m2 is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## WELFORD_MIN_IS_ABOVE_MAX

Cause: 'welford.min is above max'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## WELFORD_STATE_MUST_BE_AN_OBJECT

Cause: 'welford state must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## WHEN_IS_INVALID

Cause: '${}.when is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## WHEN_IS_INVALID_2

Cause: '${}.when.${} is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## WIFI_MAC_IS_INVALID

Cause: 'wifi.mac is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## WIFI_OP_IS_INVALID

Cause: 'wifi.op is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## WINDOWMS_MISMATCH

Cause: 'windowMs mismatch'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## WORKER_SHARDS_WAIT_FOR_A_RASPBERRY_PI_4_BENCH

Cause: 'worker shards wait for a Raspberry Pi 4 bench'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## WRONG_TIME_STATE_IS_INVALID

Cause: 'wrong-time state is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ZONES_ARE_INVALID

Cause: 'zones are invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ZONE_CIDR_IS_INVALID

Cause: 'zone cidr is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ZONE_ID_IS_INVALID

Cause: 'zone id is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## ZONE_IS_INVALID

Cause: 'zone is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## WIFI_SSID_IS_REQUIRED

Cause: 'wifi ssid is required'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## BLOOM_STATE_MUST_BE_AN_OBJECT

Cause: 'bloom state must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## BLOOM_TOKEN_MUST_BE_A_STRING

Cause: 'bloom token must be a string'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## HSTREE_POINT_IS_INVALID

Cause: 'hstree point is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## HSTREE_SEED_IS_INVALID

Cause: 'hstree seed is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## HSTREE_STATE_MUST_BE_AN_OBJECT

Cause: 'hstree state must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MINHASH_STATE_MUST_BE_AN_OBJECT

Cause: 'minhash state must be an object'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## MINHASH_TOKEN_MUST_BE_A_STRING

Cause: 'minhash token must be a string'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## SCORING_IS_INVALID

Cause: 'scoring is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## TEMPLATE_INVALID

Cause: 'templates must be an array'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CRITICALITY_IS_INVALID

Cause: 'criticality is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_CORRELATE_IS_INVALID

Cause: 'checkpoint correlate is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## CHECKPOINT_FDR_IS_INVALID

Cause: 'checkpoint fdr is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.

## HAWKES_STATE_IS_INVALID

Cause: 'hawkes state is invalid'.
Fix: change the value that failed the check and call the method again. The library does not modify traffic.
