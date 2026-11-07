# Errors

`HubvikError` is what `packages/core` throws. `code` is stable. The message may name the field or the value that failed.

Catch `HubvikError` and branch on `code`. A host that only needs the text can read `message`. The library does not change traffic.

## Contents

Headings below stay in their existing order. This list only groups them.

### Validation

- [APP_PROTO_IS_INVALID](#app_proto_is_invalid)
- [APP_ROLE_IS_INVALID](#app_role_is_invalid)
- [BUDGET_CLOCK_MUST_BE_A_FUNCTION](#budget_clock_must_be_a_function)
- [BUDGET_MUST_BE_AN_OBJECT](#budget_must_be_an_object)
- [DAYOF_MUST_BE_A_FUNCTION](#dayof_must_be_a_function)
- [DETECTORS_CANARY_MUST_BE_AN_OBJECT](#detectors_canary_must_be_an_object)
- [DETECTORS_ENABLED_MUST_BE_BOOLEAN](#detectors_enabled_must_be_boolean)
- [DETECTORS_MODE_MUST_BE_LIVE_OR_SHADOW](#detectors_mode_must_be_live_or_shadow)
- [DETECTORS_MUST_BE_AN_OBJECT](#detectors_must_be_an_object)
- [DETECTORS_MUST_BE_AN_OBJECT_2](#detectors_must_be_an_object_2)
- [DETECTORS_SEVERITY_IS_INVALID](#detectors_severity_is_invalid)
- [DNS_QNAME_IS_INVALID](#dns_qname_is_invalid)
- [EVENTS_MUST_BE_AN_ARRAY](#events_must_be_an_array)
- [EVENT_DEVICE_IS_REQUIRED](#event_device_is_required)
- [EVENT_DEVICE_IS_RESERVED](#event_device_is_reserved)
- [EVENT_MUST_BE_AN_OBJECT](#event_must_be_an_object)
- [EVENT_REQUIRES](#event_requires)
- [EVENT_TYPE_IS_INVALID](#event_type_is_invalid)
- [FLOW_DIRECTION_IS_INVALID](#flow_direction_is_invalid)
- [FLOW_PROTO_IS_INVALID](#flow_proto_is_invalid)
- [FORBIDDEN_KEY](#forbidden_key)
- [HOUROF_MUST_BE_A_FUNCTION](#hourof_must_be_a_function)
- [IDENTITY_MUST_BE_OFF_OR_AUTO](#identity_must_be_off_or_auto)
- [INDICATOR_CIDR_IS_INVALID](#indicator_cidr_is_invalid)
- [INDICATOR_IP_IS_INVALID](#indicator_ip_is_invalid)
- [INDICATOR_MUST_BE_AN_OBJECT](#indicator_must_be_an_object)
- [INDICATOR_SOURCE_IS_INVALID](#indicator_source_is_invalid)
- [INDICATOR_TYPE_IS_INVALID](#indicator_type_is_invalid)
- [INDICATOR_VALUE_IS_INVALID](#indicator_value_is_invalid)
- [LOOKUP_MUST_BE_A_FUNCTION](#lookup_must_be_a_function)
- [MAPPING_PROTO_IS_INVALID](#mapping_proto_is_invalid)
- [MUST_BE_AN_INTEGER](#must_be_an_integer)
- [MUST_BE_A_BOOLEAN](#must_be_a_boolean)
- [MUST_BE_A_FINITE_NUMBER](#must_be_a_finite_number)
- [ND_IP_MUST_BE_IPV6](#nd_ip_must_be_ipv6)
- [ND_MAC_IS_INVALID](#nd_mac_is_invalid)
- [ND_OP_IS_INVALID](#nd_op_is_invalid)
- [OPTIONS_MUST_BE_AN_OBJECT](#options_must_be_an_object)
- [POLICY_EXCEEDS_CAP](#policy_exceeds_cap)
- [POLICY_ID_IS_INVALID](#policy_id_is_invalid)
- [POLICY_MATCH_IS_INVALID](#policy_match_is_invalid)
- [POLICY_MUST_BE_AN_ARRAY](#policy_must_be_an_array)
- [POLICY_RULE_IS_INVALID](#policy_rule_is_invalid)
- [POLICY_SEVERITY_IS_INVALID](#policy_severity_is_invalid)
- [PROMOTE_MUST_BE_FALSE_OR_AN_OBJECT](#promote_must_be_false_or_an_object)
- [REDACT_FIELDS_IS_INVALID](#redact_fields_is_invalid)
- [REDACT_KEY_IS_INVALID](#redact_key_is_invalid)
- [REDACT_MUST_BE_AN_OBJECT](#redact_must_be_an_object)
- [REDACT_REDACTMAP_MUST_BE_A_FUNCTION](#redact_redactmap_must_be_a_function)
- [SHADOW_ID_IS_INVALID](#shadow_id_is_invalid)
- [SHADOW_MUST_BE_FALSE_TRUE_OR_AN_ARRAY_OF_IDS](#shadow_must_be_false_true_or_an_array_of_ids)
- [TIERSILENTBYTIER_IS_INVALID](#tiersilentbytier_is_invalid)
- [TIERSILENTBYTIER_MUST_BE_AN_OBJECT](#tiersilentbytier_must_be_an_object)
- [TIERS_MUST_LIST_ONE_OR_MORE_OF_T0_T5](#tiers_must_list_one_or_more_of_t0_t5)
- [UNKNOWN_EVENT_TYPE](#unknown_event_type)
- [WIFI_MAC_IS_INVALID](#wifi_mac_is_invalid)
- [WIFI_OP_IS_INVALID](#wifi_op_is_invalid)
- [ZONES_ARE_INVALID](#zones_are_invalid)
- [ZONE_CIDR_IS_INVALID](#zone_cidr_is_invalid)
- [ZONE_ID_IS_INVALID](#zone_id_is_invalid)
- [ZONE_IS_INVALID](#zone_is_invalid)
- [WIFI_SSID_IS_REQUIRED](#wifi_ssid_is_required)
- [SCORING_IS_INVALID](#scoring_is_invalid)

### Baseline and checkpoint

- [ARRAY_IDENTITY_EXCEEDS_CAP](#array_identity_exceeds_cap)
- [ARRAY_SUMMARIES_EXCEEDS_CAP](#array_summaries_exceeds_cap)
- [BASELINE_DETECTORS_ARE_INVALID](#baseline_detectors_are_invalid)
- [BASELINE_DEVICES_ARE_INVALID](#baseline_devices_are_invalid)
- [BASELINE_DEVICE_IS_INVALID](#baseline_device_is_invalid)
- [BASELINE_SIGNATURE_MISMATCH](#baseline_signature_mismatch)
- [CHECKPOINT_DELTA_HASH_DOES_NOT_MATCH](#checkpoint_delta_hash_does_not_match)
- [CHECKPOINT_DELTA_IS_INVALID](#checkpoint_delta_is_invalid)
- [CHECKPOINT_DELTA_IS_OUT_OF_ORDER](#checkpoint_delta_is_out_of_order)
- [CHECKPOINT_LIVE_STATE_IS_INVALID](#checkpoint_live_state_is_invalid)
- [CHECKPOINT_REORDER_BUFFER_EXCEEDS_CAP](#checkpoint_reorder_buffer_exceeds_cap)
- [CHECKPOINT_REORDER_BUFFER_IS_INVALID](#checkpoint_reorder_buffer_is_invalid)
- [CHECKPOINT_SCRATCH_ARP_SPOOF_IS_INVALID](#checkpoint_scratch_arp_spoof_is_invalid)
- [CHECKPOINT_SCRATCH_DHCP_STARVATION_IS_INVALID](#checkpoint_scratch_dhcp_starvation_is_invalid)
- [CHECKPOINT_SCRATCH_FLEET_WAVE_IS_INVALID](#checkpoint_scratch_fleet_wave_is_invalid)
- [CHECKPOINT_SCRATCH_IDENTITY_CHANGE_IS_INVALID](#checkpoint_scratch_identity_change_is_invalid)
- [CHECKPOINT_SCRATCH_IDENTITY_IS_INVALID](#checkpoint_scratch_identity_is_invalid)
- [CHECKPOINT_SCRATCH_IS_INVALID](#checkpoint_scratch_is_invalid)
- [CHECKPOINT_SCRATCH_IS_INVALID_2](#checkpoint_scratch_is_invalid_2)
- [CHECKPOINT_SCRATCH_ND_SPOOF_IS_INVALID](#checkpoint_scratch_nd_spoof_is_invalid)
- [CHECKPOINT_SCRATCH_WIFI_DEAUTH_FLOOD_IS_INVALID](#checkpoint_scratch_wifi_deauth_flood_is_invalid)
- [CHECKPOINT_STATE_IS_INVALID](#checkpoint_state_is_invalid)
- [CHECKPOINT_WATERMARK_IS_INVALID](#checkpoint_watermark_is_invalid)
- [DETECTOR_STATE_VERSION_MISMATCH_FOR](#detector_state_version_mismatch_for)
- [DEVICE_CLASS_IS_INVALID](#device_class_is_invalid)
- [GATEWAYID_IS_INVALID](#gatewayid_is_invalid)
- [MUD_ACL_IS_INVALID](#mud_acl_is_invalid)
- [MUD_ALLOWS_IS_INVALID](#mud_allows_is_invalid)
- [MUD_ALLOW_IS_INVALID](#mud_allow_is_invalid)
- [MUD_DIRECTION_IS_INVALID](#mud_direction_is_invalid)
- [MUD_DOMAIN_IS_INVALID](#mud_domain_is_invalid)
- [MUD_DSTPORT_IS_INVALID](#mud_dstport_is_invalid)
- [MUD_PROTO_IS_INVALID](#mud_proto_is_invalid)
- [SHARDS_MUST_BE_AN_INTEGER_FROM_1_TO_64](#shards_must_be_an_integer_from_1_to_64)
- [SINCESEQ_IS_INVALID](#sinceseq_is_invalid)
- [SUMMARIES_MUST_BE_AN_ARRAY](#summaries_must_be_an_array)
- [SUMMARY_GROUPS_ARE_INVALID](#summary_groups_are_invalid)
- [SUMMARY_GROUP_IS_INVALID](#summary_group_is_invalid)
- [SUMMARY_IS_INVALID](#summary_is_invalid)
- [SUMMARY_KEY_IS_INVALID](#summary_key_is_invalid)
- [SUMMARY_SIGNATURE_IS_INVALID](#summary_signature_is_invalid)
- [TIME_ZONE_IS_INVALID](#time_zone_is_invalid)
- [UNKNOWN_DETECTOR](#unknown_detector)
- [UNKNOWN_SCRATCH_TABLE](#unknown_scratch_table)
- [UNSUPPORTED_BASELINE](#unsupported_baseline)
- [UNSUPPORTED_CHECKPOINT](#unsupported_checkpoint)
- [WINDOWMS_MISMATCH](#windowms_mismatch)
- [WORKER_SHARDS_WAIT_FOR_A_RASPBERRY_PI_4_BENCH](#worker_shards_wait_for_a_raspberry_pi_4_bench)

### Stats primitives

- [CMS_STATE_MUST_BE_AN_OBJECT](#cms_state_must_be_an_object)
- [CUSUM_ALARMED_IS_INVALID](#cusum_alarmed_is_invalid)
- [CUSUM_H_IS_INVALID](#cusum_h_is_invalid)
- [CUSUM_K_IS_INVALID](#cusum_k_is_invalid)
- [CUSUM_MEAN_IS_INVALID](#cusum_mean_is_invalid)
- [CUSUM_OPTIONS_MUST_BE_AN_OBJECT](#cusum_options_must_be_an_object)
- [CUSUM_SIDE_IS_INVALID](#cusum_side_is_invalid)
- [CUSUM_STATE_MUST_BE_AN_OBJECT](#cusum_state_must_be_an_object)
- [EWMA_ALPHA_IS_INVALID](#ewma_alpha_is_invalid)
- [EWMA_COUNT_IS_INVALID](#ewma_count_is_invalid)
- [EWMA_HALFLIFE_IS_INVALID](#ewma_halflife_is_invalid)
- [EWMA_MEAN_IS_INVALID](#ewma_mean_is_invalid)
- [EWMA_OPTIONS_MUST_BE_AN_OBJECT](#ewma_options_must_be_an_object)
- [EWMA_STATE_MUST_BE_AN_OBJECT](#ewma_state_must_be_an_object)
- [EWMA_VARIANCE_IS_INVALID](#ewma_variance_is_invalid)
- [HLL_PRECISION_MISMATCH](#hll_precision_mismatch)
- [HLL_P_IS_INVALID](#hll_p_is_invalid)
- [HLL_STATE_MUST_BE_AN_OBJECT](#hll_state_must_be_an_object)
- [LENGTH_MISMATCH](#length_mismatch)
- [MUST_BE_BASE64](#must_be_base64)
- [P2_COUNT_IS_INVALID](#p2_count_is_invalid)
- [P2_MARKERS_IS_INVALID](#p2_markers_is_invalid)
- [P2_P_IS_INVALID](#p2_p_is_invalid)
- [P2_STATE_MUST_BE_AN_OBJECT](#p2_state_must_be_an_object)
- [PAGEHINKLEY_ALARMED_IS_INVALID](#pagehinkley_alarmed_is_invalid)
- [PAGEHINKLEY_COUNT_IS_INVALID](#pagehinkley_count_is_invalid)
- [PAGEHINKLEY_DELTA_IS_INVALID](#pagehinkley_delta_is_invalid)
- [PAGEHINKLEY_LAMBDA_IS_INVALID](#pagehinkley_lambda_is_invalid)
- [PAGEHINKLEY_OPTIONS_MUST_BE_AN_OBJECT](#pagehinkley_options_must_be_an_object)
- [PAGEHINKLEY_STATE_MUST_BE_AN_OBJECT](#pagehinkley_state_must_be_an_object)
- [WELFORD_EMPTY_STATE_IS_INVALID](#welford_empty_state_is_invalid)
- [WELFORD_M2_IS_INVALID](#welford_m2_is_invalid)
- [WELFORD_MIN_IS_ABOVE_MAX](#welford_min_is_above_max)
- [WELFORD_STATE_MUST_BE_AN_OBJECT](#welford_state_must_be_an_object)
- [BLOOM_STATE_MUST_BE_AN_OBJECT](#bloom_state_must_be_an_object)
- [BLOOM_TOKEN_MUST_BE_A_STRING](#bloom_token_must_be_a_string)
- [HSTREE_POINT_IS_INVALID](#hstree_point_is_invalid)
- [HSTREE_SEED_IS_INVALID](#hstree_seed_is_invalid)
- [HSTREE_STATE_MUST_BE_AN_OBJECT](#hstree_state_must_be_an_object)
- [MINHASH_STATE_MUST_BE_AN_OBJECT](#minhash_state_must_be_an_object)
- [MINHASH_TOKEN_MUST_BE_A_STRING](#minhash_token_must_be_a_string)
- [HAWKES_STATE_IS_INVALID](#hawkes_state_is_invalid)

### Rules and templates

- [AGG_IS_INVALID](#agg_is_invalid)
- [AGG_IS_INVALID_2](#agg_is_invalid_2)
- [ARRAY_GROUPS_EXCEEDS_CAP](#array_groups_exceeds_cap)
- [ARRAY_PARTIALS_EXCEEDS_CAP](#array_partials_exceeds_cap)
- [ARRAY_RULES_EXCEEDS_CAP](#array_rules_exceeds_cap)
- [BASELINE_IS_INVALID](#baseline_is_invalid)
- [BY_IS_INVALID](#by_is_invalid)
- [CATEGORY_IS_INVALID](#category_is_invalid)
- [GROUPBY_IS_INVALID](#groupby_is_invalid)
- [ID_IS_INVALID](#id_is_invalid)
- [IS_INVALID_2](#is_invalid_2)
- [IS_INVALID_3](#is_invalid_3)
- [IS_INVALID_4](#is_invalid_4)
- [IS_NOT_A_MULTIPLE_OF_WINDOWMS](#is_not_a_multiple_of_windowms)
- [MODE_IS_INVALID](#mode_is_invalid)
- [RULES_ID_IS_DUPLICATED](#rules_id_is_duplicated)
- [RULES_MUST_BE_AN_ARRAY](#rules_must_be_an_array)
- [SEQUENCE_IS_INVALID](#sequence_is_invalid)
- [SEVERITY_IS_INVALID](#severity_is_invalid)
- [WHEN_IS_INVALID](#when_is_invalid)
- [WHEN_IS_INVALID_2](#when_is_invalid_2)
- [TEMPLATE_INVALID](#template_invalid)

### Options, reports, and other engine paths

- [ALERTED_MUST_BE_AN_ARRAY](#alerted_must_be_an_array)
- [ALLOWED_MUST_BE_AN_ARRAY](#allowed_must_be_an_array)
- [ALLOWED_MUST_BE_STRINGS](#allowed_must_be_strings)
- [ALLOW_KIND_IS_INVALID](#allow_kind_is_invalid)
- [ALLOW_VALUE_IS_INVALID](#allow_value_is_invalid)
- [ANOMALY_ID_IS_INVALID](#anomaly_id_is_invalid)
- [ANNOTATION_INVALID](#annotation_invalid)
- [ANSWER_DRIFT_ANSWERS_MUST_BE_AN_ARRAY](#answer_drift_answers_must_be_an_array)
- [ARRAY_ALERTED_EXCEEDS_CAP](#array_alerted_exceeds_cap)
- [ARRAY_ALLOWED_EXCEEDS_CAP](#array_allowed_exceeds_cap)
- [ARRAY_ANSWER_DRIFT_ANSWERS_EXCEEDS_CAP](#array_answer_drift_answers_exceeds_cap)
- [ARRAY_BEACON_CHANGE_LEARNED_EXCEEDS_CAP](#array_beacon_change_learned_exceeds_cap)
- [ARRAY_BINDINGS_EXCEEDS_CAP](#array_bindings_exceeds_cap)
- [ARRAY_BSSIDS_EXCEEDS_CAP](#array_bssids_exceeds_cap)
- [ARRAY_BUCKETS_EXCEEDS_CAP](#array_buckets_exceeds_cap)
- [ARRAY_EXCEEDS_CAP](#array_exceeds_cap)
- [ARRAY_FAMILIES_EXCEEDS_CAP](#array_families_exceeds_cap)
- [ARRAY_FEEDBACK_EXCEEDS_CAP](#array_feedback_exceeds_cap)
- [ARRAY_FIRED_EXCEEDS_CAP](#array_fired_exceeds_cap)
- [ARRAY_GRAPH_EXCEEDS_CAP](#array_graph_exceeds_cap)
- [ARRAY_HOURS_EXCEEDS_CAP](#array_hours_exceeds_cap)
- [ARRAY_INDICATORS_EXCEEDS_CAP](#array_indicators_exceeds_cap)
- [ARRAY_ISSUERS_EXCEEDS_CAP](#array_issuers_exceeds_cap)
- [ARRAY_KEYS_EXCEEDS_CAP](#array_keys_exceeds_cap)
- [ARRAY_LEARNED_EXCEEDS_CAP](#array_learned_exceeds_cap)
- [ARRAY_MACS_EXCEEDS_CAP](#array_macs_exceeds_cap)
- [ARRAY_MAX_EXCEEDS_CAP](#array_max_exceeds_cap)
- [ARRAY_OT_SPOOF_OWNERS_EXCEEDS_CAP](#array_ot_spoof_owners_exceeds_cap)
- [ARRAY_OT_VALUE_OUT_OF_RANGE_RANGES_EXCEEDS_CAP](#array_ot_value_out_of_range_ranges_exceeds_cap)
- [ARRAY_PAIRS_EXCEEDS_CAP](#array_pairs_exceeds_cap)
- [ARRAY_ROWS_EXCEEDS_CAP](#array_rows_exceeds_cap)
- [ARRAY_SAMPLES_EXCEEDS_CAP](#array_samples_exceeds_cap)
- [ARRAY_SEEN_EXCEEDS_CAP](#array_seen_exceeds_cap)
- [ARRAY_SESSIONS_EXCEEDS_CAP](#array_sessions_exceeds_cap)
- [ARRAY_SOURCES_EXCEEDS_CAP](#array_sources_exceeds_cap)
- [ARRAY_SSIDS_EXCEEDS_CAP](#array_ssids_exceeds_cap)
- [ARRAY_TRACKS_EXCEEDS_CAP](#array_tracks_exceeds_cap)
- [AT_MOST_4_CANARIES](#at_most_4_canaries)
- [AUDIT_ARGS_ARE_INVALID](#audit_args_are_invalid)
- [AUDIT_KEY_IS_INVALID](#audit_key_is_invalid)
- [AUDIT_KIND_IS_INVALID](#audit_kind_is_invalid)
- [AUDIT_LOG_IS_INVALID](#audit_log_is_invalid)
- [AUDIT_RECORD_IS_INVALID](#audit_record_is_invalid)
- [AUDIT_SEQ_IS_INVALID](#audit_seq_is_invalid)
- [AUDIT_STATE_IS_INVALID](#audit_state_is_invalid)
- [AUDIT_TS_IS_INVALID](#audit_ts_is_invalid)
- [BEACON_CHANGE_LEARNED_MUST_BE_AN_ARRAY](#beacon_change_learned_must_be_an_array)
- [BINDINGS_MUST_BE_PAIRS](#bindings_must_be_pairs)
- [BUCKETS_MUST_BE_AN_ARRAY](#buckets_must_be_an_array)
- [BUCKET_IS_INVALID](#bucket_is_invalid)
- [CAP_MUST_BE_A_POSITIVE_INTEGER](#cap_must_be_a_positive_integer)
- [CHECKPOINT_FEEDBACK_IS_INVALID](#checkpoint_feedback_is_invalid)
- [CHECKPOINT_GRAPH_IS_INVALID](#checkpoint_graph_is_invalid)
- [CHECKPOINT_HORIZON_IS_INVALID](#checkpoint_horizon_is_invalid)
- [CONSUMES_MUST_BE_AN_ARRAY](#consumes_must_be_an_array)
- [CONSUMES_UNKNOWN_EVENT_TYPE](#consumes_unknown_event_type)
- [COUNT_IS_INVALID](#count_is_invalid)
- [DETECTORS_MUST_BE_AN_ARRAY](#detectors_must_be_an_array)
- [DETECTOR_DEFAULTS_IS_INVALID](#detector_defaults_is_invalid)
- [DETECTOR_ID_IS_INVALID](#detector_id_is_invalid)
- [DETECTOR_IS_ALREADY_REGISTERED](#detector_is_already_registered)
- [DETECTOR_MUST_BE_AN_OBJECT](#detector_must_be_an_object)
- [DETECTOR_REQUIRES_IS_INVALID](#detector_requires_is_invalid)
- [DETECTOR_VERSION_IS_INVALID](#detector_version_is_invalid)
- [DEVICE_ID_IS_INVALID](#device_id_is_invalid)
- [ATTACKS_SINCE_IS_INVALID](#attacks_since_is_invalid)
- [DIGEST_SINCE_IS_INVALID](#digest_since_is_invalid)
- [COUNTS_SINCE_IS_INVALID](#counts_since_is_invalid)
- [HINTS_SINCE_IS_INVALID](#hints_since_is_invalid)
- [QUIET_MS_IS_INVALID](#quiet_ms_is_invalid)
- [OPEN_INCIDENTS_NOW_IS_INVALID](#open_incidents_now_is_invalid)
- [QUIET_NOW_IS_INVALID](#quiet_now_is_invalid)
- [SHADOW_SINCE_IS_INVALID](#shadow_since_is_invalid)
- [CAMPAIGNS_NOW_IS_INVALID](#campaigns_now_is_invalid)
- [OVERVIEW_NOW_IS_INVALID](#overview_now_is_invalid)
- [OVERVIEW_SINCE_IS_INVALID](#overview_since_is_invalid)
- [HOUSE_NOW_IS_INVALID](#house_now_is_invalid)
- [HOUSE_QUIET_IS_INVALID](#house_quiet_is_invalid)
- [ATTENTION_NOW_IS_INVALID](#attention_now_is_invalid)
- [TIMELINE_SINCE_IS_INVALID](#timeline_since_is_invalid)
- [TIMELINE_QUIET_IS_INVALID](#timeline_quiet_is_invalid)
- [CHANGES_SINCE_IS_INVALID](#changes_since_is_invalid)
- [CHANGES_QUIET_IS_INVALID](#changes_quiet_is_invalid)
- [AT_DEVICE_IS_INVALID](#at_device_is_invalid)
- [AT_TS_IS_INVALID](#at_ts_is_invalid)
- [AT_LOG_IS_INVALID](#at_log_is_invalid)
- [AT_DEVICE_IS_UNKNOWN](#at_device_is_unknown)
- [AT_LOG_IS_REQUIRED](#at_log_is_required)
- [AT_CHECKPOINT_IS_INVALID](#at_checkpoint_is_invalid)
- [DIFF_BASELINE_IS_INVALID](#diff_baseline_is_invalid)
- [WITHOUT_DEVICE_IS_INVALID](#without_device_is_invalid)
- [WITHOUT_DESTINATION_IS_INVALID](#without_destination_is_invalid)
- [WITHOUT_EVENTS_ARE_INVALID](#without_events_are_invalid)
- [STORY_INCIDENT_IS_INVALID](#story_incident_is_invalid)
- [HOST_FACT_NAME_IS_INVALID](#host_fact_name_is_invalid)
- [SKETCH_KEY_IS_INVALID](#sketch_key_is_invalid)
- [SKETCH_FIELDS_ARE_INVALID](#sketch_fields_are_invalid)
- [SKETCH_BUCKET_IS_INVALID](#sketch_bucket_is_invalid)
- [SKETCH_CAP_IS_INVALID](#sketch_cap_is_invalid)
- [SKETCHES_MUST_BE_AN_ARRAY](#sketches_must_be_an_array)
- [ARRAY_SKETCHES_EXCEEDS_CAP](#array_sketches_exceeds_cap)
- [ALLOW_UPDATES_ARE_INVALID](#allow_updates_are_invalid)
- [WAVES_SINCE_IS_INVALID](#waves_since_is_invalid)
- [DRIFT_DAY_IS_INVALID](#drift_day_is_invalid)
- [DRIFT_DEVICE_IS_INVALID](#drift_device_is_invalid)
- [DRIFT_SERIES_IS_INVALID](#drift_series_is_invalid)
- [DRIFT_SIGMA_IS_INVALID](#drift_sigma_is_invalid)
- [DRIFT_STATE_IS_INVALID](#drift_state_is_invalid)
- [DRIFT_VALUE_IS_INVALID](#drift_value_is_invalid)
- [FAMILIES_MUST_BE_AN_ARRAY](#families_must_be_an_array)
- [FAMILIES_MUST_BE_OBJECTS](#families_must_be_objects)
- [FAMILIES_MUST_BE_STRINGS](#families_must_be_strings)
- [FAMILY_TIME_IS_INVALID](#family_time_is_invalid)
- [FEEDBACK_OPTIONS_MUST_BE_AN_OBJECT](#feedback_options_must_be_an_object)
- [FIRED_MUST_BE_STRINGS](#fired_must_be_strings)
- [FLUSH_TIME_IS_INVALID](#flush_time_is_invalid)
- [FORBIDDEN_KEY_AT](#forbidden_key_at)
- [HOURS_MUST_BE_0_23](#hours_must_be_0_23)
- [HOURS_MUST_BE_24_ARRAYS](#hours_must_be_24_arrays)
- [HOURS_MUST_BE_AN_ARRAY](#hours_must_be_an_array)
- [HOURS_MUST_BE_NUMBERS](#hours_must_be_numbers)
- [INDICATORS_MUST_BE_AN_ARRAY](#indicators_must_be_an_array)
- [ISSUERS_MUST_BE_PAIRS](#issuers_must_be_pairs)
- [IS_INVALID](#is_invalid)
- [KEYS_MUST_BE_AN_ARRAY](#keys_must_be_an_array)
- [KEYS_MUST_BE_OBJECTS](#keys_must_be_objects)
- [KEYS_MUST_BE_STRINGS](#keys_must_be_strings)
- [KEY_TIME_IS_INVALID](#key_time_is_invalid)
- [LEARNED_MUST_BE_AN_ARRAY](#learned_must_be_an_array)
- [LEARNED_MUST_BE_A_DESTINATION_AND_A_COUNT](#learned_must_be_a_destination_and_a_count)
- [LEARNED_MUST_BE_PAIRS](#learned_must_be_pairs)
- [MACS_MUST_BE_AN_ARRAY](#macs_must_be_an_array)
- [MACS_MUST_BE_PAIRS](#macs_must_be_pairs)
- [MACS_MUST_BE_STRINGS](#macs_must_be_strings)
- [MATCH_IS_INVALID](#match_is_invalid)
- [MAXGAP_IS_INVALID](#maxgap_is_invalid)
- [MAX_ENTRIES_ARE_INVALID](#max_entries_are_invalid)
- [MAX_IS_INVALID](#max_is_invalid)
- [MAX_MUST_BE_AN_ARRAY](#max_must_be_an_array)
- [MAX_MUST_BE_A_NUMBER](#max_must_be_a_number)
- [MUST_BE_AN_ARRAY](#must_be_an_array)
- [MUST_BE_STRINGS](#must_be_strings)
- [NEW_DESTINATION_STATE_IS_INVALID](#new_destination_state_is_invalid)
- [NOTE_IS_INVALID](#note_is_invalid)
- [OPERATOR_IS_INVALID](#operator_is_invalid)
- [OT_SPOOF_OWNERS_MUST_BE_AN_ARRAY](#ot_spoof_owners_must_be_an_array)
- [OT_VALUE_OUT_OF_RANGE_RANGES_MUST_BE_AN_ARRAY](#ot_value_out_of_range_ranges_must_be_an_array)
- [PEER_GROUP_IS_INVALID](#peer_group_is_invalid)
- [SAMPLES_MUST_BE_AN_ARRAY](#samples_must_be_an_array)
- [SAMPLES_MUST_BE_A_NON_NEGATIVE_INTEGER](#samples_must_be_a_non_negative_integer)
- [SAMPLES_MUST_BE_NON_NEGATIVE_NUMBERS](#samples_must_be_non_negative_numbers)
- [SEEN_MUST_BE_AN_ARRAY](#seen_must_be_an_array)
- [SEEN_MUST_BE_STRINGS](#seen_must_be_strings)
- [STATE_IS_INVALID](#state_is_invalid)
- [STRING_TOO_LONG](#string_too_long)
- [TICK_TIME_IS_INVALID](#tick_time_is_invalid)
- [UNKNOWN_ANOMALY](#unknown_anomaly)
- [UNKNOWN_DEVICE](#unknown_device)
- [UNKNOWN_DEVICE_CLASS](#unknown_device_class)
- [UNTILTS_IS_INVALID](#untilts_is_invalid)
- [VERDICT_IS_INVALID](#verdict_is_invalid)
- [WRONG_TIME_STATE_IS_INVALID](#wrong_time_state_is_invalid)
- [CRITICALITY_IS_INVALID](#criticality_is_invalid)
- [CHECKPOINT_CORRELATE_IS_INVALID](#checkpoint_correlate_is_invalid)
- [CHECKPOINT_FDR_IS_INVALID](#checkpoint_fdr_is_invalid)

## AGG_IS_INVALID

Cause: `normalizeAgg()` in `packages/core/src/engine/rules.js` throws it when `!agg || typeof agg !== 'object' || Array.isArray(agg)`. The message is "${path}.agg is invalid".
Fix: Pass a value that satisfies "${path}.agg is invalid".

## AGG_IS_INVALID_2

Cause: `normalizeAgg()` in `packages/core/src/engine/rules.js` throws it when `!/^[A-Za-z][A-Za-z0-9]*$/.test(name)`. The message is "${path}.agg.${name} is invalid". `normalizeAgg()` in `packages/core/src/engine/rules.js` throws it when `keys.length !== 1`. The message is "${path}.agg.${name} is invalid". `normalizeAgg()` in `packages/core/src/engine/rules.js` throws it when `kind !== 'count' && kind !== 'sum' && kind !== 'max' && kind !== 'min' && kind !== 'distinct'`. The message is "${path}.agg.${name} is invalid". `normalizeAgg()` in `packages/core/src/engine/rules.js` throws it when `kind !== 'count' && (typeof field !== 'string' || !/^[A-Za-z][A-Za-z0-9]*$/.test(field))`. The message is "${path}.agg.${name} is invalid".
Fix: Pass a value that satisfies "${path}.agg.${name} is invalid".

## ALERTED_MUST_BE_AN_ARRAY

Cause: `readState()` in `packages/core/src/detectors/ttl-anomaly.js` throws it when `!Array.isArray(state.alerted)`. The message is "alerted must be an array".
Fix: Pass an array. The check says "alerted must be an array".

## ALLOWED_MUST_BE_AN_ARRAY

Cause: `importState()` in `packages/core/src/detectors/identity-change.js` throws it when `!Array.isArray(state.allowed)`. The message is "allowed must be an array".
Fix: Pass an array. The check says "allowed must be an array".

## ALLOWED_MUST_BE_STRINGS

Cause: `importState()` in `packages/core/src/detectors/identity-change.js` throws it when `typeof value !== 'string'`. The message is "allowed must be strings".
Fix: Pass a string. The check says "allowed must be strings".

## ALLOW_KIND_IS_INVALID

Cause: `allow()` in `packages/core/src/engine/engine.js` throws it when `!ALLOW_KINDS.includes(kind)`. The message is "allow kind is invalid".
Fix: Pass a value that satisfies "allow kind is invalid".

## ALLOW_VALUE_IS_INVALID

Cause: `allow()` in `packages/core/src/engine/engine.js` throws it when `typeof value !== 'string' || value.length === 0 || value.length > this.opts.maxString`. The message is "allow value is invalid".
Fix: Pass a value that satisfies "allow value is invalid".

## ANOMALY_ID_IS_INVALID

Cause: `ack()` in `packages/core/src/engine/engine.js` throws it when `typeof anomalyId !== 'string' || anomalyId.length === 0`. The message is "anomaly id is invalid". `recordFeedback()` in `packages/core/src/engine/feedback.js` throws it when `typeof key !== 'string' || key.length === 0`. The message is "anomaly id is invalid".
Fix: Pass a value that satisfies "anomaly id is invalid".

## ANNOTATION_INVALID

Cause: `invalid()` in `packages/core/src/engine/annotations.js` throws it when `!times) { times = []; addMap.set(entry.target, times); } times.push(entry.at); } return { next, items: itemMap, adds: addMap }; } /** * @returns {never} */ function invalid(`. The message is "annotation is invalid".
Fix: Pass a value that satisfies "annotation is invalid".

## ANSWER_DRIFT_ANSWERS_MUST_BE_AN_ARRAY

Cause: `importState()` in `packages/core/src/detectors/answer-drift.js` throws it when `!Array.isArray(state.answers)`. The message is "answer-drift answers must be an array".
Fix: Pass an array. The check says "answer-drift answers must be an array".

## APP_PROTO_IS_INVALID

Cause: `appEvent()` in `packages/core/src/engine/validate/app.js` throws it when `!APP_PROTOS.has(raw.proto)`. The message is "app proto is invalid".
Fix: Pass a value that satisfies "app proto is invalid".

## APP_ROLE_IS_INVALID

Cause: `appEvent()` in `packages/core/src/engine/validate/app.js` throws it when `raw.role !== 'client' && raw.role !== 'server'`. The message is "app role is invalid".
Fix: Pass a value that satisfies "app role is invalid".

## ARRAY_ALERTED_EXCEEDS_CAP

Cause: `readState()` in `packages/core/src/detectors/ttl-anomaly.js` throws it when `state.alerted.length > 3`. The message is "array alerted exceeds cap".
Fix: Stay inside the cap. The check says "array alerted exceeds cap".

## ARRAY_ALLOWED_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/identity-change.js` throws it when `state.allowed.length > CAP`. The message is "array allowed exceeds cap".
Fix: Stay inside the cap. The check says "array allowed exceeds cap".

## ARRAY_ANSWER_DRIFT_ANSWERS_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/answer-drift.js` throws it when `state.answers.length > 5000`. The message is "array answer-drift.answers exceeds cap".
Fix: Stay inside the cap. The check says "array answer-drift.answers exceeds cap".

## ARRAY_BEACON_CHANGE_LEARNED_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/beacon-change.js` throws it when `state.learned.length > 5000`. The message is "array beacon-change.learned exceeds cap".
Fix: Stay inside the cap. The check says "array beacon-change.learned exceeds cap".

## ARRAY_BINDINGS_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/arp-spoof.js` throws it when `state.bindings.length > CAP`. The message is "array bindings exceeds cap". `assertRevived()` in `packages/core/src/engine/checkpoint.js` throws it when `arp.bindings.size > 5000`. The message is "array bindings exceeds cap". `assertRevived()` in `packages/core/src/engine/checkpoint.js` throws it when `arp.macIps.size > 5000`. The message is "array bindings exceeds cap". `assertRevived()` in `packages/core/src/engine/checkpoint.js` throws it when `nd.bindings.size > 5000`. The message is "array bindings exceeds cap".
Fix: Stay inside the cap. The check says "array bindings exceeds cap".

## ARRAY_BSSIDS_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/evil-twin.js` throws it when `pair[1].length > CAP`. The message is "array bssids exceeds cap".
Fix: Stay inside the cap. The check says "array bssids exceeds cap".

## ARRAY_BUCKETS_EXCEEDS_CAP

Cause: `readState()` in `packages/core/src/detectors/ttl-anomaly.js` throws it when `state.buckets.length > 3`. The message is "array buckets exceeds cap".
Fix: Stay inside the cap. The check says "array buckets exceeds cap".

## ARRAY_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/bacnet-bbmd-write.js` throws it when `state.clients.length > 64`. The message is "array clients exceeds cap". `importState()` in `packages/core/src/detectors/cname-cloak.js` throws it when `state.families.length > dev.cap`. The message is "array families exceeds cap". `importState()` in `packages/core/src/detectors/cname-cloak.js` throws it when `state.fired.length > dev.cap`. The message is "array fired exceeds cap". `importState()` in `packages/core/src/detectors/dhcp-route-injection.js` throws it when `state.ips.length > CAP`. The message is "array ips exceeds cap". `importState()` in `packages/core/src/detectors/dispersed-flood.js` throws it when `state.rows.length > caps.maxDestinations`. The message is "array rows exceeds cap". `importState()` in `packages/core/src/detectors/doh-bypass.js` throws it when `state.learned.length > CAP`. The message is "array learned exceeds cap". `importState()` in `packages/core/src/detectors/doh-bypass.js` throws it when `state.alerted.length > CAP`. The message is "array alerted exceeds cap". `importState()` in `packages/core/src/detectors/dormant-reactivation.js` throws it when `state.days.length > 64`. The message is "array days exceeds cap". `importState()` in `packages/core/src/detectors/dormant-reactivation.js` throws it when `state.families.length > 256`. The message is "array families exceeds cap". `importState()` in `packages/core/src/detectors/firmware-size-divergence.js` throws it when `state.downloads.length > 32`. The message is "array downloads exceeds cap". `importState()` in `packages/core/src/detectors/flow-shape-change.js` throws it when `state.families.length > CAP`. The message is "array families exceeds cap". `importState()` in `packages/core/src/detectors/graph-contagion.js` throws it when `state.stages.length > STAGES_CAP`. The message is "array stages exceeds cap". `importState()` in `packages/core/src/detectors/graph-contagion.js` throws it when `raw.times.length > 32`. The message is "array times exceeds cap". `importState()` in `packages/core/src/detectors/inbound-lateral.js` throws it when `state.inbound.length > inboundCap`. The message is "array inbound exceeds cap". `importState()` in `packages/core/src/detectors/ja4-churn.js` throws it when `state.max > 10000`. The message is "array max exceeds cap". `importState()` in `packages/core/src/detectors/karma-responder.js` throws it when `state && state.extra && Array.isArray(state.extra) && state.extra.length > CAP`. The message is "array extra exceeds cap". `importState()` in `packages/core/src/detectors/lan-first-seen-domain.js` throws it when `!Number.isInteger(state.count) || state.count < 0 || state.count > 20`. The message is "array count exceeds cap". `importState()` in `packages/core/src/detectors/modbus-address-sweep.js` throws it when `state.max > TARGETS`. The message is "array max exceeds cap". `importState()` in `packages/core/src/detectors/modbus-unit-sweep.js` throws it when `state.max > 256`. The message is "array max exceeds cap". `importState()` in `packages/core/src/detectors/mqtt-retained-command.js` throws it when `state.learned.length > 128`. The message is "array learned exceeds cap". `importState()` in `packages/core/src/detectors/multivariate-outlier.js` throws it when `state.streak > 100`. The message is "array streak exceeds cap". `readNames()` in `packages/core/src/detectors/new-destination.js` throws it when `value.length > max`. The message is "array ${label} exceeds cap". `importState()` in `packages/core/src/detectors/onion-name.js` throws it when `state.seen.length > CAP`. The message is "array seen exceeds cap". `importState()` in `packages/core/src/detectors/rtsp-new-viewer.js` throws it when `state.fired.length > 256`. The message is "array fired exceeds cap". `importState()` in `packages/core/src/detectors/sequence-surprise.js` throws it when `state.known.length > 256`. The message is "array known exceeds cap". `importState()` in `packages/core/src/detectors/sequence-surprise.js` throws it when `state.counts.length > 128`. The message is "array counts exceeds cap". `importState()` in `packages/core/src/detectors/spectral-beacon.js` throws it when `state.tracks.length > TRACKS`. The message is "array tracks exceeds cap". `readStrings()` in `packages/core/src/detectors/state.js` throws it when `value.length > max`. The message is "array ${label} exceeds cap". `importState()` in `packages/core/src/detectors/stun-turn-relay.js` throws it when `state.hosts.length > 64`. The message is "array hosts exceeds cap". `importState()` in `packages/core/src/detectors/suppression-abuse.js` throws it when `state && Array.isArray(state.extra) && state.extra.length > 20`. The message is "array extra exceeds cap". `importState()` in `packages/core/src/detectors/txt-channel.js` throws it when `state.counts.length > CAP`. The message is "array counts exceeds cap". `parseState()` in `packages/core/src/engine/audit.js` throws it when `items.length > CAP`. The message is "array records exceeds cap".
Fix: Stay inside the cap. The check says "array clients exceeds cap". Stay inside the cap. The check says "array families exceeds cap". Stay inside the cap. The check says "array fired exceeds cap". Stay inside the cap. The check says "array ips exceeds cap". Stay inside the cap. The check says "array learned exceeds cap". Stay inside the cap. The check says "array rows exceeds cap". Stay inside the cap. The check says "array alerted exceeds cap". Stay inside the cap. The check says "array days exceeds cap". Stay inside the cap. The check says "array downloads exceeds cap". Stay inside the cap. The check says "array stages exceeds cap". Stay inside the cap. The check says "array times exceeds cap". Stay inside the cap. The check says "array inbound exceeds cap". Stay inside the cap. The check says "array max exceeds cap". Stay inside the cap. The check says "array extra exceeds cap". Stay inside the cap. The check says "array count exceeds cap". Stay inside the cap. The check says "array streak exceeds cap". Stay inside the cap. The check says "array ${label} exceeds cap". Stay inside the cap. The check says "array seen exceeds cap". Stay inside the cap. The check says "array known exceeds cap". Stay inside the cap. The check says "array counts exceeds cap". Stay inside the cap. The check says "array tracks exceeds cap". Stay inside the cap. The check says "array hosts exceeds cap". Stay inside the cap. The check says "array records exceeds cap".

## ARRAY_FAMILIES_EXCEEDS_CAP

Cause: `readFamilies()` in `packages/core/src/detectors/young-domain.js` throws it when `value.length > CAP`. The message is "array families exceeds cap". `readFamilies()` in `packages/core/src/detectors/young-domain.js` throws it when `families.size > CAP`. The message is "array families exceeds cap".
Fix: Stay inside the cap. The check says "array families exceeds cap".

## ARRAY_FEEDBACK_EXCEEDS_CAP

Cause: `readFeedback()` in `packages/core/src/engine/feedback.js` throws it when `raw.length > CAP`. The message is "array feedback exceeds cap".
Fix: Stay inside the cap. The check says "array feedback exceeds cap".

## ARRAY_FIRED_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/policy-violation.js` throws it when `!Array.isArray(fired) || fired.length > 5000`. The message is "array fired exceeds cap".
Fix: Stay inside the cap. The check says "array fired exceeds cap".

## ARRAY_GRAPH_EXCEEDS_CAP

Cause: `importGraph()` in `packages/core/src/engine/graph.js` throws it when `raw.lan.length > engine.opts.maxDevices * LAN_CAP`. The message is "array graph exceeds cap".
Fix: Stay inside the cap. The check says "array graph exceeds cap".

## ARRAY_GROUPS_EXCEEDS_CAP

Cause: `importRuleState()` in `packages/core/src/engine/rules.js` throws it when `!Array.isArray(state.groups) || state.groups.length > GROUP_CAP`. The message is "array groups exceeds cap".
Fix: Stay inside the cap. The check says "array groups exceeds cap".

## ARRAY_HOURS_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/volume-spike-hourly.js` throws it when `hour.length > size`. The message is "array hours exceeds cap". `importState()` in `packages/core/src/detectors/went-silent.js` throws it when `state.hours.length > 64`. The message is "array hours exceeds cap". `read()` in `packages/core/src/detectors/wrong-time.js` throws it when `state.hours.length > 64`. The message is "array hours exceeds cap".
Fix: Stay inside the cap. The check says "array hours exceeds cap".

## ARRAY_IDENTITY_EXCEEDS_CAP

Cause: `assertRevived()` in `packages/core/src/engine/checkpoint.js` throws it when `bindings.size > 50_000`. The message is "array identity exceeds cap".
Fix: Stay inside the cap. The check says "array identity exceeds cap".

## ARRAY_INDICATORS_EXCEEDS_CAP

Cause: `loadIndicators()` in `packages/core/src/engine/engine.js` throws it when `list.length > this.opts.maxIndicators`. The message is "array indicators exceeds cap".
Fix: Stay inside the cap. The check says "array indicators exceeds cap".

## ARRAY_ISSUERS_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/cert-change.js` throws it when `state.issuers.length > 5000`. The message is "array issuers exceeds cap".
Fix: Stay inside the cap. The check says "array issuers exceeds cap".

## ARRAY_KEYS_EXCEEDS_CAP

Cause: `readKeys()` in `packages/core/src/detectors/exploit-probe-http.js` throws it when `value.length > CAP`. The message is "array keys exceeds cap". `readKeys()` in `packages/core/src/detectors/exploit-probe-http.js` throws it when `keys.size > CAP`. The message is "array keys exceeds cap".
Fix: Stay inside the cap. The check says "array keys exceeds cap".

## ARRAY_LEARNED_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/egress-flood.js` throws it when `state.learned.length > caps.maxDestinations`. The message is "array learned exceeds cap".
Fix: Stay inside the cap. The check says "array learned exceeds cap".

## ARRAY_MACS_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/identity-change.js` throws it when `state.macs.length > CAP`. The message is "array macs exceeds cap".
Fix: Stay inside the cap. The check says "array macs exceeds cap".

## ARRAY_MAX_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/horizontal-scan.js` throws it when `state.max.length > 512`. The message is "array max exceeds cap".
Fix: Stay inside the cap. The check says "array max exceeds cap".

## ARRAY_OT_SPOOF_OWNERS_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/ot-spoof.js` throws it when `state.owners.length > 5000`. The message is "array ot-spoof.owners exceeds cap".
Fix: Stay inside the cap. The check says "array ot-spoof.owners exceeds cap".

## ARRAY_OT_VALUE_OUT_OF_RANGE_RANGES_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/ot-value-out-of-range.js` throws it when `state.ranges.length > 5000`. The message is "array ot-value-out-of-range.ranges exceeds cap".
Fix: Stay inside the cap. The check says "array ot-value-out-of-range.ranges exceeds cap".

## ARRAY_PAIRS_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/graph-new-bridge.js` throws it when `state.pairs.length > 256`. The message is "array pairs exceeds cap".
Fix: Stay inside the cap. The check says "array pairs exceeds cap".

## ARRAY_PARTIALS_EXCEEDS_CAP

Cause: `importRuleState()` in `packages/core/src/engine/rules.js` throws it when `!Array.isArray(state.partials) || state.partials.length > PARTIAL_CAP`. The message is "array partials exceeds cap".
Fix: Stay inside the cap. The check says "array partials exceeds cap".

## ARRAY_ROWS_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/cloud-storage-exfil.js` throws it when `state.rows.length > PATTERNS.length`. The message is "array rows exceeds cap".
Fix: Stay inside the cap. The check says "array rows exceeds cap".

## ARRAY_RULES_EXCEEDS_CAP

Cause: `compileRules()` in `packages/core/src/engine/rules.js` throws it when `input.length > RULE_CAP`. The message is "array rules exceeds cap".
Fix: Stay inside the cap. The check says "array rules exceeds cap".

## ARRAY_SAMPLES_EXCEEDS_CAP

Cause: `readSamples()` in `packages/core/src/detectors/samples.js` throws it when `state.samples.length > caps.maxWindows`. The message is "array samples exceeds cap". `readStreamState()` in `packages/core/src/detectors/samples.js` throws it when `state.samples.length > cap`. The message is "array samples exceeds cap". `importState()` in `packages/core/src/detectors/slow-exfil.js` throws it when `state.samples && state.samples.length > 168`. The message is "array samples exceeds cap".
Fix: Stay inside the cap. The check says "array samples exceeds cap".

## ARRAY_SEEN_EXCEEDS_CAP

Cause: `read()` in `packages/core/src/detectors/wrong-time.js` throws it when `keys.length > caps.maxAlertKeys`. The message is "array seen exceeds cap".
Fix: Stay inside the cap. The check says "array seen exceeds cap".

## ARRAY_SESSIONS_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/exploit-then-download.js` throws it when `state.sessions.length > RING`. The message is "array sessions exceeds cap".
Fix: Stay inside the cap. The check says "array sessions exceeds cap".

## ARRAY_SOURCES_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/ssh-brute-then-session.js` throws it when `state.sources.length > CAP`. The message is "array sources exceeds cap".
Fix: Stay inside the cap. The check says "array sources exceeds cap".

## ARRAY_SSIDS_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/evil-twin.js` throws it when `state.ssids.length > 256`. The message is "array ssids exceeds cap".
Fix: Stay inside the cap. The check says "array ssids exceeds cap".

## ARRAY_SUMMARIES_EXCEEDS_CAP

Cause: `importPeerSummaries()` in `packages/core/src/engine/finish09.js` throws it when `list.length > SUMMARY_CAP`. The message is "array summaries exceeds cap".
Fix: Stay inside the cap. The check says "array summaries exceeds cap".

## ARRAY_TRACKS_EXCEEDS_CAP

Cause: `importState()` in `packages/core/src/detectors/jitter-beacon.js` throws it when `state.tracks.length > CAP`. The message is "array tracks exceeds cap".
Fix: Stay inside the cap. The check says "array tracks exceeds cap".

## AT_MOST_4_CANARIES

Cause: `constructor()` in `packages/core/src/engine/engine.js` throws it when `canaries > 4`. The message is "at most 4 canaries".
Fix: Correct the input so this passes: "at most 4 canaries". The library does not change traffic.

## AUDIT_ARGS_ARE_INVALID

Cause: `canonical()` in `packages/core/src/engine/audit.js` throws it when `depth > MAX_DEPTH`. The message is "audit args are invalid". `canonical()` in `packages/core/src/engine/audit.js` throws it when `value.length > MAX_ARG_STRING`. The message is "audit args are invalid". `canonical()` in `packages/core/src/engine/audit.js` throws it when `!Number.isFinite(value)`. The message is "audit args are invalid". `canonical()` in `packages/core/src/engine/audit.js` throws it when `typeof value !== 'object'`. The message is "audit args are invalid". `canonical()` in `packages/core/src/engine/audit.js` throws it when `seen.has(value)`. The message is "audit args are invalid". `canonicalArray()` in `packages/core/src/engine/audit.js` throws it when `value.length > MAX_NODES`. The message is "audit args are invalid". `canonicalArray()` in `packages/core/src/engine/audit.js` throws it when `Object.getOwnPropertySymbols(value).length > 0`. The message is "audit args are invalid". `canonicalObject()` in `packages/core/src/engine/audit.js` throws it when `Object.getOwnPropertySymbols(value).length > 0`. The message is "audit args are invalid". `canonicalObject()` in `packages/core/src/engine/audit.js` throws it when `keys.length > MAX_NODES`. The message is "audit args are invalid".
Fix: Correct the input so this passes: "audit args are invalid". The library does not change traffic.

## AUDIT_KEY_IS_INVALID

Cause: `resolveKey()` in `packages/core/src/engine/audit.js` throws it when `typeof opts !== 'object' || Array.isArray(opts)`. The message is "audit key is invalid". `resolveKey()` in `packages/core/src/engine/audit.js` throws it when `Object.getOwnPropertySymbols(record).length > 0`. The message is "audit key is invalid". `resolveKey()` in `packages/core/src/engine/audit.js` throws it when `key !== 'key'`. The message is "audit key is invalid". `resolveKey()` in `packages/core/src/engine/audit.js` throws it when `typeof record.key !== 'string' || record.key.length > MAX_KEY`. The message is "audit key is invalid". `resolveKey()` in `packages/core/src/engine/audit.js` throws it when `log.records.length !== 0`. The message is "audit key is invalid". `resolveKey()` in `packages/core/src/engine/audit.js` throws it when `record.key !== log.key`. The message is "audit key is invalid". `parseState()` in `packages/core/src/engine/audit.js` throws it when `typeof body.key !== 'string' || body.key.length > MAX_KEY`. The message is "audit key is invalid".
Fix: Pass a value that satisfies "audit key is invalid".

## AUDIT_KIND_IS_INVALID

Cause: `parseInput()` in `packages/core/src/engine/audit.js` throws it when `typeof record.kind !== 'string' || !KINDS.has(record.kind)`. The message is "audit kind is invalid". `parseRecord()` in `packages/core/src/engine/audit.js` throws it when `typeof record.kind !== 'string' || !KINDS.has(record.kind)`. The message is "audit kind is invalid".
Fix: Pass a value that satisfies "audit kind is invalid".

## AUDIT_LOG_IS_INVALID

Cause: `assertLog()` in `packages/core/src/engine/audit.js` throws it when `value === null || typeof value !== 'object' || !instances.has(value)`. The message is "audit log is invalid".
Fix: Pass a value that satisfies "audit log is invalid".

## AUDIT_RECORD_IS_INVALID

Cause: `parseInput()` in `packages/core/src/engine/audit.js` throws it when `raw === null || typeof raw !== 'object' || Array.isArray(raw)`. The message is "audit record is invalid". `parseInput()` in `packages/core/src/engine/audit.js` throws it when `Object.getOwnPropertySymbols(record).length > 0`. The message is "audit record is invalid". `parseInput()` in `packages/core/src/engine/audit.js` throws it when `!INPUT_KEYS.has(key)`. The message is "audit record is invalid". `optionalString()` in `packages/core/src/engine/audit.js` throws it when `typeof value !== 'string'`. The message is "audit record is invalid". `parseRecord()` in `packages/core/src/engine/audit.js` throws it when `raw === null || typeof raw !== 'object' || Array.isArray(raw)`. The message is "audit record is invalid". `parseRecord()` in `packages/core/src/engine/audit.js` throws it when `Object.getOwnPropertySymbols(record).length > 0`. The message is "audit record is invalid". `parseRecord()` in `packages/core/src/engine/audit.js` throws it when `!RECORD_KEYS.has(key)`. The message is "audit record is invalid". `parseRecord()` in `packages/core/src/engine/audit.js` throws it when `!Object.hasOwn(record, key)`. The message is "audit record is invalid". `parseRecord()` in `packages/core/src/engine/audit.js` throws it when `!isHex(record.argsDigest, 16) || !isHex(record.prevHash, 64) || !isHex(record.hash, 64)`. The message is "audit record is invalid". `storedString()` in `packages/core/src/engine/audit.js` throws it when `typeof value !== 'string'`. The message is "audit record is invalid".
Fix: Pass a value that satisfies "audit record is invalid".

## AUDIT_SEQ_IS_INVALID

Cause: `append()` in `packages/core/src/engine/audit.js` throws it when `!Number.isSafeInteger(current.nextSeq) || current.nextSeq < 0`. The message is "audit seq is invalid". `append()` in `packages/core/src/engine/audit.js` throws it when `current.nextSeq >= Number.MAX_SAFE_INTEGER`. The message is "audit seq is invalid". `auditLog()` in `packages/core/src/engine/audit.js` throws it when `typeof record.seq !== 'number' || !Number.isSafeInteger(record.seq)`. The message is "audit seq is invalid". `sinceOf()` in `packages/core/src/engine/audit.js` throws it when `typeof record.sinceSeq !== 'number' || !Number.isSafeInteger(record.sinceSeq) || record.sinceSeq < 0`. The message is "audit seq is invalid". `parseState()` in `packages/core/src/engine/audit.js` throws it when `typeof nextSeq !== 'number' || !Number.isSafeInteger(nextSeq) || nextSeq < 0`. The message is "audit seq is invalid". `parseRecord()` in `packages/core/src/engine/audit.js` throws it when `typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 0`. The message is "audit seq is invalid".
Fix: Pass a value that satisfies "audit seq is invalid".

## AUDIT_STATE_IS_INVALID

Cause: `append()` in `packages/core/src/engine/audit.js` throws it when `typeof current.anchor !== 'string'`. The message is "audit state is invalid". `previousHash()` in `packages/core/src/engine/audit.js` throws it when `!last || typeof last.hash !== 'string'`. The message is "audit state is invalid". `sinceOf()` in `packages/core/src/engine/audit.js` throws it when `typeof opts !== 'object' || Array.isArray(opts)`. The message is "audit state is invalid". `sinceOf()` in `packages/core/src/engine/audit.js` throws it when `Object.getOwnPropertySymbols(record).length > 0`. The message is "audit state is invalid". `sinceOf()` in `packages/core/src/engine/audit.js` throws it when `key !== 'sinceSeq'`. The message is "audit state is invalid". `parseState()` in `packages/core/src/engine/audit.js` throws it when `raw === null || typeof raw !== 'object' || Array.isArray(raw)`. The message is "audit state is invalid". `parseState()` in `packages/core/src/engine/audit.js` throws it when `Object.getOwnPropertySymbols(body).length > 0`. The message is "audit state is invalid". `parseState()` in `packages/core/src/engine/audit.js` throws it when `!STATE_KEYS.has(key)`. The message is "audit state is invalid". `parseState()` in `packages/core/src/engine/audit.js` throws it when `!isHex(anchor, 64)`. The message is "audit state is invalid". `parseState()` in `packages/core/src/engine/audit.js` throws it when `!Array.isArray(items)`. The message is "audit state is invalid".
Fix: Pass a value that satisfies "audit state is invalid".

## AUDIT_TS_IS_INVALID

Cause: `parseInput()` in `packages/core/src/engine/audit.js` throws it when `!Object.hasOwn(record, 'ts')`. The message is "audit ts is invalid". `parseInput()` in `packages/core/src/engine/audit.js` throws it when `typeof ts !== 'number' || !Number.isFinite(ts) || ts < 0`. The message is "audit ts is invalid". `parseRecord()` in `packages/core/src/engine/audit.js` throws it when `typeof ts !== 'number' || !Number.isFinite(ts) || ts < 0`. The message is "audit ts is invalid".
Fix: Pass a value that satisfies "audit ts is invalid".

## BASELINE_DETECTORS_ARE_INVALID

Cause: `prepareImport()` in `packages/core/src/engine/baseline.js` throws it when `!blocks || typeof blocks !== 'object' || Array.isArray(blocks)`. The message is "baseline detectors are invalid".
Fix: Correct the input so this passes: "baseline detectors are invalid". The library does not change traffic.

## BASELINE_DEVICES_ARE_INVALID

Cause: `prepareImport()` in `packages/core/src/engine/baseline.js` throws it when `!raw.devices || typeof raw.devices !== 'object' || Array.isArray(raw.devices)`. The message is "baseline devices are invalid".
Fix: Correct the input so this passes: "baseline devices are invalid". The library does not change traffic.

## BASELINE_DEVICE_IS_INVALID

Cause: `prepareImport()` in `packages/core/src/engine/baseline.js` throws it when `!record || typeof record !== 'object' || Array.isArray(record)`. The message is "baseline device is invalid".
Fix: Pass a value that satisfies "baseline device is invalid".

## BASELINE_IS_INVALID

Cause: `normalizeWhere()` in `packages/core/src/engine/rules.js` throws it when `value !== true`. The message is "${path}.${field}.baseline is invalid".
Fix: Pass a value that satisfies "${path}.${field}.baseline is invalid".

## BASELINE_SIGNATURE_MISMATCH

Cause: `assertSignature()` in `packages/core/src/engine/baseline.js` throws it when `!raw || !raw.sig || raw.sig.alg !== 'HMAC-SHA256' || typeof mac !== 'string' || !/^[0-9a-f]{64}$/i.test(mac)`. The message is "baseline signature mismatch". `assertSignature()` in `packages/core/src/engine/baseline.js` throws it when `left.length !== right.length || !timingSafeEqual(left, right)`. The message is "baseline signature mismatch".
Fix: Correct the input so this passes: "baseline signature mismatch". The library does not change traffic.

## BEACON_CHANGE_LEARNED_MUST_BE_AN_ARRAY

Cause: `importState()` in `packages/core/src/detectors/beacon-change.js` throws it when `!Array.isArray(state.learned)`. The message is "beacon-change learned must be an array".
Fix: Pass an array. The check says "beacon-change learned must be an array".

## BINDINGS_MUST_BE_PAIRS

Cause: `importState()` in `packages/core/src/detectors/arp-spoof.js` throws it when `!Array.isArray(pair) || pair.length !== 2`. The message is "bindings must be pairs".
Fix: Correct the input so this passes: "bindings must be pairs". The library does not change traffic.

## BUCKETS_MUST_BE_AN_ARRAY

Cause: `readState()` in `packages/core/src/detectors/ttl-anomaly.js` throws it when `!Array.isArray(state.buckets)`. The message is "buckets must be an array".
Fix: Pass an array. The check says "buckets must be an array".

## BUCKET_IS_INVALID

Cause: `readState()` in `packages/core/src/detectors/ttl-anomaly.js` throws it when `!BUCKETS.has(value)`. The message is "bucket is invalid".
Fix: Pass a value that satisfies "bucket is invalid".

## BUDGET_CLOCK_MUST_BE_A_FUNCTION

Cause: `parseBudget()` in `packages/core/src/engine/validate/index.js` throws it when `input.clock != null && typeof input.clock !== 'function'`. The message is "budget.clock must be a function".
Fix: Correct the input so this passes: "budget.clock must be a function". The library does not change traffic.

## BUDGET_MUST_BE_AN_OBJECT

Cause: `parseBudget()` in `packages/core/src/engine/validate/index.js` throws it when `!input || typeof input !== 'object' || Array.isArray(input)`. The message is "budget must be an object".
Fix: Correct the input so this passes: "budget must be an object". The library does not change traffic.

## BY_IS_INVALID

Cause: `normalizeSequence()` in `packages/core/src/engine/rules.js` throws it when `by !== 'device' && by !== 'srcIp'`. The message is "${path}.by is invalid".
Fix: Pass a value that satisfies "${path}.by is invalid".

## CAP_MUST_BE_A_POSITIVE_INTEGER

Cause: `constructor()` in `packages/core/src/engine/caps.js` throws it when `!Number.isInteger(max) || max < 1`. The message is "cap must be a positive integer".
Fix: Correct the input so this passes: "cap must be a positive integer". The library does not change traffic.

## CATEGORY_IS_INVALID

Cause: `normalizeRule()` in `packages/core/src/engine/rules.js` throws it when `typeof category !== 'string' || category.length === 0 || category.length > 32`. The message is "${path}.category is invalid".
Fix: Pass a value that satisfies "${path}.category is invalid".

## CHECKPOINT_DELTA_HASH_DOES_NOT_MATCH

Cause: `applyDelta()` in `packages/core/src/engine/finish09.js` throws it when `(delta.prevHash || '') !== (this._deltaHash || '')`. The message is "checkpoint delta hash does not match". `applyDelta()` in `packages/core/src/engine/finish09.js` throws it when `deltaHash(unsigned, key) !== delta.hash`. The message is "checkpoint delta hash does not match".
Fix: Correct the input so this passes: "checkpoint delta hash does not match". The library does not change traffic.

## CHECKPOINT_DELTA_IS_INVALID

Cause: `applyDelta()` in `packages/core/src/engine/finish09.js` throws it when `!delta || typeof delta !== 'object' || Array.isArray(delta)`. The message is "checkpoint delta is invalid".
Fix: Pass a value that satisfies "checkpoint delta is invalid".

## CHECKPOINT_DELTA_IS_OUT_OF_ORDER

Cause: `checkpointDelta()` in `packages/core/src/engine/finish09.js` throws it when `sinceSeq !== from`. The message is "checkpoint delta is out of order". `applyDelta()` in `packages/core/src/engine/finish09.js` throws it when `delta.fromSeq !== from`. The message is "checkpoint delta is out of order".
Fix: Apply checkpoint deltas in order.

## CHECKPOINT_FEEDBACK_IS_INVALID

Cause: `readFeedback()` in `packages/core/src/engine/feedback.js` throws it when `!Array.isArray(raw)`. The message is "checkpoint feedback is invalid". `readFeedback()` in `packages/core/src/engine/feedback.js` throws it when `!row || typeof row !== 'object' || Array.isArray(row)`. The message is "checkpoint feedback is invalid". `readFeedback()` in `packages/core/src/engine/feedback.js` throws it when `typeof row.fingerprint !== 'string' || typeof row.detector !== 'string' || typeof row.device !== 'string' || typeof row.ts !== 'number' || !VERDICTS.has(row.verdict)`. The message is "checkpoint feedback is invalid". `readFeedback()` in `packages/core/src/engine/feedback.js` throws it when `typeof row.operator !== 'string'`. The message is "checkpoint feedback is invalid". `readFeedback()` in `packages/core/src/engine/feedback.js` throws it when `typeof row.note !== 'string'`. The message is "checkpoint feedback is invalid".
Fix: Pass a value that satisfies "checkpoint feedback is invalid".

## CHECKPOINT_GRAPH_IS_INVALID

Cause: `importGraph()` in `packages/core/src/engine/graph.js` throws it when `!raw || typeof raw !== 'object' || !Array.isArray(raw.lan) || !Array.isArray(raw.wan)`. The message is "checkpoint graph is invalid". `importGraph()` in `packages/core/src/engine/graph.js` throws it when `!edge || typeof edge.src !== 'string' || typeof edge.dst !== 'string'`. The message is "checkpoint graph is invalid". `importGraph()` in `packages/core/src/engine/graph.js` throws it when `!edge || typeof edge.src !== 'string' || typeof edge.family !== 'string'`. The message is "checkpoint graph is invalid".
Fix: Pass a value that satisfies "checkpoint graph is invalid".

## CHECKPOINT_HORIZON_IS_INVALID

Cause: `importRow()` in `packages/core/src/engine/horizon.js` throws it when `!raw || typeof raw !== 'object'`. The message is "checkpoint horizon is invalid". `importRow()` in `packages/core/src/engine/horizon.js` throws it when `typeof raw.hour !== 'number' || typeof raw.bytesOut !== 'number'`. The message is "checkpoint horizon is invalid". `importHorizon()` in `packages/core/src/engine/horizon.js` throws it when `!raw || typeof raw !== 'object' || !Array.isArray(raw.rows) || raw.rows.length > RING`. The message is "checkpoint horizon is invalid".
Fix: Pass a value that satisfies "checkpoint horizon is invalid".

## CHECKPOINT_LIVE_STATE_IS_INVALID

Cause: `thawStates()` in `packages/core/src/engine/checkpoint.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "checkpoint live state is invalid". `assertLiveShape()` in `packages/core/src/engine/checkpoint.js` throws it when `live == null || live.constructor !== fresh.constructor`. The message is "checkpoint live state is invalid". `assertLiveShape()` in `packages/core/src/engine/checkpoint.js` throws it when `!Array.isArray(live)`. The message is "checkpoint live state is invalid". `assertLiveShape()` in `packages/core/src/engine/checkpoint.js` throws it when `!live || typeof live !== 'object' || Array.isArray(live)`. The message is "checkpoint live state is invalid". `assertLiveShape()` in `packages/core/src/engine/checkpoint.js` throws it when `!Object.prototype.hasOwnProperty.call(live, key)`. The message is "checkpoint live state is invalid". `_probeLive()` in `packages/core/src/engine/persist.js` throws it when `!det || typeof det.exportState !== 'function' || typeof det.importState !== 'function'`. The message is "checkpoint live state is invalid".
Fix: Pass a value that satisfies "checkpoint live state is invalid".

## CHECKPOINT_REORDER_BUFFER_EXCEEDS_CAP

Cause: `_readReorder()` in `packages/core/src/engine/persist.js` throws it when `raw.length > this.opts.maxBuffered`. The message is "checkpoint reorder buffer exceeds cap".
Fix: Stay inside the cap. The check says "checkpoint reorder buffer exceeds cap".

## CHECKPOINT_REORDER_BUFFER_IS_INVALID

Cause: `_readReorder()` in `packages/core/src/engine/persist.js` throws it when `!Array.isArray(raw)`. The message is "checkpoint reorder buffer is invalid". `_readReorder()` in `packages/core/src/engine/persist.js` throws it when `!item || typeof item !== 'object' || Array.isArray(item)`. The message is "checkpoint reorder buffer is invalid". `_readReorder()` in `packages/core/src/engine/persist.js` throws it when `typeof item.seq !== 'number' || !Number.isInteger(item.seq) || item.seq < 1`. The message is "checkpoint reorder buffer is invalid". `_readReorder()` in `packages/core/src/engine/persist.js` throws it when `!item.event || typeof item.event !== 'object' || Array.isArray(item.event)`. The message is "checkpoint reorder buffer is invalid". `_readReorder()` in `packages/core/src/engine/persist.js` throws it when `checked.event.ts < prevTs || (checked.event.ts === prevTs && item.seq <= prevSeq)`. The message is "checkpoint reorder buffer is invalid".
Fix: Pass a value that satisfies "checkpoint reorder buffer is invalid".

## CHECKPOINT_SCRATCH_ARP_SPOOF_IS_INVALID

Cause: `assertRevived()` in `packages/core/src/engine/checkpoint.js` throws it when `typeof arp !== 'object' || !(arp.bindings instanceof Map) || !(arp.macIps instanceof Map)`. The message is "checkpoint scratch arp-spoof is invalid".
Fix: Pass a value that satisfies "checkpoint scratch arp-spoof is invalid".

## CHECKPOINT_SCRATCH_DHCP_STARVATION_IS_INVALID

Cause: `assertRevived()` in `packages/core/src/engine/checkpoint.js` throws it when `typeof dhcp !== 'object' || !(dhcp.macs instanceof Set)`. The message is "checkpoint scratch dhcp-starvation is invalid".
Fix: Pass a value that satisfies "checkpoint scratch dhcp-starvation is invalid".

## CHECKPOINT_SCRATCH_FLEET_WAVE_IS_INVALID

Cause: `assertRevived()` in `packages/core/src/engine/checkpoint.js` throws it when `!(wave instanceof Map)`. The message is "checkpoint scratch fleet-wave is invalid". `assertRevived()` in `packages/core/src/engine/checkpoint.js` throws it when `!row || typeof row !== 'object' || Array.isArray(row)`. The message is "checkpoint scratch fleet-wave is invalid". `assertRevived()` in `packages/core/src/engine/checkpoint.js` throws it when `!(row.devices instanceof Map) || typeof row.first !== 'number'`. The message is "checkpoint scratch fleet-wave is invalid".
Fix: Pass a value that satisfies "checkpoint scratch fleet-wave is invalid".

## CHECKPOINT_SCRATCH_IDENTITY_CHANGE_IS_INVALID

Cause: `assertRevived()` in `packages/core/src/engine/checkpoint.js` throws it when `typeof learnedMacs !== 'object' || !(learnedMacs.macs instanceof Map)`. The message is "checkpoint scratch identity-change is invalid".
Fix: Pass a value that satisfies "checkpoint scratch identity-change is invalid".

## CHECKPOINT_SCRATCH_IDENTITY_IS_INVALID

Cause: `assertRevived()` in `packages/core/src/engine/checkpoint.js` throws it when `!(bindings instanceof Map)`. The message is "checkpoint scratch identity is invalid". `assertRevived()` in `packages/core/src/engine/checkpoint.js` throws it when `!row || typeof row.mac !== 'string' || typeof row.lastTs !== 'number'`. The message is "checkpoint scratch identity is invalid". `assertRevived()` in `packages/core/src/engine/checkpoint.js` throws it when `row.source !== 'dhcp' && row.source !== 'arp' && row.source !== 'nd'`. The message is "checkpoint scratch identity is invalid".
Fix: Pass a value that satisfies "checkpoint scratch identity is invalid".

## CHECKPOINT_SCRATCH_IS_INVALID

Cause: `assertCheckpoint()` in `packages/core/src/engine/checkpoint.js` throws it when `typeof raw.scratch !== 'object' || Array.isArray(raw.scratch)`. The message is "checkpoint scratch is invalid".
Fix: Pass a value that satisfies "checkpoint scratch is invalid".

## CHECKPOINT_SCRATCH_IS_INVALID_2

Cause: `restore()` in `packages/core/src/engine/persist.js` throws it when `cp.scratch != null) { for (const key of Object.keys(cp.scratch)) { try { revived[key] = revive(cp.scratch[key]); } catch (err`. The message is "checkpoint scratch ${key} is invalid".
Fix: Pass a value that satisfies "checkpoint scratch ${key} is invalid".

## CHECKPOINT_SCRATCH_ND_SPOOF_IS_INVALID

Cause: `assertRevived()` in `packages/core/src/engine/checkpoint.js` throws it when `typeof nd !== 'object' || !(nd.bindings instanceof Map)`. The message is "checkpoint scratch nd-spoof is invalid".
Fix: Pass a value that satisfies "checkpoint scratch nd-spoof is invalid".

## CHECKPOINT_SCRATCH_WIFI_DEAUTH_FLOOD_IS_INVALID

Cause: `assertRevived()` in `packages/core/src/engine/checkpoint.js` throws it when `typeof wifi !== 'object' || !(wifi.byMac instanceof Map)`. The message is "checkpoint scratch wifi-deauth-flood is invalid".
Fix: Pass a value that satisfies "checkpoint scratch wifi-deauth-flood is invalid".

## CHECKPOINT_STATE_IS_INVALID

Cause: `revive()` in `packages/core/src/engine/checkpoint.js` throws it when `bytes.length % 8 !== 0`. The message is "checkpoint state is invalid". `revive()` in `packages/core/src/engine/checkpoint.js` throws it when `bytes.length % 4 !== 0`. The message is "checkpoint state is invalid". `revive()` in `packages/core/src/engine/checkpoint.js` throws it when `tagged`. The message is "checkpoint state is invalid".
Fix: Pass a value that satisfies "checkpoint state is invalid".

## CHECKPOINT_WATERMARK_IS_INVALID

Cause: `assertCheckpoint()` in `packages/core/src/engine/checkpoint.js` throws it when `raw.watermark != null && (typeof raw.watermark !== 'number' || !Number.isFinite(raw.watermark))`. The message is "checkpoint watermark is invalid".
Fix: Pass a value that satisfies "checkpoint watermark is invalid".

## CMS_STATE_MUST_BE_AN_OBJECT

Cause: `fromJSON()` in `packages/core/src/engine/stats/cms.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "cms state must be an object".
Fix: Correct the input so this passes: "cms state must be an object". The library does not change traffic.

## CONSUMES_MUST_BE_AN_ARRAY

Cause: `consumesOf()` in `packages/core/src/engine/engine.js` throws it when `!Array.isArray(raw)`. The message is "${det.id} consumes must be an array".
Fix: Pass an array. The check says "${det.id} consumes must be an array".

## CONSUMES_UNKNOWN_EVENT_TYPE

Cause: `consumesOf()` in `packages/core/src/engine/engine.js` throws it when `typeof type !== 'string' || !EVENT_TYPE_SET.has(type)`. The message is "${det.id} consumes unknown event type".
Fix: Correct the input so this passes: "${det.id} consumes unknown event type". The library does not change traffic.

## COUNT_IS_INVALID

Cause: `readStreamState()` in `packages/core/src/detectors/samples.js` throws it when `!Number.isInteger(state.count) || state.count < 0`. The message is "${id} count is invalid".
Fix: Pass a value that satisfies "${id} count is invalid".

## CUSUM_ALARMED_IS_INVALID

Cause: `fromJSON()` in `packages/core/src/engine/stats/cusum.js` throws it when `typeof row.alarmed !== 'boolean'`. The message is "cusum.alarmed is invalid".
Fix: Pass a value that satisfies "cusum.alarmed is invalid".

## CUSUM_H_IS_INVALID

Cause: `createCusum()` in `packages/core/src/engine/stats/cusum.js` throws it when `typeof opts.h !== 'number' || !(opts.h > 0) || !Number.isFinite(opts.h)`. The message is "cusum.h is invalid".
Fix: Pass a value that satisfies "cusum.h is invalid".

## CUSUM_K_IS_INVALID

Cause: `createCusum()` in `packages/core/src/engine/stats/cusum.js` throws it when `typeof opts.k !== 'number' || !(opts.k >= 0) || !Number.isFinite(opts.k)`. The message is "cusum.k is invalid".
Fix: Pass a value that satisfies "cusum.k is invalid".

## CUSUM_MEAN_IS_INVALID

Cause: `createCusum()` in `packages/core/src/engine/stats/cusum.js` throws it when `typeof mean !== 'number' || !Number.isFinite(mean)`. The message is "cusum.mean is invalid".
Fix: Pass a value that satisfies "cusum.mean is invalid".

## CUSUM_OPTIONS_MUST_BE_AN_OBJECT

Cause: `createCusum()` in `packages/core/src/engine/stats/cusum.js` throws it when `!opts || typeof opts !== 'object'`. The message is "cusum options must be an object".
Fix: Correct the input so this passes: "cusum options must be an object". The library does not change traffic.

## CUSUM_SIDE_IS_INVALID

Cause: `fromJSON()` in `packages/core/src/engine/stats/cusum.js` throws it when `stats.high < 0 || stats.low < 0`. The message is "cusum side is invalid".
Fix: Pass a value that satisfies "cusum side is invalid".

## CUSUM_STATE_MUST_BE_AN_OBJECT

Cause: `fromJSON()` in `packages/core/src/engine/stats/cusum.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "cusum state must be an object".
Fix: Correct the input so this passes: "cusum state must be an object". The library does not change traffic.

## DAYOF_MUST_BE_A_FUNCTION

Cause: `validateOptions()` in `packages/core/src/engine/validate/index.js` throws it when `input.dayOf != null && typeof input.dayOf !== 'function'`. The message is "dayOf must be a function".
Fix: Correct the input so this passes: "dayOf must be a function". The library does not change traffic.

## DETECTORS_CANARY_MUST_BE_AN_OBJECT

Cause: `validateOptions()` in `packages/core/src/engine/validate/index.js` throws it when `!value.canary || typeof value.canary !== 'object' || Array.isArray(value.canary)`. The message is "detectors.${id}.canary must be an object".
Fix: Correct the input so this passes: "detectors.${id}.canary must be an object". The library does not change traffic.

## DETECTORS_ENABLED_MUST_BE_BOOLEAN

Cause: `validateOptions()` in `packages/core/src/engine/validate/index.js` throws it when `value.enabled != null && typeof value.enabled !== 'boolean'`. The message is "detectors.${id}.enabled must be boolean".
Fix: Correct the input so this passes: "detectors.${id}.enabled must be boolean". The library does not change traffic.

## DETECTORS_MODE_MUST_BE_LIVE_OR_SHADOW

Cause: `validateOptions()` in `packages/core/src/engine/validate/index.js` throws it when `value.mode != null && value.mode !== 'live' && value.mode !== 'shadow'`. The message is "detectors.${id}.mode must be live or shadow".
Fix: Correct the input so this passes: "detectors.${id}.mode must be live or shadow". The library does not change traffic.

## DETECTORS_MUST_BE_AN_ARRAY

Cause: `relearn()` in `packages/core/src/engine/learning.js` throws it when `!Array.isArray(ids)`. The message is "detectors must be an array".
Fix: Pass an array. The check says "detectors must be an array".

## DETECTORS_MUST_BE_AN_OBJECT

Cause: `validateOptions()` in `packages/core/src/engine/validate/index.js` throws it when `!input.detectors || typeof input.detectors !== 'object' || Array.isArray(input.detectors)`. The message is "detectors must be an object".
Fix: Correct the input so this passes: "detectors must be an object". The library does not change traffic.

## DETECTORS_MUST_BE_AN_OBJECT_2

Cause: `validateOptions()` in `packages/core/src/engine/validate/index.js` throws it when `!value || typeof value !== 'object' || Array.isArray(value)`. The message is "detectors.${id} must be an object".
Fix: Correct the input so this passes: "detectors.${id} must be an object". The library does not change traffic.

## DETECTORS_SEVERITY_IS_INVALID

Cause: `validateOptions()` in `packages/core/src/engine/validate/index.js` throws it when `value.severity != null && !SEVERITY_NAMES.has(value.severity)`. The message is "detectors.${id}.severity is invalid".
Fix: Pass a value that satisfies "detectors.${id}.severity is invalid".

## DETECTOR_DEFAULTS_IS_INVALID

Cause: `_assertDetector()` in `packages/core/src/engine/engine.js` throws it when `!detector.defaults || typeof detector.defaults !== 'object'`. The message is "detector.defaults is invalid".
Fix: Pass a value that satisfies "detector.defaults is invalid".

## DETECTOR_ID_IS_INVALID

Cause: `_assertDetector()` in `packages/core/src/engine/engine.js` throws it when `typeof detector.id !== 'string' || !/^(?:rule:)?[a-z0-9-]+$/.test(detector.id)`. The message is "detector.id is invalid".
Fix: Pass a value that satisfies "detector.id is invalid".

## DETECTOR_IS_ALREADY_REGISTERED

Cause: `use()` in `packages/core/src/engine/engine.js` throws it when `this.byId.has(detector.id)`. The message is "detector ${detector.id} is already registered".
Fix: Correct the input so this passes: "detector ${detector.id} is already registered". The library does not change traffic.

## DETECTOR_MUST_BE_AN_OBJECT

Cause: `_assertDetector()` in `packages/core/src/engine/engine.js` throws it when `!detector || typeof detector !== 'object'`. The message is "detector must be an object".
Fix: Correct the input so this passes: "detector must be an object". The library does not change traffic.

## DETECTOR_REQUIRES_IS_INVALID

Cause: `_assertDetector()` in `packages/core/src/engine/engine.js` throws it when `!Array.isArray(detector.requires) || detector.requires.length === 0`. The message is "detector.requires is invalid".
Fix: Pass a value that satisfies "detector.requires is invalid".

## DETECTOR_STATE_VERSION_MISMATCH_FOR

Cause: `prepareImport()` in `packages/core/src/engine/baseline.js` throws it when `!block || typeof block !== 'object' || block.v !== det.version`. The message is "detector state version mismatch for ${detId}".
Fix: Correct the input so this passes: "detector state version mismatch for ${detId}". The library does not change traffic.

## DETECTOR_VERSION_IS_INVALID

Cause: `_assertDetector()` in `packages/core/src/engine/engine.js` throws it when `!Number.isInteger(detector.version) || detector.version < 1`. The message is "detector.version is invalid".
Fix: Pass a value that satisfies "detector.version is invalid".

## DEVICE_CLASS_IS_INVALID

Cause: `prepareImport()` in `packages/core/src/engine/baseline.js` throws it when `typeof record.deviceClass !== 'string' || !CLASSES[record.deviceClass]`. The message is "device class is invalid".
Fix: Pass a value that satisfies "device class is invalid".

## DEVICE_ID_IS_INVALID

Cause: `setDeviceClass()` in `packages/core/src/engine/engine.js` throws it when `typeof deviceId !== 'string' || deviceId.length === 0 || FORBIDDEN_KEYS.has(deviceId)`. The message is "device id is invalid". `setPeerGroup()` in `packages/core/src/engine/engine.js` throws it when `typeof deviceId !== 'string' || deviceId.length === 0 || FORBIDDEN_KEYS.has(deviceId)`. The message is "device id is invalid". `blank()` in `packages/core/src/engine/finish09.js` throws it when `typeof deviceId !== 'string' || deviceId.length === 0 || FORBIDDEN_KEYS.has(deviceId)`. The message is "device id is invalid".
Fix: Pass a value that satisfies "device id is invalid".

## ATTACKS_SINCE_IS_INVALID

Cause: `attacksOf()` in `packages/core/src/engine/report.js` throws it when `typeof sinceTs !== 'number' || !Number.isFinite(sinceTs)`. The message is "attacks sinceTs is invalid".
Fix: Pass a value that satisfies "attacks sinceTs is invalid".

## DIGEST_SINCE_IS_INVALID

Cause: `digestOf()` in `packages/core/src/engine/report.js` throws it when `typeof sinceTs !== 'number' || !Number.isFinite(sinceTs)`. The message is "digest sinceTs is invalid".
Fix: Pass a value that satisfies "digest sinceTs is invalid".

## COUNTS_SINCE_IS_INVALID

Cause: `countsOf()` in `packages/core/src/engine/report.js` throws it when `typeof sinceTs !== 'number' || !Number.isFinite(sinceTs)`. The message is "counts sinceTs is invalid".
Fix: Pass a value that satisfies "counts sinceTs is invalid".

## HINTS_SINCE_IS_INVALID

Cause: `hintsOf()` in `packages/core/src/engine/report.js` throws it when `typeof sinceTs !== 'number' || !Number.isFinite(sinceTs)`. The message is "hints sinceTs is invalid".
Fix: Pass a value that satisfies "hints sinceTs is invalid".

## QUIET_MS_IS_INVALID

Cause: `requireQuiet()` in `packages/core/src/engine/report.js` throws it when `typeof quietMs !== 'number' || !Number.isFinite(quietMs) || quietMs < 0`. The message is "quiet ms is invalid".
Fix: Pass a value that satisfies "quiet ms is invalid".

## OPEN_INCIDENTS_NOW_IS_INVALID

Cause: `openIncidentsOf()` in `packages/core/src/engine/report.js` throws it when `typeof now !== 'number' || !Number.isFinite(now)`. The message is "open incidents now is invalid". `mergeOpen()` in `packages/core/src/engine/report.js` throws it when `typeof now !== 'number' || !Number.isFinite(now)`. The message is "open incidents now is invalid".
Fix: Pass a value that satisfies "open incidents now is invalid".

## QUIET_NOW_IS_INVALID

Cause: `requireQuiet()` in `packages/core/src/engine/report.js` throws it when `typeof now !== 'number' || !Number.isFinite(now)`. The message is "quiet now is invalid".
Fix: Pass a value that satisfies "quiet now is invalid".

## SHADOW_SINCE_IS_INVALID

Cause: `shadowOf()` in `packages/core/src/engine/report.js` throws it when `typeof sinceTs !== 'number' || !Number.isFinite(sinceTs)`. The message is "shadow sinceTs is invalid".
Fix: Pass a value that satisfies "shadow sinceTs is invalid".

## CAMPAIGNS_NOW_IS_INVALID

Cause: `campaignsOf()` in `packages/core/src/engine/report.js` throws it when `typeof now !== 'number' || !Number.isFinite(now)`. The message is "campaigns now is invalid". `mergeCampaigns()` in `packages/core/src/engine/report.js` throws it when `typeof now !== 'number' || !Number.isFinite(now)`. The message is "campaigns now is invalid".
Fix: Pass a value that satisfies "campaigns now is invalid".

## OVERVIEW_NOW_IS_INVALID

Cause: `overviewOf()` in `packages/core/src/engine/report.js` throws it when `typeof now !== 'number' || !Number.isFinite(now)`. The message is "overview now is invalid".
Fix: Pass a value that satisfies "overview now is invalid".

## OVERVIEW_SINCE_IS_INVALID

Cause: `overviewOf()` in `packages/core/src/engine/report.js` throws it when `typeof since !== 'number' || !Number.isFinite(since)`. The message is "overview sinceTs is invalid".
Fix: Pass a value that satisfies "overview sinceTs is invalid".

## HOUSE_NOW_IS_INVALID

Cause: `houseOf()` in `packages/core/src/engine/house.js` throws it when `now` is not a finite number. The message is "house now is invalid".
Fix: Pass a finite number for `now`.

## HOUSE_QUIET_IS_INVALID

Cause: `houseOf()` throws it when `quietMs` is passed and is not a finite number >= 0. The message is "quietMs is invalid".
Fix: Omit `quietMs`, or pass a finite number >= 0.

## ATTENTION_NOW_IS_INVALID

Cause: `attentionOf()` throws it when `now` is not a finite number. The message is "attention now is invalid".
Fix: Pass a finite number for `now`.

## TIMELINE_SINCE_IS_INVALID

Cause: `timelineOf()` throws it when `sinceTs` is not a finite number. The message is "timeline sinceTs is invalid".
Fix: Pass a finite number for `sinceTs`.

## TIMELINE_QUIET_IS_INVALID

Cause: `timelineOf()` throws it when `quietMs` is passed and is not a finite number >= 0. The message is "quietMs is invalid".
Fix: Omit `quietMs`, or pass a finite number >= 0.

## CHANGES_SINCE_IS_INVALID

Cause: `changesOf()` throws it when `sinceTs` is not a finite number. The message is "changes sinceTs is invalid".
Fix: Pass a finite number for `sinceTs`.

## CHANGES_QUIET_IS_INVALID

Cause: `changesOf()` throws it when `quietMs` is passed and is not a finite number >= 0. The message is "quietMs is invalid".
Fix: Omit `quietMs`, or pass a finite number >= 0.

## AT_DEVICE_IS_INVALID

Cause: `atOf()` in `packages/core/src/engine/past.js` throws it when the device id is not a string of 1 to 255 characters, or the id is a forbidden key. The message is "device id is invalid".
Fix: Pass a device id of 1 to 255 characters.

## AT_TS_IS_INVALID

Cause: `atOf()` throws it when `ts` is not a finite number. The message is "at ts is invalid".
Fix: Pass a finite number for `ts`.

## AT_LOG_IS_INVALID

Cause: `atOf()` throws it when `opts.log` is passed and is not an array. The message is "at log is invalid".
Fix: Omit `log`, or pass an array of events.

## AT_DEVICE_IS_UNKNOWN

Cause: `atOf()` throws it when that device is not in the checkpoint or the replay. The message is "at device is unknown".
Fix: Pass a device the checkpoint or the log has already seen.

## AT_LOG_IS_REQUIRED

Cause: `atOf()` throws it when no log is passed and the device's last event is after `ts`. The message is "at log is required".
Fix: Pass `opts.log` with the events the host still has, or pass a `ts` at or after the device's last event.

## AT_CHECKPOINT_IS_INVALID

Cause: `atOf()` throws it when `opts.checkpoint` is passed and is not an object. The message is "at checkpoint is invalid".
Fix: Omit `checkpoint`, or pass a checkpoint object.

## DIFF_BASELINE_IS_INVALID

Cause: `diffBaselineOf()` throws it when either baseline is missing a `devices` object, or a device id is a forbidden key. The message is "baseline is invalid".
Fix: Pass two baseline objects that each have a `devices` object.

## WITHOUT_DEVICE_IS_INVALID

Cause: `withoutOf()` throws it when the device id is not a string of 1 to 255 characters, or the id is a forbidden key. The message is "device id is invalid".
Fix: Pass a device id of 1 to 255 characters.

## WITHOUT_DESTINATION_IS_INVALID

Cause: `withoutOf()` throws it when `destination` is not a string of 1 to 255 characters. The message is "without destination is invalid".
Fix: Pass the destination string.

## WITHOUT_EVENTS_ARE_INVALID

Cause: `withoutOf()` throws it when `events` is not an array. The message is "without events are invalid".
Fix: Pass the events the host still has.

## STORY_INCIDENT_IS_INVALID

Cause: `storyOf()` throws it when `incidentId` is not a non-empty string, or no stored incident has that id. The message is "story incident is invalid".
Fix: Pass the id of an incident the engine still stores.

## HOST_FACT_NAME_IS_INVALID

Cause: `hostFact()` in `packages/core/src/engine/validate/index.js` throws it when `name` is present and is not a string. The message is "host fact name is invalid".
Fix: Omit `name`, or pass a string.

## SKETCH_KEY_IS_INVALID

Cause: a sketch call throws it when `key` or `verify` is not a string or a Buffer. The message is "sketch key is invalid".
Fix: Pass the same key a baseline signature already uses.

## SKETCH_FIELDS_ARE_INVALID

Cause: `exportSketch()` throws it when `fields` is empty or names something other than `families`, `resolvers`, `updates`, or `beacons`. The message is "sketch fields are invalid".
Fix: Pass the granularity the host chose.

## SKETCH_BUCKET_IS_INVALID

Cause: `exportSketch()` throws it when `beacons` is requested and `bucketMs` is not an integer of at least 1. The message is "sketch bucket is invalid".
Fix: Pass the bucket width. There is no default.

## SKETCH_CAP_IS_INVALID

Cause: `importSketches()` throws it when `cap` is not an integer of at least 1. The message is "sketch cap is invalid".
Fix: Pass the cap. This version sets no default.

## SKETCHES_MUST_BE_AN_ARRAY

Cause: `importSketches()` throws it when `list` is not an array. The message is "sketches must be an array".
Fix: Pass an array of sketches.

## ARRAY_SKETCHES_EXCEEDS_CAP

Cause: `importSketches()` throws it when the stored book would grow past `cap`. The message is "array sketches exceeds cap".
Fix: Pass a larger cap, or fewer sketches. The previous book is left in place.

## ALLOW_UPDATES_ARE_INVALID

Cause: `exportAllowSketch()` throws it when `updates` is not an array of names of 1 to 255 characters. The message is "allow updates are invalid".
Fix: Pass the update-host families the host already listed.

## WAVES_SINCE_IS_INVALID

Cause: `wavesOf()` in `packages/core/src/engine/report.js` throws it when `typeof sinceTs !== 'number' || !Number.isFinite(sinceTs)`. The message is "waves sinceTs is invalid".
Fix: Pass a value that satisfies "waves sinceTs is invalid".

## DNS_QNAME_IS_INVALID

Cause: `dnsEvent()` in `packages/core/src/engine/validate/dns.js` throws it when `!qname`. The message is "dns qname is invalid".
Fix: Pass a value that satisfies "dns qname is invalid".

## DRIFT_DAY_IS_INVALID

Cause: `observe()` in `packages/core/src/engine/drift.js` throws it when `day <= row.day`. The message is "drift day is invalid". `parseObserveDay()` in `packages/core/src/engine/drift.js` throws it when `typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER`. The message is "drift day is invalid". `parseStoredDay()` in `packages/core/src/engine/drift.js` throws it when `typeof value !== 'number' || !Number.isInteger(value) || value < -1`. The message is "drift day is invalid".
Fix: Pass a value that satisfies "drift day is invalid".

## DRIFT_DEVICE_IS_INVALID

Cause: `parseDevice()` in `packages/core/src/engine/drift.js` throws it when `typeof value !== 'string' || value.length === 0 || value.length > 255`. The message is "drift device is invalid". `parseDevice()` in `packages/core/src/engine/drift.js` throws it when `FORBIDDEN_KEYS.has(value)`. The message is "drift device is invalid".
Fix: Pass a value that satisfies "drift device is invalid".

## DRIFT_SERIES_IS_INVALID

Cause: `parseSeriesName()` in `packages/core/src/engine/drift.js` throws it when `name === 'families' || name === 'bytesOut' || name === 'ports' || name === 'hours') return name;`. The message is "drift series is invalid".
Fix: Pass a value that satisfies "drift series is invalid".

## DRIFT_SIGMA_IS_INVALID

Cause: `parseSigma()` in `packages/core/src/engine/drift.js` throws it when `typeof value !== 'number' || !Number.isFinite(value) || value < 0`. The message is "drift sigma is invalid". `parseSigma()` in `packages/core/src/engine/drift.js` throws it when `value > 0 && !Number.isFinite(8 * value)`. The message is "drift sigma is invalid".
Fix: Pass a value that satisfies "drift sigma is invalid".

## DRIFT_STATE_IS_INVALID

Cause: `parseSeries()` in `packages/core/src/engine/drift.js` throws it when `count === 0 ? day !== -1 : day < 0`. The message is "drift state is invalid". `assertDrift()` in `packages/core/src/engine/drift.js` throws it when `!state || typeof state !== 'object' || Array.isArray(state)`. The message is "drift state is invalid". `assertDrift()` in `packages/core/src/engine/drift.js` throws it when `!isSeries(row.families) || !isSeries(row.bytesOut) || !isSeries(row.ports) || !isSeries(row.hours)`. The message is "drift state is invalid". `assertDrift()` in `packages/core/src/engine/drift.js` throws it when `typeof row.deviceId !== 'string' || row.deviceId.length === 0`. The message is "drift state is invalid". `record()` in `packages/core/src/engine/drift.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "drift state is invalid". `record()` in `packages/core/src/engine/drift.js` throws it when `!keys.has(key)`. The message is "drift state is invalid". `record()` in `packages/core/src/engine/drift.js` throws it when `!Object.hasOwn(row, key)`. The message is "drift state is invalid". `parseCount()` in `packages/core/src/engine/drift.js` throws it when `typeof value !== 'number' || !Number.isInteger(value) || value < 0`. The message is "drift state is invalid".
Fix: Pass a value that satisfies "drift state is invalid".

## DRIFT_VALUE_IS_INVALID

Cause: `parseValue()` in `packages/core/src/engine/drift.js` throws it when `typeof value !== 'number' || !Number.isFinite(value)`. The message is "drift value is invalid".
Fix: Pass a value that satisfies "drift value is invalid".

## EVENTS_MUST_BE_AN_ARRAY

Cause: `feedBatch()` in `packages/core/src/engine/feed.js` throws it when `!Array.isArray(events)`. The message is "events must be an array".
Fix: Pass an array. The check says "events must be an array".

## EVENT_DEVICE_IS_REQUIRED

Cause: `validateEvent()` in `packages/core/src/engine/validate/index.js` throws it when `typeof raw.device !== 'string' || raw.device.length === 0 || raw.device.length > 255`. The message is "event.device is required".
Fix: Pass a value that satisfies "event.device is required".

## EVENT_DEVICE_IS_RESERVED

Cause: `validateEvent()` in `packages/core/src/engine/validate/index.js` throws it when `FORBIDDEN_KEYS.has(raw.device)`. The message is "event.device is reserved".
Fix: Correct the input so this passes: "event.device is reserved". The library does not change traffic.

## EVENT_MUST_BE_AN_OBJECT

Cause: `validateEvent()` in `packages/core/src/engine/validate/index.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "event must be an object".
Fix: Correct the input so this passes: "event must be an object". The library does not change traffic.

## EVENT_REQUIRES

Cause: `requireFields()` in `packages/core/src/engine/validate/common.js` throws it when `raw[field] == null`. The message is "${type} event requires ${field}".
Fix: Correct the input so this passes: "${type} event requires ${field}". The library does not change traffic.

## EVENT_TYPE_IS_INVALID

Cause: `validateEvent()` in `packages/core/src/engine/validate/index.js` throws it when `typeof type !== 'string'`. The message is "event.type is invalid".
Fix: Pass a value that satisfies "event.type is invalid".

## EWMA_ALPHA_IS_INVALID

Cause: `createEwma()` in `packages/core/src/engine/stats/ewma.js` throws it when `typeof alpha !== 'number' || !(alpha > 0) || alpha > 1`. The message is "ewma.alpha is invalid". `fromJSON()` in `packages/core/src/engine/stats/ewma.js` throws it when `typeof row.alpha !== 'number' || !(row.alpha > 0) || row.alpha > 1`. The message is "ewma.alpha is invalid".
Fix: Pass a value that satisfies "ewma.alpha is invalid".

## EWMA_COUNT_IS_INVALID

Cause: `fromJSON()` in `packages/core/src/engine/stats/ewma.js` throws it when `typeof row.count !== 'number' || !Number.isInteger(row.count) || row.count < 0`. The message is "ewma.count is invalid".
Fix: Pass a value that satisfies "ewma.count is invalid".

## EWMA_HALFLIFE_IS_INVALID

Cause: `createEwma()` in `packages/core/src/engine/stats/ewma.js` throws it when `typeof opts.halfLife !== 'number' || !(opts.halfLife > 0)`. The message is "ewma.halfLife is invalid".
Fix: Pass a value that satisfies "ewma.halfLife is invalid".

## EWMA_MEAN_IS_INVALID

Cause: `fromJSON()` in `packages/core/src/engine/stats/ewma.js` throws it when `typeof row.mean !== 'number' || !Number.isFinite(row.mean)`. The message is "ewma.mean is invalid".
Fix: Pass a value that satisfies "ewma.mean is invalid".

## EWMA_OPTIONS_MUST_BE_AN_OBJECT

Cause: `createEwma()` in `packages/core/src/engine/stats/ewma.js` throws it when `!opts || typeof opts !== 'object' || Array.isArray(opts)`. The message is "ewma options must be an object".
Fix: Correct the input so this passes: "ewma options must be an object". The library does not change traffic.

## EWMA_STATE_MUST_BE_AN_OBJECT

Cause: `fromJSON()` in `packages/core/src/engine/stats/ewma.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "ewma state must be an object".
Fix: Correct the input so this passes: "ewma state must be an object". The library does not change traffic.

## EWMA_VARIANCE_IS_INVALID

Cause: `fromJSON()` in `packages/core/src/engine/stats/ewma.js` throws it when `typeof row.variance !== 'number' || !Number.isFinite(row.variance) || row.variance < 0`. The message is "ewma.variance is invalid".
Fix: Pass a value that satisfies "ewma.variance is invalid".

## FAMILIES_MUST_BE_AN_ARRAY

Cause: `readFamilies()` in `packages/core/src/detectors/young-domain.js` throws it when `!Array.isArray(value)`. The message is "families must be an array".
Fix: Pass an array. The check says "families must be an array".

## FAMILIES_MUST_BE_OBJECTS

Cause: `readFamilies()` in `packages/core/src/detectors/young-domain.js` throws it when `!item || typeof item !== 'object' || Array.isArray(item)`. The message is "families must be objects".
Fix: Correct the input so this passes: "families must be objects". The library does not change traffic.

## FAMILIES_MUST_BE_STRINGS

Cause: `readFamilies()` in `packages/core/src/detectors/young-domain.js` throws it when `typeof item.family !== 'string' || item.family.length === 0 || item.family.length > 255`. The message is "families must be strings".
Fix: Pass a string. The check says "families must be strings".

## FAMILY_TIME_IS_INVALID

Cause: `readFamilies()` in `packages/core/src/detectors/young-domain.js` throws it when `!Number.isInteger(item.ts)`. The message is "family time is invalid".
Fix: Pass a value that satisfies "family time is invalid".

## FEEDBACK_OPTIONS_MUST_BE_AN_OBJECT

Cause: `recordFeedback()` in `packages/core/src/engine/feedback.js` throws it when `opts != null && (typeof opts !== 'object' || Array.isArray(opts))`. The message is "feedback options must be an object".
Fix: Correct the input so this passes: "feedback options must be an object". The library does not change traffic.

## FIRED_MUST_BE_STRINGS

Cause: `importState()` in `packages/core/src/detectors/policy-violation.js` throws it when `typeof key !== 'string'`. The message is "fired must be strings".
Fix: Pass a string. The check says "fired must be strings".

## FLOW_DIRECTION_IS_INVALID

Cause: `flowEvent()` in `packages/core/src/engine/validate/flow.js` throws it when `direction !== 'out' && direction !== 'in' && direction !== 'lan'`. The message is "flow direction is invalid".
Fix: Pass a value that satisfies "flow direction is invalid".

## FLOW_PROTO_IS_INVALID

Cause: `flowEvent()` in `packages/core/src/engine/validate/flow.js` throws it when `!protoOk`. The message is "flow proto is invalid".
Fix: Pass a value that satisfies "flow proto is invalid".

## FLUSH_TIME_IS_INVALID

Cause: `flush()` in `packages/core/src/engine/windows.js` throws it when `explicit && (typeof now !== 'number' || !Number.isFinite(now))`. The message is "flush time is invalid".
Fix: Pass a value that satisfies "flush time is invalid".

## FORBIDDEN_KEY

Cause: `assertSafeKey()` in `packages/core/src/engine/validate/common.js` throws it when `FORBIDDEN_KEYS.has(key)`. The message is "forbidden key ${key}".
Fix: Remove that key. **proto**, constructor, and prototype are rejected.

## FORBIDDEN_KEY_AT

Cause: `parseState()` in `packages/core/src/engine/audit.js` throws it when `Object.getPrototypeOf(items) !== Array.prototype`. The message is "forbidden key **proto** at audit.records". `assertPlain()` in `packages/core/src/engine/audit.js` throws it when `proto !== Object.prototype && proto !== null`. The message is "forbidden key **proto** at ${path}". `canonicalArray()` in `packages/core/src/engine/audit.js` throws it when `Object.getPrototypeOf(value) !== Array.prototype`. The message is "forbidden key **proto** at audit.args". `assertSafeKeys()` in `packages/core/src/engine/validate/common.js` throws it when `FORBIDDEN_KEYS.has(key)`. The message is "forbidden key ${key} at ${path}". `assertSafeKeys()` in `packages/core/src/engine/validate/common.js` throws it when `Object.hasOwn(value, key)`. The message is "forbidden key ${key} at ${path}".
Fix: Remove that key. **proto**, constructor, and prototype are rejected.

## GATEWAYID_IS_INVALID

Cause: `exportSummary()` in `packages/core/src/engine/finish09.js` throws it when `!opts || typeof opts.gatewayId !== 'string' || opts.gatewayId.length === 0`. The message is "gatewayId is invalid".
Fix: Pass a value that satisfies "gatewayId is invalid".

## GROUPBY_IS_INVALID

Cause: `normalizeGroupBy()` in `packages/core/src/engine/rules.js` throws it when `!Array.isArray(list) || list.length === 0 || list.length > 4`. The message is "${path}.groupBy is invalid". `normalizeGroupBy()` in `packages/core/src/engine/rules.js` throws it when `typeof field !== 'string' || !/^[A-Za-z][A-Za-z0-9]*$/.test(field)`. The message is "${path}.groupBy is invalid".
Fix: Pass a value that satisfies "${path}.groupBy is invalid".

## HLL_PRECISION_MISMATCH

Cause: `merge()` in `packages/core/src/engine/stats/hll.js` throws it when `left.p !== right.p || left.registers.length !== right.registers.length`. The message is "hll precision mismatch".
Fix: Correct the input so this passes: "hll precision mismatch". The library does not change traffic.

## HLL_P_IS_INVALID

Cause: `createHll()` in `packages/core/src/engine/stats/hll.js` throws it when `!Number.isInteger(p) || p < 4 || p > 16`. The message is "hll.p is invalid". `fromJSON()` in `packages/core/src/engine/stats/hll.js` throws it when `!Number.isInteger(row.p) || row.p < 4 || row.p > 16`. The message is "hll.p is invalid".
Fix: Pass a value that satisfies "hll.p is invalid".

## HLL_STATE_MUST_BE_AN_OBJECT

Cause: `fromJSON()` in `packages/core/src/engine/stats/hll.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "hll state must be an object".
Fix: Correct the input so this passes: "hll state must be an object". The library does not change traffic.

## HOUROF_MUST_BE_A_FUNCTION

Cause: `validateOptions()` in `packages/core/src/engine/validate/index.js` throws it when `input.hourOf != null && typeof input.hourOf !== 'function'`. The message is "hourOf must be a function".
Fix: Correct the input so this passes: "hourOf must be a function". The library does not change traffic.

## HOURS_MUST_BE_0_23

Cause: `importState()` in `packages/core/src/detectors/went-silent.js` throws it when `!Number.isInteger(hour) || hour < 0 || hour > 23`. The message is "hours must be 0..23".
Fix: Correct the input so this passes: "hours must be 0..23". The library does not change traffic.

## HOURS_MUST_BE_24_ARRAYS

Cause: `importState()` in `packages/core/src/detectors/volume-spike-hourly.js` throws it when `!state || !Array.isArray(state.hours) || state.hours.length !== 24`. The message is "hours must be 24 arrays".
Fix: Correct the input so this passes: "hours must be 24 arrays". The library does not change traffic.

## HOURS_MUST_BE_AN_ARRAY

Cause: `importState()` in `packages/core/src/detectors/went-silent.js` throws it when `!state || !Array.isArray(state.hours)`. The message is "hours must be an array". `read()` in `packages/core/src/detectors/wrong-time.js` throws it when `!Array.isArray(state.hours)`. The message is "hours must be an array".
Fix: Pass an array. The check says "hours must be an array".

## HOURS_MUST_BE_NUMBERS

Cause: `read()` in `packages/core/src/detectors/wrong-time.js` throws it when `typeof hour !== 'number' || !Number.isFinite(hour)`. The message is "hours must be numbers".
Fix: Correct the input so this passes: "hours must be numbers". The library does not change traffic.

## IDENTITY_MUST_BE_OFF_OR_AUTO

Cause: `identityMode()` in `packages/core/src/engine/validate/common.js` throws it when `value === 'off' || value === 'auto') return value;`. The message is "identity must be off or auto".
Fix: Correct the input so this passes: "identity must be off or auto". The library does not change traffic.

## ID_IS_INVALID

Cause: `normalizeRule()` in `packages/core/src/engine/rules.js` throws it when `typeof rule.id !== 'string' || !/^[a-z0-9-]+$/.test(rule.id)`. The message is "${path}.id is invalid".
Fix: Pass a value that satisfies "${path}.id is invalid".

## INDICATORS_MUST_BE_AN_ARRAY

Cause: `loadIndicators()` in `packages/core/src/engine/engine.js` throws it when `!Array.isArray(list)`. The message is "indicators must be an array".
Fix: Pass an array. The check says "indicators must be an array".

## INDICATOR_CIDR_IS_INVALID

Cause: `validateIndicator()` in `packages/core/src/engine/validate/index.js` throws it when `raw.type === 'cidr' && !/^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(raw.value)`. The message is "indicator cidr is invalid".
Fix: Pass a value that satisfies "indicator cidr is invalid".

## INDICATOR_IP_IS_INVALID

Cause: `validateIndicator()` in `packages/core/src/engine/validate/index.js` throws it when `raw.type === 'ip' && !ip`. The message is "indicator ip is invalid".
Fix: Pass a value that satisfies "indicator ip is invalid".

## INDICATOR_MUST_BE_AN_OBJECT

Cause: `validateIndicator()` in `packages/core/src/engine/validate/index.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "indicator must be an object".
Fix: Correct the input so this passes: "indicator must be an object". The library does not change traffic.

## INDICATOR_SOURCE_IS_INVALID

Cause: `validateIndicator()` in `packages/core/src/engine/validate/index.js` throws it when `typeof raw.source !== 'string' || raw.source.length === 0 || raw.source.length > 255`. The message is "indicator.source is invalid".
Fix: Pass a value that satisfies "indicator.source is invalid".

## INDICATOR_TYPE_IS_INVALID

Cause: `validateIndicator()` in `packages/core/src/engine/validate/index.js` throws it when `!types.has(raw.type)`. The message is "indicator.type is invalid".
Fix: Pass a value that satisfies "indicator.type is invalid".

## INDICATOR_VALUE_IS_INVALID

Cause: `validateIndicator()` in `packages/core/src/engine/validate/index.js` throws it when `typeof raw.value !== 'string' || raw.value.length === 0 || raw.value.length > 255`. The message is "indicator.value is invalid".
Fix: Pass a value that satisfies "indicator.value is invalid".

## ISSUERS_MUST_BE_PAIRS

Cause: `importState()` in `packages/core/src/detectors/cert-change.js` throws it when `!Array.isArray(pair) || pair.length !== 2`. The message is "issuers must be pairs".
Fix: Correct the input so this passes: "issuers must be pairs". The library does not change traffic.

## IS_INVALID

Cause: `readStreamState()` in `packages/core/src/detectors/samples.js` throws it when `typeof state[key] !== 'number' || !Number.isFinite(state[key])`. The message is "${id} ${key} is invalid".
Fix: Pass a value that satisfies "${id} ${key} is invalid".

## IS_INVALID_2

Cause: `normalizeRule()` in `packages/core/src/engine/rules.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "${path} is invalid". `requireType()` in `packages/core/src/engine/rules.js` throws it when `typeof value !== 'string' || !Object.prototype.hasOwnProperty.call(TIER_OF, value)`. The message is "${path} is invalid". `normalizeWindow()` in `packages/core/src/engine/rules.js` throws it when `typeof value !== 'string' || !Object.prototype.hasOwnProperty.call(WINDOWS, value)`. The message is "${path} is invalid". `normalizeSequence()` in `packages/core/src/engine/rules.js` throws it when `!step || typeof step !== 'object' || Array.isArray(step)`. The message is "${stepPath} is invalid". `normalizeWhere()` in `packages/core/src/engine/rules.js` throws it when `!where || typeof where !== 'object' || Array.isArray(where)`. The message is "${path} is invalid". `normalizeOperand()` in `packages/core/src/engine/rules.js` throws it when `!Array.isArray(value) || value.length === 0 || value.length > VALUE_CAP`. The message is "${path} is invalid". `normalizeOperand()` in `packages/core/src/engine/rules.js` throws it when `typeof value !== 'string' || value.length > VALUE_CAP`. The message is "${path} is invalid". `normalizeOperand()` in `packages/core/src/engine/rules.js` throws it when `ip == null || !Number.isInteger(bits) || bits < 0 || bits > 32`. The message is "${path} is invalid". `normalizeOperand()` in `packages/core/src/engine/rules.js` throws it when `typeof value !== 'string' || value.length === 0 || value.length > VALUE_CAP`. The message is "${path} is invalid". `scalar()` in `packages/core/src/engine/rules.js` throws it when `value.length > 255`. The message is "${path} is invalid". `scalar()` in `packages/core/src/engine/rules.js` throws it when `typeof value === 'boolean') return value;`. The message is "${path} is invalid". `finite()` in `packages/core/src/engine/stats/cusum.js` throws it when `typeof value !== 'number' || !Number.isFinite(value)`. The message is "${label} is invalid". `integer()` in `packages/core/src/engine/stats/welford.js` throws it when `typeof value !== 'number' || !Number.isInteger(value) || value < 0`. The message is "${label} is invalid". `parseOptionalString()` in `packages/core/src/engine/validate/common.js` throws it when `typeof value !== 'string' || value.length === 0 || value.length > 255`. The message is "${label} is invalid". `parseStringList()` in `packages/core/src/engine/validate/common.js` throws it when `!Array.isArray(value) || value.length > 32`. The message is "${label} is invalid". `parseStringList()` in `packages/core/src/engine/validate/common.js` throws it when `typeof item !== 'string' || item.length === 0 || item.length > 255`. The message is "${label} is invalid".
Fix: Pass a value that satisfies "${path} is invalid". Pass a value that satisfies "${stepPath} is invalid". Pass a value that satisfies "${label} is invalid".

## IS_INVALID_3

Cause: `normalizeWhere()` in `packages/core/src/engine/rules.js` throws it when `!/^[A-Za-z][A-Za-z0-9]*$/.test(field)`. The message is "${path}.${field} is invalid". `normalizeWhere()` in `packages/core/src/engine/rules.js` throws it when `!pred || typeof pred !== 'object' || Array.isArray(pred)`. The message is "${path}.${field} is invalid".
Fix: Pass a value that satisfies "${path}.${field} is invalid".

## IS_INVALID_4

Cause: `normalizeWhere()` in `packages/core/src/engine/rules.js` throws it when `!OPS.has(op)`. The message is "${path}.${field}.${op} is invalid".
Fix: Pass a value that satisfies "${path}.${field}.${op} is invalid".

## IS_NOT_A_MULTIPLE_OF_WINDOWMS

Cause: `normalizeWindow()` in `packages/core/src/engine/rules.js` throws it when `engineWindow <= 0 || ms % engineWindow !== 0`. The message is "${path} is not a multiple of windowMs".
Fix: Use the same windowMs the baseline or checkpoint was exported with, or re-learn.

## KEYS_MUST_BE_AN_ARRAY

Cause: `readKeys()` in `packages/core/src/detectors/exploit-probe-http.js` throws it when `!Array.isArray(value)`. The message is "keys must be an array".
Fix: Pass an array. The check says "keys must be an array".

## KEYS_MUST_BE_OBJECTS

Cause: `readKeys()` in `packages/core/src/detectors/exploit-probe-http.js` throws it when `!item || typeof item !== 'object' || Array.isArray(item)`. The message is "keys must be objects".
Fix: Correct the input so this passes: "keys must be objects". The library does not change traffic.

## KEYS_MUST_BE_STRINGS

Cause: `readKeys()` in `packages/core/src/detectors/exploit-probe-http.js` throws it when `typeof item.key !== 'string' || item.key.length === 0 || item.key.length > 600`. The message is "keys must be strings".
Fix: Pass a string. The check says "keys must be strings".

## KEY_TIME_IS_INVALID

Cause: `readKeys()` in `packages/core/src/detectors/exploit-probe-http.js` throws it when `!Number.isInteger(item.ts)`. The message is "key time is invalid".
Fix: Pass a value that satisfies "key time is invalid".

## LEARNED_MUST_BE_AN_ARRAY

Cause: `importState()` in `packages/core/src/detectors/egress-flood.js` throws it when `!Array.isArray(state.learned)`. The message is "learned must be an array".
Fix: Pass an array. The check says "learned must be an array".

## LEARNED_MUST_BE_A_DESTINATION_AND_A_COUNT

Cause: `importState()` in `packages/core/src/detectors/egress-flood.js` throws it when `typeof pair[0] !== 'string' || typeof pair[1] !== 'number'`. The message is "learned must be a destination and a count".
Fix: Correct the input so this passes: "learned must be a destination and a count". The library does not change traffic.

## LEARNED_MUST_BE_PAIRS

Cause: `importState()` in `packages/core/src/detectors/egress-flood.js` throws it when `!Array.isArray(pair) || pair.length !== 2`. The message is "learned must be pairs".
Fix: Correct the input so this passes: "learned must be pairs". The library does not change traffic.

## LENGTH_MISMATCH

Cause: `decodeTyped()` in `packages/core/src/engine/stats/hash.js` throws it when `bytes.length !== length * width`. The message is "${label} length mismatch".
Fix: Correct the input so this passes: "${label} length mismatch". The library does not change traffic.

## LOOKUP_MUST_BE_A_FUNCTION

Cause: `parseLookup()` in `packages/core/src/engine/validate/common.js` throws it when `typeof input.lookup !== 'function'`. The message is "lookup must be a function".
Fix: Correct the input so this passes: "lookup must be a function". The library does not change traffic.

## MACS_MUST_BE_AN_ARRAY

Cause: `importState()` in `packages/core/src/detectors/identity-change.js` throws it when `!Array.isArray(state.macs)`. The message is "macs must be an array".
Fix: Pass an array. The check says "macs must be an array".

## MACS_MUST_BE_PAIRS

Cause: `importState()` in `packages/core/src/detectors/identity-change.js` throws it when `!Array.isArray(pair) || pair.length !== 2`. The message is "macs must be pairs".
Fix: Correct the input so this passes: "macs must be pairs". The library does not change traffic.

## MACS_MUST_BE_STRINGS

Cause: `importState()` in `packages/core/src/detectors/identity-change.js` throws it when `typeof pair[0] !== 'string' || typeof pair[1] !== 'string'`. The message is "macs must be strings".
Fix: Pass a string. The check says "macs must be strings".

## MAPPING_PROTO_IS_INVALID

Cause: `mappingEvent()` in `packages/core/src/engine/validate/app.js` throws it when `raw.proto !== 'upnp' && raw.proto !== 'nat-pmp' && raw.proto !== 'pcp'`. The message is "mapping proto is invalid".
Fix: Pass a value that satisfies "mapping proto is invalid".

## MATCH_IS_INVALID

Cause: `suppress()` in `packages/core/src/engine/engine.js` throws it when `typeof opts.match !== 'string'`. The message is "match is invalid".
Fix: Pass a value that satisfies "match is invalid".

## MAXGAP_IS_INVALID

Cause: `importState()` in `packages/core/src/detectors/went-silent.js` throws it when `typeof state.maxGap !== 'number' || state.maxGap < 0`. The message is "maxGap is invalid".
Fix: Pass a value that satisfies "maxGap is invalid".

## MAX_ENTRIES_ARE_INVALID

Cause: `importState()` in `packages/core/src/detectors/horizontal-scan.js` throws it when `!Array.isArray(pair) || pair.length !== 2`. The message is "max entries are invalid". `importState()` in `packages/core/src/detectors/horizontal-scan.js` throws it when `!Number.isInteger(port) || typeof count !== 'number'`. The message is "max entries are invalid".
Fix: Correct the input so this passes: "max entries are invalid". The library does not change traffic.

## MAX_IS_INVALID

Cause: `readStreamState()` in `packages/core/src/detectors/samples.js` throws it when `state.max < 0`. The message is "${id} max is invalid".
Fix: Pass a value that satisfies "${id} max is invalid".

## MAX_MUST_BE_AN_ARRAY

Cause: `importState()` in `packages/core/src/detectors/horizontal-scan.js` throws it when `!Array.isArray(state.max)`. The message is "max must be an array".
Fix: Pass an array. The check says "max must be an array".

## MAX_MUST_BE_A_NUMBER

Cause: `importState()` in `packages/core/src/detectors/vertical-scan.js` throws it when `typeof state.max !== 'number' || state.max < 0`. The message is "max must be a number".
Fix: Correct the input so this passes: "max must be a number". The library does not change traffic.

## MODE_IS_INVALID

Cause: `normalizeRule()` in `packages/core/src/engine/rules.js` throws it when `mode !== 'shadow' && mode !== 'live'`. The message is "${path}.mode is invalid".
Fix: Pass a value that satisfies "${path}.mode is invalid".

## MUD_ACL_IS_INVALID

Cause: `loadMud()` in `packages/core/src/engine/finish09.js` throws it when `!acl || typeof acl !== 'object' || Array.isArray(acl)`. The message is "mud acl is invalid".
Fix: Pass a value that satisfies "mud acl is invalid".

## MUD_ALLOWS_IS_INVALID

Cause: `loadMud()` in `packages/core/src/engine/finish09.js` throws it when `!Array.isArray(acl.allows) || acl.allows.length > 64`. The message is "mud allows is invalid".
Fix: Pass a value that satisfies "mud allows is invalid".

## MUD_ALLOW_IS_INVALID

Cause: `loadMud()` in `packages/core/src/engine/finish09.js` throws it when `!row || typeof row !== 'object' || Array.isArray(row)`. The message is "mud allow is invalid". `loadMud()` in `packages/core/src/engine/finish09.js` throws it when `FORBIDDEN_KEYS.has(key)`. The message is "mud allow is invalid".
Fix: Pass a value that satisfies "mud allow is invalid".

## MUD_DIRECTION_IS_INVALID

Cause: `loadMud()` in `packages/core/src/engine/finish09.js` throws it when `row.direction !== 'out' && row.direction !== 'in' && row.direction !== 'lan'`. The message is "mud direction is invalid".
Fix: Pass a value that satisfies "mud direction is invalid".

## MUD_DOMAIN_IS_INVALID

Cause: `loadMud()` in `packages/core/src/engine/finish09.js` throws it when `typeof row.domain !== 'string' || row.domain.length > 255`. The message is "mud domain is invalid".
Fix: Pass a value that satisfies "mud domain is invalid".

## MUD_DSTPORT_IS_INVALID

Cause: `loadMud()` in `packages/core/src/engine/finish09.js` throws it when `!Number.isInteger(row.dstPort) || row.dstPort < 0 || row.dstPort > 65535`. The message is "mud dstPort is invalid".
Fix: Pass a value that satisfies "mud dstPort is invalid".

## MUD_PROTO_IS_INVALID

Cause: `loadMud()` in `packages/core/src/engine/finish09.js` throws it when `typeof row.proto !== 'string' || row.proto.length > 16`. The message is "mud proto is invalid".
Fix: Pass a value that satisfies "mud proto is invalid".

## MUST_BE_AN_ARRAY

Cause: `importState()` in `packages/core/src/detectors/dispersed-flood.js` throws it when `!Array.isArray(state.rows)`. The message is "rows must be an array". `importState()` in `packages/core/src/detectors/inbound-lateral.js` throws it when `!Array.isArray(state.inbound)`. The message is "inbound must be an array". `readNames()` in `packages/core/src/detectors/new-destination.js` throws it when `!Array.isArray(value)`. The message is "${label} must be an array". `importState()` in `packages/core/src/detectors/onion-name.js` throws it when `!Array.isArray(state.seen)`. The message is "seen must be an array". `readStrings()` in `packages/core/src/detectors/state.js` throws it when `!Array.isArray(value)`. The message is "${label} must be an array". `importState()` in `packages/core/src/detectors/txt-channel.js` throws it when `!Array.isArray(state.counts)`. The message is "counts must be an array".
Fix: Pass an array. The check says "rows must be an array". Pass an array. The check says "inbound must be an array". Pass an array. The check says "${label} must be an array". Pass an array. The check says "seen must be an array". Pass an array. The check says "counts must be an array".

## MUST_BE_AN_INTEGER

Cause: `num()` in `packages/core/src/engine/validate/common.js` throws it when `rule.integer && !Number.isInteger(value)`. The message is "${name} must be an integer".
Fix: Pass a value that satisfies "${name} must be an integer".

## MUST_BE_A_BOOLEAN

Cause: `bool()` in `packages/core/src/engine/validate/common.js` throws it when `typeof value !== 'boolean'`. The message is "${name} must be a boolean".
Fix: Pass true or false. The check says "${name} must be a boolean".

## MUST_BE_A_FINITE_NUMBER

Cause: `num()` in `packages/core/src/engine/validate/common.js` throws it when `typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max`. The message is "${name} must be a finite number >= ${min}".
Fix: Pass a value that satisfies "${name} must be a finite number >= ${min}".

## MUST_BE_BASE64

Cause: `decodeTyped()` in `packages/core/src/engine/stats/hash.js` throws it when `typeof text !== 'string' || text.length === 0`. The message is "${label} must be base64".
Fix: Correct the input so this passes: "${label} must be base64". The library does not change traffic.

## MUST_BE_STRINGS

Cause: `importState()` in `packages/core/src/detectors/dispersed-flood.js` throws it when `typeof row.ip !== 'string'`. The message is "rows ip must be a string". `readNames()` in `packages/core/src/detectors/new-destination.js` throws it when `typeof item !== 'string'`. The message is "${label} must be strings". `readStrings()` in `packages/core/src/detectors/state.js` throws it when `typeof item !== 'string'`. The message is "${label} must be strings". `importState()` in `packages/core/src/detectors/txt-channel.js` throws it when `!row || typeof row !== 'object' || Array.isArray(row)`. The message is "counts name must be a string". `importState()` in `packages/core/src/detectors/txt-channel.js` throws it when `typeof row.name !== 'string'`. The message is "counts name must be a string".
Fix: Pass a string. The check says "rows ip must be a string". Pass a string. The check says "${label} must be strings". Pass a string. The check says "counts name must be a string".

## ND_IP_MUST_BE_IPV6

Cause: `linkEvent()` in `packages/core/src/engine/validate/link.js` throws it when `!ndIp`. The message is "nd.ip must be IPv6".
Fix: Correct the input so this passes: "nd.ip must be IPv6". The library does not change traffic.

## ND_MAC_IS_INVALID

Cause: `linkEvent()` in `packages/core/src/engine/validate/link.js` throws it when `!isMac(mac)`. The message is "nd.mac is invalid".
Fix: Pass a value that satisfies "nd.mac is invalid".

## ND_OP_IS_INVALID

Cause: `linkEvent()` in `packages/core/src/engine/validate/link.js` throws it when `raw.op !== 'na' && raw.op !== 'ns' && raw.op !== 'rs' && raw.op !== 'ra'`. The message is "nd.op is invalid".
Fix: Pass a value that satisfies "nd.op is invalid".

## NEW_DESTINATION_STATE_IS_INVALID

Cause: `read()` in `packages/core/src/detectors/new-destination.js` throws it when `!state || typeof state !== 'object' || Array.isArray(state)`. The message is "new-destination state is invalid".
Fix: Pass a value that satisfies "new-destination state is invalid".

## NOTE_IS_INVALID

Cause: `recordFeedback()` in `packages/core/src/engine/feedback.js` throws it when `typeof opts.note !== 'string' || opts.note.length > 255`. The message is "note is invalid".
Fix: Pass a value that satisfies "note is invalid".

## OPERATOR_IS_INVALID

Cause: `recordFeedback()` in `packages/core/src/engine/feedback.js` throws it when `typeof opts.operator !== 'string' || opts.operator.length === 0 || opts.operator.length > 64`. The message is "operator is invalid".
Fix: Pass a value that satisfies "operator is invalid".

## OPTIONS_MUST_BE_AN_OBJECT

Cause: `validateOptions()` in `packages/core/src/engine/validate/index.js` throws it when `!input || typeof input !== 'object' || Array.isArray(input)`. The message is "options must be an object".
Fix: Correct the input so this passes: "options must be an object". The library does not change traffic.

## OT_SPOOF_OWNERS_MUST_BE_AN_ARRAY

Cause: `importState()` in `packages/core/src/detectors/ot-spoof.js` throws it when `!Array.isArray(state.owners)`. The message is "ot-spoof owners must be an array".
Fix: Pass an array. The check says "ot-spoof owners must be an array".

## OT_VALUE_OUT_OF_RANGE_RANGES_MUST_BE_AN_ARRAY

Cause: `importState()` in `packages/core/src/detectors/ot-value-out-of-range.js` throws it when `!Array.isArray(state.ranges)`. The message is "ot-value-out-of-range ranges must be an array".
Fix: Pass an array. The check says "ot-value-out-of-range ranges must be an array".

## P2_COUNT_IS_INVALID

Cause: `fromJSON()` in `packages/core/src/engine/stats/p2.js` throws it when `typeof row.count !== 'number' || !Number.isInteger(row.count) || row.count < 0`. The message is "p2.count is invalid".
Fix: Pass a value that satisfies "p2.count is invalid".

## P2_MARKERS_IS_INVALID

Cause: `fromJSON()` in `packages/core/src/engine/stats/p2.js` throws it when `!Number.isFinite(markers[i])`. The message is "p2.markers is invalid".
Fix: Pass a value that satisfies "p2.markers is invalid".

## P2_P_IS_INVALID

Cause: `createP2()` in `packages/core/src/engine/stats/p2.js` throws it when `typeof p !== 'number' || !(p > 0) || !(p < 1)`. The message is "p2.p is invalid". `fromJSON()` in `packages/core/src/engine/stats/p2.js` throws it when `typeof row.p !== 'number' || !(row.p > 0) || !(row.p < 1)`. The message is "p2.p is invalid".
Fix: Pass a value that satisfies "p2.p is invalid".

## P2_STATE_MUST_BE_AN_OBJECT

Cause: `fromJSON()` in `packages/core/src/engine/stats/p2.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "p2 state must be an object".
Fix: Correct the input so this passes: "p2 state must be an object". The library does not change traffic.

## PAGEHINKLEY_ALARMED_IS_INVALID

Cause: `fromJSON()` in `packages/core/src/engine/stats/pagehinkley.js` throws it when `typeof row.alarmed !== 'boolean'`. The message is "pagehinkley.alarmed is invalid".
Fix: Pass a value that satisfies "pagehinkley.alarmed is invalid".

## PAGEHINKLEY_COUNT_IS_INVALID

Cause: `fromJSON()` in `packages/core/src/engine/stats/pagehinkley.js` throws it when `typeof row.count !== 'number' || !Number.isInteger(row.count) || row.count < 0`. The message is "pagehinkley.count is invalid".
Fix: Pass a value that satisfies "pagehinkley.count is invalid".

## PAGEHINKLEY_DELTA_IS_INVALID

Cause: `createPageHinkley()` in `packages/core/src/engine/stats/pagehinkley.js` throws it when `typeof opts.delta !== 'number' || !(opts.delta >= 0) || !Number.isFinite(opts.delta)`. The message is "pagehinkley.delta is invalid".
Fix: Pass a value that satisfies "pagehinkley.delta is invalid".

## PAGEHINKLEY_LAMBDA_IS_INVALID

Cause: `createPageHinkley()` in `packages/core/src/engine/stats/pagehinkley.js` throws it when `typeof opts.lambda !== 'number' || !(opts.lambda > 0) || !Number.isFinite(opts.lambda)`. The message is "pagehinkley.lambda is invalid".
Fix: Pass a value that satisfies "pagehinkley.lambda is invalid".

## PAGEHINKLEY_OPTIONS_MUST_BE_AN_OBJECT

Cause: `createPageHinkley()` in `packages/core/src/engine/stats/pagehinkley.js` throws it when `!opts || typeof opts !== 'object'`. The message is "pagehinkley options must be an object".
Fix: Correct the input so this passes: "pagehinkley options must be an object". The library does not change traffic.

## PAGEHINKLEY_STATE_MUST_BE_AN_OBJECT

Cause: `fromJSON()` in `packages/core/src/engine/stats/pagehinkley.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "pagehinkley state must be an object".
Fix: Correct the input so this passes: "pagehinkley state must be an object". The library does not change traffic.

## PEER_GROUP_IS_INVALID

Cause: `setPeerGroup()` in `packages/core/src/engine/engine.js` throws it when `groupId != null && (typeof groupId !== 'string' || groupId.length > this.opts.maxString)`. The message is "peer group is invalid".
Fix: Pass a value that satisfies "peer group is invalid".

## POLICY_EXCEEDS_CAP

Cause: `parsePolicy()` in `packages/core/src/engine/validate/common.js` throws it when `input.policy.length > 256`. The message is "policy exceeds cap".
Fix: Stay inside the cap. The check says "policy exceeds cap".

## POLICY_ID_IS_INVALID

Cause: `parsePolicy()` in `packages/core/src/engine/validate/common.js` throws it when `typeof rule.id !== 'string' || !/^[a-z0-9-]+$/.test(rule.id)`. The message is "policy id is invalid".
Fix: Pass a value that satisfies "policy id is invalid".

## POLICY_MATCH_IS_INVALID

Cause: `parsePolicy()` in `packages/core/src/engine/validate/common.js` throws it when `!rule.match || typeof rule.match !== 'object' || Array.isArray(rule.match)`. The message is "policy match is invalid".
Fix: Pass a value that satisfies "policy match is invalid".

## POLICY_MUST_BE_AN_ARRAY

Cause: `parsePolicy()` in `packages/core/src/engine/validate/common.js` throws it when `!Array.isArray(input.policy)`. The message is "policy must be an array".
Fix: Pass an array. The check says "policy must be an array".

## POLICY_RULE_IS_INVALID

Cause: `parsePolicy()` in `packages/core/src/engine/validate/common.js` throws it when `!rule || typeof rule !== 'object' || Array.isArray(rule)`. The message is "policy rule is invalid".
Fix: Pass a value that satisfies "policy rule is invalid".

## POLICY_SEVERITY_IS_INVALID

Cause: `parsePolicy()` in `packages/core/src/engine/validate/common.js` throws it when `rule.severity != null && !SEVERITY_NAMES.has(rule.severity)`. The message is "policy severity is invalid".
Fix: Pass a value that satisfies "policy severity is invalid".

## PROMOTE_MUST_BE_FALSE_OR_AN_OBJECT

Cause: `parsePromote()` in `packages/core/src/engine/validate/common.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "promote must be false or an object".
Fix: Correct the input so this passes: "promote must be false or an object". The library does not change traffic.

## REDACT_FIELDS_IS_INVALID

Cause: `parseRedact()` in `packages/core/src/engine/validate/index.js` throws it when `fields.some((/** @type {unknown} */ field) => typeof field !== 'string')`. The message is "redact.fields is invalid".
Fix: Pass a value that satisfies "redact.fields is invalid".

## REDACT_KEY_IS_INVALID

Cause: `parseRedact()` in `packages/core/src/engine/validate/index.js` throws it when `typeof value.key !== 'string' && !Buffer.isBuffer(value.key)`. The message is "redact.key is invalid".
Fix: Pass a value that satisfies "redact.key is invalid".

## REDACT_MUST_BE_AN_OBJECT

Cause: `parseRedact()` in `packages/core/src/engine/validate/index.js` throws it when `!value || typeof value !== 'object' || Array.isArray(value)`. The message is "redact must be an object".
Fix: Correct the input so this passes: "redact must be an object". The library does not change traffic.

## REDACT_REDACTMAP_MUST_BE_A_FUNCTION

Cause: `parseRedact()` in `packages/core/src/engine/validate/index.js` throws it when `value.redactMap != null && typeof value.redactMap !== 'function'`. The message is "redact.redactMap must be a function".
Fix: Correct the input so this passes: "redact.redactMap must be a function". The library does not change traffic.

## RULES_ID_IS_DUPLICATED

Cause: `compileRules()` in `packages/core/src/engine/rules.js` throws it when `seen.has(spec.id)`. The message is "rules[${i}].id is duplicated".
Fix: Correct the input so this passes: "rules[${i}].id is duplicated". The library does not change traffic.

## RULES_MUST_BE_AN_ARRAY

Cause: `compileRules()` in `packages/core/src/engine/rules.js` throws it when `!Array.isArray(input)`. The message is "rules must be an array".
Fix: Pass an array. The check says "rules must be an array".

## SAMPLES_MUST_BE_AN_ARRAY

Cause: `readSamples()` in `packages/core/src/detectors/samples.js` throws it when `!Array.isArray(state.samples)`. The message is "samples must be an array". `readStreamState()` in `packages/core/src/detectors/samples.js` throws it when `!Array.isArray(state.samples)`. The message is "samples must be an array". `importState()` in `packages/core/src/detectors/slow-exfil.js` throws it when `state.samples != null && !Array.isArray(state.samples)`. The message is "samples must be an array".
Fix: Pass an array. The check says "samples must be an array".

## SAMPLES_MUST_BE_A_NON_NEGATIVE_INTEGER

Cause: `readState()` in `packages/core/src/detectors/ttl-anomaly.js` throws it when `!Number.isInteger(state.samples) || state.samples < 0`. The message is "samples must be a non-negative integer".
Fix: Correct the input so this passes: "samples must be a non-negative integer". The library does not change traffic.

## SAMPLES_MUST_BE_NON_NEGATIVE_NUMBERS

Cause: `readSamples()` in `packages/core/src/detectors/samples.js` throws it when `typeof value !== 'number' || !Number.isFinite(value) || value < 0`. The message is "samples must be non-negative numbers". `readStreamState()` in `packages/core/src/detectors/samples.js` throws it when `typeof value !== 'number' || !Number.isFinite(value) || value < 0`. The message is "samples must be non-negative numbers".
Fix: Correct the input so this passes: "samples must be non-negative numbers". The library does not change traffic.

## SEEN_MUST_BE_AN_ARRAY

Cause: `read()` in `packages/core/src/detectors/wrong-time.js` throws it when `!Array.isArray(keys)`. The message is "seen must be an array".
Fix: Pass an array. The check says "seen must be an array".

## SEEN_MUST_BE_STRINGS

Cause: `read()` in `packages/core/src/detectors/wrong-time.js` throws it when `typeof key !== 'string'`. The message is "seen must be strings".
Fix: Pass a string. The check says "seen must be strings".

## SEQUENCE_IS_INVALID

Cause: `normalizeSequence()` in `packages/core/src/engine/rules.js` throws it when `!Array.isArray(steps) || steps.length < 2 || steps.length > STEP_CAP`. The message is "${path}.sequence is invalid".
Fix: Pass a value that satisfies "${path}.sequence is invalid".

## SEVERITY_IS_INVALID

Cause: `normalizeRule()` in `packages/core/src/engine/rules.js` throws it when `!SEVERITIES.has(rule.severity)`. The message is "${path}.severity is invalid".
Fix: Pass a value that satisfies "${path}.severity is invalid".

## SHADOW_ID_IS_INVALID

Cause: `parseShadow()` in `packages/core/src/engine/validate/common.js` throws it when `typeof id !== 'string' || !/^(?:rule:)?[a-z0-9-]+$/.test(id)`. The message is "shadow id is invalid".
Fix: Pass a value that satisfies "shadow id is invalid".

## SHADOW_MUST_BE_FALSE_TRUE_OR_AN_ARRAY_OF_IDS

Cause: `parseShadow()` in `packages/core/src/engine/validate/common.js` throws it when `!Array.isArray(value)`. The message is "shadow must be false, true, or an array of ids".
Fix: Correct the input so this passes: "shadow must be false, true, or an array of ids". The library does not change traffic.

## SHARDS_MUST_BE_AN_INTEGER_FROM_1_TO_64

Cause: `createShardedEngine()` in `packages/core/src/engine/finish09.js` throws it when `!Number.isInteger(shards) || shards < 1 || shards > 64`. The message is "shards must be an integer from 1 to 64".
Fix: Pass a value that satisfies "shards must be an integer from 1 to 64".

## SINCESEQ_IS_INVALID

Cause: `checkpointDelta()` in `packages/core/src/engine/finish09.js` throws it when `!Number.isInteger(sinceSeq) || sinceSeq < 0`. The message is "sinceSeq is invalid".
Fix: Pass a value that satisfies "sinceSeq is invalid".

## STATE_IS_INVALID

Cause: `importState()` in `packages/core/src/detectors/dispersed-flood.js` throws it when `!row || typeof row !== 'object' || Array.isArray(row)`. The message is "dispersed-flood row is invalid". `importState()` in `packages/core/src/detectors/inbound-lateral.js` throws it when `!row || typeof row !== 'object' || Array.isArray(row)`. The message is "inbound-lateral row is invalid". `importState()` in `packages/core/src/detectors/inbound-lateral.js` throws it when `typeof row.src !== 'string' || typeof row.ts !== 'number'`. The message is "inbound-lateral row is invalid". `importState()` in `packages/core/src/detectors/onion-name.js` throws it when `!row || typeof row !== 'object' || Array.isArray(row)`. The message is "onion-name row is invalid". `importState()` in `packages/core/src/detectors/onion-name.js` throws it when `typeof row.name !== 'string' || typeof row.ts !== 'number'`. The message is "onion-name row is invalid". `readSamples()` in `packages/core/src/detectors/samples.js` throws it when `!state || typeof state !== 'object' || Array.isArray(state)`. The message is "${id} state is invalid". `readStreamState()` in `packages/core/src/detectors/samples.js` throws it when `!state || typeof state !== 'object' || Array.isArray(state)`. The message is "${id} state is invalid". `importState()` in `packages/core/src/detectors/scatter-udp.js` throws it when `!row || typeof row !== 'object' || Array.isArray(row)`. The message is "scatter-udp row is invalid". `importState()` in `packages/core/src/detectors/short-lived-cert.js` throws it when `!row || typeof row !== 'object' || Array.isArray(row)`. The message is "short-lived-cert row is invalid". `importState()` in `packages/core/src/detectors/short-lived-cert.js` throws it when `typeof row.key !== 'string' || typeof row.ts !== 'number'`. The message is "short-lived-cert row is invalid". `assertState()` in `packages/core/src/detectors/state.js` throws it when `!state || typeof state !== 'object' || Array.isArray(state)`. The message is "${id} state is invalid".
Fix: Pass a value that satisfies "dispersed-flood row is invalid". Pass a value that satisfies "inbound-lateral row is invalid". Pass a value that satisfies "onion-name row is invalid". Pass a value that satisfies "${id} state is invalid". Pass a value that satisfies "scatter-udp row is invalid". Pass a value that satisfies "short-lived-cert row is invalid".

## STRING_TOO_LONG

Cause: `importState()` in `packages/core/src/detectors/arp-spoof.js` throws it when `ip.length > 64 || mac.length > 64`. The message is "string too long". `importState()` in `packages/core/src/detectors/dispersed-flood.js` throws it when `row.ip.length > caps.maxString`. The message is "string too long". `importState()` in `packages/core/src/detectors/egress-flood.js` throws it when `pair[0].length > caps.maxString`. The message is "string too long". `importState()` in `packages/core/src/detectors/inbound-lateral.js` throws it when `row.src.length > caps.maxString`. The message is "string too long". `readNames()` in `packages/core/src/detectors/new-destination.js` throws it when `item.length > maxString`. The message is "string too long". `importState()` in `packages/core/src/detectors/onion-name.js` throws it when `row.name.length > caps.maxString`. The message is "string too long". `importState()` in `packages/core/src/detectors/short-lived-cert.js` throws it when `row.key.length > caps.maxString`. The message is "string too long". `readStrings()` in `packages/core/src/detectors/state.js` throws it when `item.length > maxString`. The message is "string too long". `read()` in `packages/core/src/detectors/wrong-time.js` throws it when `key.length > caps.maxString`. The message is "string too long". `optionalString()` in `packages/core/src/engine/audit.js` throws it when `value.length > MAX_FIELD`. The message is "string too long". `storedString()` in `packages/core/src/engine/audit.js` throws it when `value.length > MAX_FIELD`. The message is "string too long". `prepareImport()` in `packages/core/src/engine/baseline.js` throws it when `FORBIDDEN_KEYS.has(id) || id.length === 0 || id.length > ctx.caps.maxString`. The message is "string too long". `prepareImport()` in `packages/core/src/engine/baseline.js` throws it when `typeof record.peerGroup !== 'string' || record.peerGroup.length > ctx.caps.maxString`. The message is "string too long".
Fix: Correct the input so this passes: "string too long". The library does not change traffic.

## SUMMARIES_MUST_BE_AN_ARRAY

Cause: `importPeerSummaries()` in `packages/core/src/engine/finish09.js` throws it when `!Array.isArray(list)`. The message is "summaries must be an array".
Fix: Pass an array. The check says "summaries must be an array".

## SUMMARY_GROUPS_ARE_INVALID

Cause: `importPeerSummaries()` in `packages/core/src/engine/finish09.js` throws it when `row.groups != null && !Array.isArray(row.groups)`. The message is "summary groups are invalid".
Fix: Correct the input so this passes: "summary groups are invalid". The library does not change traffic.

## SUMMARY_GROUP_IS_INVALID

Cause: `importPeerSummaries()` in `packages/core/src/engine/finish09.js` throws it when `!group || typeof group !== 'object' || Array.isArray(group)`. The message is "summary group is invalid".
Fix: Pass a value that satisfies "summary group is invalid".

## SUMMARY_IS_INVALID

Cause: `importPeerSummaries()` in `packages/core/src/engine/finish09.js` throws it when `!row || typeof row !== 'object' || Array.isArray(row)`. The message is "summary is invalid".
Fix: Pass a value that satisfies "summary is invalid".

## SUMMARY_KEY_IS_INVALID

Cause: `exportSummary()` in `packages/core/src/engine/finish09.js` throws it when `typeof opts.key !== 'string' && !Buffer.isBuffer(opts.key)`. The message is "summary key is invalid".
Fix: Pass a value that satisfies "summary key is invalid".

## SUMMARY_SIGNATURE_IS_INVALID

Cause: `importPeerSummaries()` in `packages/core/src/engine/finish09.js` throws it when `!macMatches(opts.verify, unsigned, mac)`. The message is "summary signature is invalid".
Fix: Pass a value that satisfies "summary signature is invalid".

## TICK_TIME_IS_INVALID

Cause: `tick()` in `packages/core/src/engine/windows.js` throws it when `typeof at !== 'number' || !Number.isFinite(at)`. The message is "tick time is invalid".
Fix: Pass a value that satisfies "tick time is invalid".

## TIERSILENTBYTIER_IS_INVALID

Cause: `tierLimits()` in `packages/core/src/engine/validate/common.js` throws it when `!TIER_SET.has(tier)`. The message is "tierSilentByTier.${tier} is invalid".
Fix: Pass a value that satisfies "tierSilentByTier.${tier} is invalid".

## TIERSILENTBYTIER_MUST_BE_AN_OBJECT

Cause: `tierLimits()` in `packages/core/src/engine/validate/common.js` throws it when `!input || typeof input !== 'object' || Array.isArray(input)`. The message is "tierSilentByTier must be an object".
Fix: Correct the input so this passes: "tierSilentByTier must be an object". The library does not change traffic.

## TIERS_MUST_LIST_ONE_OR_MORE_OF_T0_T5

Cause: `validateOptions()` in `packages/core/src/engine/validate/index.js` throws it when `!Array.isArray(tiers) || tiers.length === 0 || tiers.some((tier) => !TIER_SET.has(tier))`. The message is "tiers must list one or more of T0..T5".
Fix: Correct the input so this passes: "tiers must list one or more of T0..T5". The library does not change traffic.

## TIME_ZONE_IS_INVALID

Cause: `setDeviceTimezone()` in `packages/core/src/engine/finish09.js` throws it when `typeof zone !== 'string' || zone.length === 0 || zone.length > 64`. The message is "time zone is invalid".
Fix: Pass a value that satisfies "time zone is invalid".

## UNKNOWN_ANOMALY

Cause: `recordFeedback()` in `packages/core/src/engine/feedback.js` throws it when `!meta`. The message is "unknown anomaly".
Fix: Correct the input so this passes: "unknown anomaly". The library does not change traffic.

## UNKNOWN_DETECTOR

Cause: `prepareImport()` in `packages/core/src/engine/baseline.js` throws it when `!det`. The message is "unknown detector ${detId}". `_checkDetectorOptions()` in `packages/core/src/engine/engine.js` throws it when `!this.byId.has(id)`. The message is "unknown detector ${id}". `_checkShadowList()` in `packages/core/src/engine/engine.js` throws it when `!this.byId.has(id)`. The message is "unknown detector ${id}". `suppress()` in `packages/core/src/engine/engine.js` throws it when `!this.byId.has(detectorId)`. The message is "unknown detector ${detectorId}". `relearn()` in `packages/core/src/engine/learning.js` throws it when `!det`. The message is "unknown detector ${id}".
Fix: Correct the input so this passes: "unknown detector ${detId}". The library does not change traffic. Correct the input so this passes: "unknown detector ${id}". The library does not change traffic. Correct the input so this passes: "unknown detector ${detectorId}". The library does not change traffic.

## UNKNOWN_DEVICE

Cause: `_requireDevice()` in `packages/core/src/engine/state.js` throws it when `!device || !device.seen`. The message is "unknown device ${id}".
Fix: Correct the input so this passes: "unknown device ${id}". The library does not change traffic.

## UNKNOWN_DEVICE_CLASS

Cause: `setDeviceClass()` in `packages/core/src/engine/engine.js` throws it when `!CLASSES[classId]`. The message is "unknown device class".
Fix: Correct the input so this passes: "unknown device class". The library does not change traffic.

## UNKNOWN_EVENT_TYPE

Cause: `validateEvent()` in `packages/core/src/engine/validate/index.js` throws it when `type === 'app') return { event: appEvent(raw, ts, warnings), warnings };`. The message is "unknown event type ${type}".
Fix: Correct the input so this passes: "unknown event type ${type}". The library does not change traffic.

## UNKNOWN_SCRATCH_TABLE

Cause: `assertCheckpoint()` in `packages/core/src/engine/checkpoint.js` throws it when `!KNOWN.has(key)`. The message is "unknown scratch table ${key}".
Fix: Correct the input so this passes: "unknown scratch table ${key}". The library does not change traffic.

## UNSUPPORTED_BASELINE

Cause: `prepareImport()` in `packages/core/src/engine/baseline.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "unsupported baseline". `prepareImport()` in `packages/core/src/engine/baseline.js` throws it when `raw.version !== 1 && !modern`. The message is "unsupported baseline".
Fix: Correct the input so this passes: "unsupported baseline". The library does not change traffic.

## UNSUPPORTED_CHECKPOINT

Cause: `assertCheckpoint()` in `packages/core/src/engine/checkpoint.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "unsupported checkpoint".
Fix: Correct the input so this passes: "unsupported checkpoint". The library does not change traffic.

## UNTILTS_IS_INVALID

Cause: `suppress()` in `packages/core/src/engine/engine.js` throws it when `typeof opts.untilTs !== 'number' || !Number.isFinite(opts.untilTs)`. The message is "untilTs is invalid".
Fix: Pass a value that satisfies "untilTs is invalid".

## VERDICT_IS_INVALID

Cause: `recordFeedback()` in `packages/core/src/engine/feedback.js` throws it when `!VERDICTS.has(verdict)`. The message is "verdict is invalid".
Fix: Pass a value that satisfies "verdict is invalid".

## WELFORD_EMPTY_STATE_IS_INVALID

Cause: `fromJSON()` in `packages/core/src/engine/stats/welford.js` throws it when `mean !== 0 || m2 !== 0`. The message is "welford empty state is invalid".
Fix: Pass a value that satisfies "welford empty state is invalid".

## WELFORD_M2_IS_INVALID

Cause: `fromJSON()` in `packages/core/src/engine/stats/welford.js` throws it when `m2 < 0`. The message is "welford.m2 is invalid".
Fix: Pass a value that satisfies "welford.m2 is invalid".

## WELFORD_MIN_IS_ABOVE_MAX

Cause: `fromJSON()` in `packages/core/src/engine/stats/welford.js` throws it when `min > max`. The message is "welford.min is above max".
Fix: Correct the input so this passes: "welford.min is above max". The library does not change traffic.

## WELFORD_STATE_MUST_BE_AN_OBJECT

Cause: `fromJSON()` in `packages/core/src/engine/stats/welford.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "welford state must be an object".
Fix: Correct the input so this passes: "welford state must be an object". The library does not change traffic.

## WHEN_IS_INVALID

Cause: `normalizeWhen()` in `packages/core/src/engine/rules.js` throws it when `!when || typeof when !== 'object' || Array.isArray(when)`. The message is "${path}.when is invalid".
Fix: Pass a value that satisfies "${path}.when is invalid".

## WHEN_IS_INVALID_2

Cause: `normalizeWhen()` in `packages/core/src/engine/rules.js` throws it when `!pred || typeof pred !== 'object' || Array.isArray(pred)`. The message is "${path}.when.${name} is invalid". `normalizeWhen()` in `packages/core/src/engine/rules.js` throws it when `keys.length !== 1 || !['gt', 'gte', 'lt', 'lte', 'eq'].includes(keys[0])`. The message is "${path}.when.${name} is invalid". `normalizeWhen()` in `packages/core/src/engine/rules.js` throws it when `typeof value !== 'number' || !Number.isFinite(value)`. The message is "${path}.when.${name} is invalid".
Fix: Pass a value that satisfies "${path}.when.${name} is invalid".

## WIFI_MAC_IS_INVALID

Cause: `linkEvent()` in `packages/core/src/engine/validate/link.js` throws it when `!isMac(mac)`. The message is "wifi.mac is invalid".
Fix: Pass a value that satisfies "wifi.mac is invalid".

## WIFI_OP_IS_INVALID

Cause: `linkEvent()` in `packages/core/src/engine/validate/link.js` throws it when `!WIFI_OPS.has(raw.op)`. The message is "wifi.op is invalid".
Fix: Pass a value that satisfies "wifi.op is invalid".

## WINDOWMS_MISMATCH

Cause: `prepareImport()` in `packages/core/src/engine/baseline.js` throws it when `!raw.engine || raw.engine.windowMs !== ctx.windowMs`. The message is "windowMs mismatch".
Fix: Use the same windowMs the baseline or checkpoint was exported with, or re-learn.

## WORKER_SHARDS_WAIT_FOR_A_RASPBERRY_PI_4_BENCH

Cause: `createShardedEngine()` in `packages/core/src/engine/finish09.js` throws it when `opts.inline !== true`. The message is "worker shards wait for a Raspberry Pi 4 bench".
Fix: Correct the input so this passes: "worker shards wait for a Raspberry Pi 4 bench". The library does not change traffic.

## WRONG_TIME_STATE_IS_INVALID

Cause: `read()` in `packages/core/src/detectors/wrong-time.js` throws it when `!state || typeof state !== 'object' || Array.isArray(state)`. The message is "wrong-time state is invalid".
Fix: Pass a value that satisfies "wrong-time state is invalid".

## ZONES_ARE_INVALID

Cause: `parseZones()` in `packages/core/src/engine/validate/common.js` throws it when `!Array.isArray(input.zones) || input.zones.length > 64`. The message is "zones are invalid".
Fix: Correct the input so this passes: "zones are invalid". The library does not change traffic.

## ZONE_CIDR_IS_INVALID

Cause: `parseZones()` in `packages/core/src/engine/validate/common.js` throws it when `base == null || bits < 0 || bits > 32`. The message is "zone cidr is invalid".
Fix: Pass a value that satisfies "zone cidr is invalid".

## ZONE_ID_IS_INVALID

Cause: `parseZones()` in `packages/core/src/engine/validate/common.js` throws it when `typeof zone.id !== 'string' || !/^[a-z0-9-]+$/.test(zone.id)`. The message is "zone id is invalid".
Fix: Pass a value that satisfies "zone id is invalid".

## ZONE_IS_INVALID

Cause: `parseZones()` in `packages/core/src/engine/validate/common.js` throws it when `!zone || typeof zone !== 'object' || Array.isArray(zone)`. The message is "zone is invalid".
Fix: Pass a value that satisfies "zone is invalid".

## WIFI_SSID_IS_REQUIRED

Cause: `linkEvent()` in `packages/core/src/engine/validate/link.js` throws it when `raw.op === 'probe-resp' && !event.ssid`. The message is "wifi ssid is required".
Fix: Pass a value that satisfies "wifi ssid is required".

## BLOOM_STATE_MUST_BE_AN_OBJECT

Cause: `assertBloom()` in `packages/core/src/engine/stats/bloom.js` throws it when `!state || typeof state !== 'object' || !(state.bits instanceof Uint8Array)`. The message is "bloom state must be an object". `assertBloom()` in `packages/core/src/engine/stats/bloom.js` throws it when `state.bits.length !== BYTES`. The message is "bloom state must be an object". `fromJSON()` in `packages/core/src/engine/stats/bloom.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "bloom state must be an object". `fromJSON()` in `packages/core/src/engine/stats/bloom.js` throws it when `typeof row.bits !== 'string'`. The message is "bloom state must be an object". `fromJSON()` in `packages/core/src/engine/stats/bloom.js` throws it when `bytes.length !== BYTES`. The message is "bloom state must be an object".
Fix: Correct the input so this passes: "bloom state must be an object". The library does not change traffic.

## BLOOM_TOKEN_MUST_BE_A_STRING

Cause: `add()` in `packages/core/src/engine/stats/bloom.js` throws it when `typeof token !== 'string' || token.length === 0`. The message is "bloom token must be a string". `has()` in `packages/core/src/engine/stats/bloom.js` throws it when `typeof token !== 'string' || token.length === 0`. The message is "bloom token must be a string".
Fix: Pass a string. The check says "bloom token must be a string".

## HSTREE_POINT_IS_INVALID

Cause: `assertPoint()` in `packages/core/src/engine/stats/hstree.js` throws it when `!point || point.length !== DIMS`. The message is "hstree point is invalid". `assertPoint()` in `packages/core/src/engine/stats/hstree.js` throws it when `typeof point[i] !== 'number' || !Number.isFinite(point[i])`. The message is "hstree point is invalid".
Fix: Pass a value that satisfies "hstree point is invalid".

## HSTREE_SEED_IS_INVALID

Cause: `createForest()` in `packages/core/src/engine/stats/hstree.js` throws it when `!Number.isInteger(seed) || seed < 0`. The message is "hstree seed is invalid". `fromJSON()` in `packages/core/src/engine/stats/hstree.js` throws it when `!Number.isInteger(row.seed) || row.seed < 0`. The message is "hstree seed is invalid".
Fix: Pass a value that satisfies "hstree seed is invalid".

## HSTREE_STATE_MUST_BE_AN_OBJECT

Cause: `assertForest()` in `packages/core/src/engine/stats/hstree.js` throws it when `!state || typeof state !== 'object' || !(state.mass instanceof Uint32Array) || state.mass.length !== TREES * NODES || !(state.lo instanceof Float64Array) || !(state.hi instanceof Float64Array)`. The message is "hstree state must be an object". `fromJSON()` in `packages/core/src/engine/stats/hstree.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "hstree state must be an object". `fromJSON()` in `packages/core/src/engine/stats/hstree.js` throws it when `!Number.isInteger(row.seen) || row.seen < 0`. The message is "hstree state must be an object". `fromJSON()` in `packages/core/src/engine/stats/hstree.js` throws it when `!Array.isArray(row.lo) || !Array.isArray(row.hi) || row.lo.length !== DIMS || row.hi.length !== DIMS`. The message is "hstree state must be an object". `fromJSON()` in `packages/core/src/engine/stats/hstree.js` throws it when `typeof row.lo[i] !== 'number' || typeof row.hi[i] !== 'number'`. The message is "hstree state must be an object". `fromJSON()` in `packages/core/src/engine/stats/hstree.js` throws it when `typeof row.mass !== 'string'`. The message is "hstree state must be an object". `fromJSON()` in `packages/core/src/engine/stats/hstree.js` throws it when `bytes.length !== state.mass.byteLength`. The message is "hstree state must be an object".
Fix: Correct the input so this passes: "hstree state must be an object". The library does not change traffic.

## MINHASH_STATE_MUST_BE_AN_OBJECT

Cause: `fromJSON()` in `packages/core/src/engine/stats/minhash.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "minhash state must be an object".
Fix: Correct the input so this passes: "minhash state must be an object". The library does not change traffic.

## MINHASH_TOKEN_MUST_BE_A_STRING

Cause: `add()` in `packages/core/src/engine/stats/minhash.js` throws it when `typeof token !== 'string'`. The message is "minhash token must be a string".
Fix: Pass a string. The check says "minhash token must be a string".

## MODEL_PACK_IS_OFF

Cause: `loadModelPack()` in `packages/core/src/engine/modelpack.js` throws it when `modelPack` is not `true`. The message is "model pack is off".
Fix: Pass `modelPack: true`, or do not call `loadModelPack`.

## MODEL_PACK_IS_INVALID

Cause: `loadModelPack()` in `packages/core/src/engine/modelpack.js` throws it when the pack is missing, the version is not 3, `model` is not an existing class id, `verify` is missing, or a forbidden key is present. `parseModelPack()` throws the same code when the option is not `true` or `false`. The message is "model pack is invalid". `selftest()` throws `SELFTEST_IS_INVALID` separately.
Fix: Pass a version-3 baseline signed with the A6 HMAC-SHA256 signature, a `model` string that is an existing class id, and `{ verify: key }`.

## SELFTEST_IS_INVALID

Cause: `selftest()` in `packages/core/src/engine/coverage.js` throws it when the scenario file is over 16 scenarios, a scenario is over 10,000 events, or a requested scenario name is not in the file. The message is "selftest is invalid".
Fix: Pass scenario names from `src/data/selftest.json`, or omit the filter.

## FAMILIES_IS_INVALID

Cause: `parseFamilies()` in `packages/core/src/engine/validate/index.js` throws it when `families` is not `true` or `false`. The message is "families is invalid".
Fix: Pass `true` or `false`, or leave the option out.

## PROFILE_IS_INVALID

Cause: `parseProfile()` in `packages/core/src/engine/validate/index.js` throws it when `profile` is not `all` or `core`. The message is "profile is invalid". `coreIdSet()` throws the same code when the core profile file has no `ids` array.
Fix: Pass `all` or `core`.

## SCORING_IS_INVALID

Cause: `parseScoring()` in `packages/core/src/engine/validate/index.js` throws it when `value === 'additive' || value === 'lr') return value;`. The message is "scoring is invalid".
Fix: Pass a value that satisfies "scoring is invalid".

## TEMPLATE_INVALID

Cause: `compile()` in `packages/core/src/engine/templates.js` throws it when `!Array.isArray(list)`. The message is "templates must be an array". `compile()` in `packages/core/src/engine/templates.js` throws it when `list.length > MAX_TEMPLATES`. The message is "at most 64 templates". `compile()` in `packages/core/src/engine/templates.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "template must be an object". `compile()` in `packages/core/src/engine/templates.js` throws it when `typeof row.id !== 'string' || row.id.length === 0 || row.id.length > 64 || seen.has(row.id)`. The message is "template id is invalid". `compile()` in `packages/core/src/engine/templates.js` throws it when `!Array.isArray(row.steps) || row.steps.length === 0 || row.steps.length > MAX_STEPS`. The message is "template steps are invalid". `compile()` in `packages/core/src/engine/templates.js` throws it when `!step || typeof step !== 'object' || Array.isArray(step)`. The message is "template step is invalid". `compile()` in `packages/core/src/engine/templates.js` throws it when `!any || any.length === 0`. The message is "template step any is invalid". `compile()` in `packages/core/src/engine/templates.js` throws it when `typeof id !== 'string' || !known.has(id)`. The message is "template detector is unknown". `compile()` in `packages/core/src/engine/templates.js` throws it when `!KINDS.has(by)`. The message is "template by is invalid". `compile()` in `packages/core/src/engine/templates.js` throws it when `typeof bonus !== 'number' || !Number.isFinite(bonus) || bonus < 0 || bonus > 3`. The message is "template llrBonus is invalid". `parseWithin()` in `packages/core/src/engine/templates.js` throws it when `typeof value !== 'string' || !/^\d+(m|h)$/.test(value)`. The message is "template within is invalid". `parseWithin()` in `packages/core/src/engine/templates.js` throws it when `ms <= 0 || ms > MAX_WITHIN`. The message is "template within is invalid".
Fix: Pass an array. The check says "templates must be an array". Correct the input so this passes: "at most 64 templates". The library does not change traffic. Correct the input so this passes: "template must be an object". The library does not change traffic. Pass a value that satisfies "template id is invalid". Correct the input so this passes: "template steps are invalid". The library does not change traffic. Pass a value that satisfies "template step is invalid". Pass a value that satisfies "template step any is invalid". Correct the input so this passes: "template detector is unknown". The library does not change traffic. Pass a value that satisfies "template by is invalid". Pass a value that satisfies "template llrBonus is invalid". Pass a value that satisfies "template within is invalid".

## CRITICALITY_IS_INVALID

Cause: `setDeviceCriticality()` in `packages/core/src/engine/partg.js` throws it when `!LEVELS.has(level)`. The message is "criticality is invalid".
Fix: Pass a value that satisfies "criticality is invalid".

## CHECKPOINT_CORRELATE_IS_INVALID

Cause: `invalid()` in `packages/core/src/engine/correlate.js` throws it when `typeof fromDns !== 'boolean') invalid(); return { ts, name, fromDns }; } /** * @returns {never} */ function invalid(`. The message is "checkpoint correlate is invalid".
Fix: Pass a value that satisfies "checkpoint correlate is invalid".

## CHECKPOINT_FDR_IS_INVALID

Cause: `readFdr()` in `packages/core/src/engine/partg.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "checkpoint fdr is invalid". `readFdr()` in `packages/core/src/engine/partg.js` throws it when `entries.length > 10000`. The message is "checkpoint fdr is invalid". `readFdr()` in `packages/core/src/engine/partg.js` throws it when `id.length === 0 || id.length > 255`. The message is "checkpoint fdr is invalid". `fromJSON()` in `packages/core/src/engine/stats/alphainvest.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "checkpoint fdr is invalid". `fromJSON()` in `packages/core/src/engine/stats/alphainvest.js` throws it when `!Number.isInteger(row.wealth) || row.wealth < 0 || row.wealth > WEALTH0`. The message is "checkpoint fdr is invalid". `fromJSON()` in `packages/core/src/engine/stats/alphainvest.js` throws it when `row.day != null && (!Number.isInteger(row.day) || row.day < 0)`. The message is "checkpoint fdr is invalid". `fromJSON()` in `packages/core/src/engine/stats/alphainvest.js` throws it when `!Array.isArray(row.decisions) || row.decisions.length > CAP`. The message is "checkpoint fdr is invalid". `fromJSON()` in `packages/core/src/engine/stats/alphainvest.js` throws it when `!item || typeof item !== 'object' || Array.isArray(item)`. The message is "checkpoint fdr is invalid". `fromJSON()` in `packages/core/src/engine/stats/alphainvest.js` throws it when `typeof item.id !== 'string' || item.id.length === 0 || item.id.length > 64`. The message is "checkpoint fdr is invalid". `fromJSON()` in `packages/core/src/engine/stats/alphainvest.js` throws it when `!VERDICTS.has(item.verdict)`. The message is "checkpoint fdr is invalid".
Fix: Pass a value that satisfies "checkpoint fdr is invalid".

## HAWKES_STATE_IS_INVALID

Cause: `fromJSON()` in `packages/core/src/engine/stats/hawkes.js` throws it when `!raw || typeof raw !== 'object' || Array.isArray(raw)`. The message is "hawkes state is invalid". `fromJSON()` in `packages/core/src/engine/stats/hawkes.js` throws it when `!Array.isArray(times) || times.length > CAP`. The message is "hawkes state is invalid". `fromJSON()` in `packages/core/src/engine/stats/hawkes.js` throws it when `!Number.isFinite(time)`. The message is "hawkes state is invalid".
Fix: Pass a value that satisfies "hawkes state is invalid".
