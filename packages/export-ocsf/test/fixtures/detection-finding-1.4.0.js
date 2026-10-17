// hand-written from SPEC C3; verify against schema.ocsf.io before 1.0
'use strict';

module.exports = {
  class_uid: 2004,
  category_uid: 2,
  create: { activity_id: 1, type_uid: 200401 },
  update: { activity_id: 2, type_uid: 200402 },
  required: [
    'class_uid',
    'class_name',
    'category_uid',
    'category_name',
    'activity_id',
    'activity_name',
    'type_uid',
    'type_name',
    'severity_id',
    'severity',
    'time',
    'message',
    'finding_info',
    'metadata',
  ],
};
