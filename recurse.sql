
  -- WHERE uuid_parent IS NULL

WITH RECURSIVE bredth_first (uuid, uuid_parent, detail, kind, kind_obj, lllevel) AS (
  SELECT uuid,
    uuid_parent,
    detail,
    kind,
    kind_obj,
    0 AS lllevel
  FROM events
  WHERE uuid IN ('5-NKRMU71UA')

  UNION ALL

  SELECT AA.uuid,
    AA.uuid_parent,
    AA.detail,
    AA.kind,
    AA.kind_obj,
    lllevel + 1 AS lllevel
  FROM events AA
  JOIN bredth_first BB ON BB.uuid = AA.uuid_parent
)
SELECT * FROM bredth_first;


WITH RECURSIVE depth_first (uuid, uuid_parent, detail, kind, kind_obj, path_, lllevel) AS (
  SELECT uuid,
    uuid_parent,
    detail,
    kind,
    kind_obj,
    CAST(uuid AS CHAR(512)) path_,
    0 AS lllevel
  FROM events
  WHERE uuid IN ('5-NKRMU71UA')

  UNION ALL

  SELECT BB.uuid,
    BB.uuid_parent,
    BB.detail,
    BB.kind,
    BB.kind_obj,
    CONCAT(AA.path_, ',', BB.uuid) AS path_,
    lllevel + 1 AS lllevel
  FROM depth_first AA, events BB
  WHERE BB.uuid_parent = AA.uuid
    AND FIND_IN_SET(BB.uuid, AA.path_)=0
)
SELECT * FROM depth_first ORDER BY path_;




WITH RECURSIVE depth_first(
  timestamp, uuid, uuid_parent, uuid_user, uuid_obj, kind, kind_obj, detail,
  api_origin, api_version, path, level
) AS (
  SELECT events.timestamp AS timestamp,
    events.uuid AS uuid,
    events.uuid_parent AS uuid_parent,
    events.uuid_user AS uuid_user,
    events.uuid_obj AS uuid_obj,
    events.kind AS kind,
    events.kind_obj AS kind_obj,
    events.detail AS detail,
    events.api_origin AS api_origin,
    events.api_version AS api_version,
    CAST(events.uuid AS VARCHAR(512)) AS path,
    0 AS level
  FROM events
  WHERE events.uuid IN (__[POSTCOMPILE_uuid_1])

  UNION ALL

  SELECT AA.timestamp AS timestamp,
    AA.uuid AS uuid,
    AA.uuid_parent AS uuid_parent,
    AA.uuid_user AS uuid_user,
    AA.uuid_obj AS uuid_obj,
    AA.kind AS kind,
    AA.kind_obj AS kind_obj,
    AA.detail AS detail,
    AA.api_origin AS api_origin,
    AA.api_version AS api_version,
    concat(roots.path, :concat_1, AA.uuid) AS path,
    level + 1 AS level
  FROM events AS AA, depth_first AS BB
  WHERE AA.uuid = BB.uuid_parent
)
 SELECT depth_first.timestamp, depth_first.uuid, depth_first.uuid_parent, depth_first.uuid_user, depth_first.uuid_obj, depth_first.kind, depth_first.kind_obj, depth_first.detail, depth_first.api_origin, depth_first.api_version, depth_first.path, depth_first.level
FROM depth_first
