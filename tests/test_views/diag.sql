


-- Deletetion Profile

CREATE VIEW documents_deletion_profile AS
  SELECT documents.uuid AS uuid,
    documents.deleted AS document_deleted,
    _assocs_users_documents.deleted AS assocs_deleted,
    _assocs_users_documents.level AS level,
    COUNT(_assocs_users_documents.uuid) AS count
  FROM _assocs_users_documents
  JOIN documents ON _assocs_users_documents.id_document=documents.id
  GROUP BY documents.uuid,
    _assocs_users_documents.level,
    _assocs_users_documents.deleted;


-- Where all deleted
CREATE VIEW documents_deletion_profile_null AS
  SELECT uuid, document_deleted, assocs_deleted, level, count
  FROM documents_deletion_profile
  WHERE count=0;
