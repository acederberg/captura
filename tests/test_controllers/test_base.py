from app.models import Collection, Document
from app.controllers.base import ResolvedAssignmentDocument, ResolvedDocument
from sqlalchemy.orm import sessionmaker


def test_UuidSetFromModel(sessionmaker: sessionmaker):

    with sessionmaker() as session:
        uuids_expected = {"aaa-aaa-aaa", "draculaflow"}
        docs = Document.if_many(session, uuids_expected)
        assert len(docs) == 2

        res = ResolvedDocument(kind="document", document=docs)  # type: ignore[reportGeneralTypeIssues]
        assert res.document == docs
        assert res.uuid_document == uuids_expected


def test_UuidFromModel(sessionmaker: sessionmaker):

    with sessionmaker() as session:
        uuid_doc_expected = "aaa-aaa-aaa"
        uuid_col_expected = {"foo-ooo-ool", "eee-eee-eee"}
        doc = Document.if_exists(session, uuid_doc_expected)
        collections = Collection.if_many(session, uuid_col_expected)

        assert len(collections) == 2
        res = ResolvedAssignmentDocument(  # type: ignore[reportGeneralTypeIssues]
            document=doc,
            collections=collections,
            kind="assignment_document",
        )
        assert res.uuid_collections == uuid_col_expected
        assert res.uuid_document == uuid_doc_expected
        assert isinstance(res.uuid_document, str)
        assert isinstance(res.uuid_collections, set)
