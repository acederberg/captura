from http import HTTPMethod
from typing import Tuple

import pytest
from app.auth import Auth, Token
from app.models import Collection, Document
from app.views.create import Upsert
from app.views.delete import Delete
from sqlalchemy.orm import Session
from tests.test_views.util import LeveledDocuments, leveled_documents


@pytest.fixture
def delete(session: Session, token: Token) -> Delete:
    return Delete(session, token, HTTPMethod.DELETE)


class TestAssignmentCollection:

    def test_collection(
        self,
        delete: Delete,
        leveled_documents: LeveledDocuments,
        force: bool,
    ):
        collection = Collection.if_exists(delete.session, "eee-eee-eee")
        documents = leveled_documents
        uuid_documents = Document.resolve_uuid(delete.session, documents)

        # Should be able to delete assignments to own collection
        event = delete.assignment_collection(collection, documents)

        # Should not be able to delete assignments to others collections
        with pytest.raises(HTTPException) as err:
            delete.assignment_collection(collection_other, document)

        if force:
            ...
