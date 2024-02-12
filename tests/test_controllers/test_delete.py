from http import HTTPMethod
from typing import Tuple

import pytest
from app.auth import Auth, Token
from app.models import Collection, Document
from app.views.create import Upsert
from sqlalchemy.orm import Session
from tests.test_views.util import LeveledDocuments, leveled_documents


@pytest.fixture
def create(session: Session, token: Token):
    return Upsert(session, token, HTTPMethod.POST)


@pytest.fixture
def update(session: Session, token: Token):
    return Upsert(session, token, HTTPMethod.PATCH)


# def TestAssignmentTryForce:
#
#     def test_collection(self, create: Upsert, leveled_documents: LeveledDocuments):
#         documents = leveled_documents
#         collection = Collection.if_exists(create.session, "eee-eee-eee")
#         uuid_documents = Document.resolve_uuid(create.session, documents)
#
#         event, uuid_active  = create.assignment_try_force(
#             collection,
#             uuid_documents
#         )


class TestDeleteAssignmentCollection: ...
