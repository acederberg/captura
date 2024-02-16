from http import HTTPMethod
from typing import Set, Tuple, Type

import pytest
from app.auth import Auth, Token
from app.models import Collection, Document, Level
from app.schemas import AssignmentCreateSchema, GrantCreateSchema
from app.views.access import H
from app.views.create import Upsert
from app.views.delete import AssocData, Delete
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from tests.test_controllers.test_delete import (CASES_ASSOCS, BaseTestAssoc,
                                                as_data)
from tests.test_views.util import LeveledDocuments, leveled_documents


@pytest.fixture
def upsert(delete: Delete, token: Token) -> Delete:
    return Upsert(delete.session, token, HTTPMethod.DELETE)


@pytest.mark.parametrize(
    "delete, T_source, uuid_source, T_target, uuid_target, T_assoc, uuid_assoc",
    CASES_ASSOCS,
    indirect=["delete"],
)
class TestAssoc(BaseTestAssoc):
    grant_data = GrantCreateSchema(level=Level.own)
    assignment_data = AssignmentCreateSchema()

    def test_assoc(
        self,
        upsert: Upsert,
        T_source: Type,
        uuid_source: str,
        T_target: Type,
        uuid_target: Set[str],
        T_assoc: Type,
        uuid_assoc: Set[str],
    ) -> None:

        data = as_data(
            upsert, T_source, uuid_source, T_target, uuid_target, T_assoc, uuid_assoc
        )
        session = upsert.session
        assocs_init = T_assoc.resolve(session, uuid_assoc)
        mthd = self.check_mthd(upsert, data)

        match data.data.kind_assoc:
            case "grant":
                upsert.upsert_data = self.grant_data
            case "assignment":
                upsert.upsert_data = self.assignment_data
            case kind_assoc:
                raise AssertionError(f"Invalid `{kind_assoc=}`.")


        # NOTE: Run the method without force with undeleted items. These should
        #       all exist so the event should be empty.
        assert data.event is None
        assert upsert.force is False
        assert upsert.method == H.PATCH
        assoc_data, _, _, T_assoc_recieved = mthd(data)

        assert T_assoc_recieved == T_assoc
        event = self.check_event(upsert, assoc_data, data)
        assert len(event.children) == 0

        # NOTE: Delete one and try to recreate. This should raise an error 
        #       asking to force.
        uuid_assoc_deleted, *_ = uuid_assoc
        assoc_deleted = T_assoc.resolve_uuid(session, uuid_assoc_deleted)
        assoc_deleted.deleted = True
        session.add(assoc_deleted) 
        session.commit()

        uuid_target_name = f"uuid_{data.data.kind_target}"

        assert data.event is not None
        data.event = None
        with pytest.raises(HTTPException) as exc:
            mthd(data)

        err: HTTPException = exc.value
        assert err.status_code == 400
        assert err.detail == dict(
            kind_target=data.data.kind_target,
            kind_source=data.data.kind_source,
            kind_assoc=data.data.kind_assoc,
            uuid_target=getattr(assoc_deleted, uuid_target_name),
            uuid_source=data.data.uuid_source,
            uuid_assoc=list(assoc_deleted.uuid),
        )
        assert data.event is None

        # NOTE: Force create. This should remove the existing uuids and replace 
        #       them.
        upsert.force = True
        assoc_data, _, _, T_assoc_recieved = mthd(data)

        assocs_old = T_assoc.resolve(session, uuid_assoc)
        assert not len(assocs_old)

        q_assocs_new = select(T_assoc).join(T_target).join(T_source).where(
            T_source.uuid == uuid_source,
            T_target.uuid.in_(uuid_target),
        )
        assocs_new = tuple(session.execute(q_assocs_new).scalars())
        assert len(assocs_new) == len(uuid_target)
        assert all(not item.deleted for item in assocs_new)

        uuid_assoc_new = T_assoc.resolve_uuid(session, assocs_new)
        assert not len(uuid_assoc_new & uuid_assoc)

        # NOTE: Delete the new items. Create without force.
        upsert.force = False
        for item in assocs_new:
            session.delete(item)
        session.commit()

        upsert.force = False
        assoc_data, _, _, T_assoc_recieved = mthd(data)

        assocs_new = tuple(session.execute(q_assocs_new).scalars())
        assert len(assocs_new) == len(uuid_target)
        assert all(not item.deleted for item in assocs_new)

        # Restore.
        for item in assocs_new:
            session.delete(item)
        session.commit()

        session.add_all(assocs_init)
        session.commit()
