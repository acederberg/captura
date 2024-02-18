from http import HTTPMethod
from typing import Set, Type
from app.views.base import Data

import pytest
from app.auth import Auth, Token
from app.models import KindObject, Level, PendingFrom
from app.schemas import AssignmentCreateSchema, GrantCreateSchema
from app.views.access import H
from app.views.create import Upsert
from app.views.delete import AssocData, Delete
from fastapi import HTTPException
from sqlalchemy import select, Update
from sqlalchemy.orm import make_transient
from tests.test_controllers.test_delete import (
    CASES_ASSOCS,
    BaseTestAssoc,
    as_data,
    delete,
)

TEST_DETAIL = "From `test_upsert.py`."
TEST_API_ORIGIN = "./tests/test_controllers/test_upsert.py"


@pytest.fixture
def upsert(delete: Delete) -> Upsert:
    res = Upsert(
        delete.session,  # type: ignore
        dict(uuid="000-000-000"),
        HTTPMethod.POST,
        detail=TEST_DETAIL,
        api_origin=TEST_API_ORIGIN,
        delete=delete
    )
    return res


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
        _ = self.check_mthd(upsert, data)

        match data.data.kind_assoc:
            case KindObject.grant:
                print("isgrant")
                upsert.upsert_data = self.grant_data
                assoc_args = lambda vv: dict(**vv, pending_from=PendingFrom.granter)
            case KindObject.assignment:
                print("isassignment")
                upsert.upsert_data = self.assignment_data
                assoc_args = lambda vv: vv
            case kind_assoc:
                raise AssertionError(f"Invalid `{kind_assoc=}`.")

        # NOTE: Run the method without force with undeleted items. These should
        #       all exist so the event should be empty.
        assert data.event is None
        assert upsert.force is False
        assert upsert.delete.force is False
        assert upsert.method == H.POST

        upsert.assoc
        res = upsert.assoc(data, assoc_args)
        assert len(res) == 4
        assert isinstance(res[0], Data)
        assert isinstance(assoc_data := res[1], AssocData)
        assert res[3] == T_assoc
        match res[2]:
            case Delete() | Update():
                pass
            case bad:
                msg =f"`res[2]` has invalid type `{type(bad)}`." 
                raise AssertionError(msg)

        event = self.check_event(upsert, assoc_data, data)
        assert len(event.children) == 0

        # NOTE: Delete one and try to recreate. This should raise an error
        #       asking to force.
        uuid_assoc_deleted, *_ = uuid_assoc
        assoc_deleted = T_assoc.resolve(session, uuid_assoc_deleted)
        assoc_deleted.deleted = True
        session.add(assoc_deleted)
        session.commit()

        uuid_target_name = f"uuid_{data.data.kind_target.name}"

        assert data.event is not None
        data.event = None
        with pytest.raises(HTTPException) as exc:
            upsert.assoc(data, assoc_args)

        err: HTTPException = exc.value
        assert err.status_code == 400
        assert err.detail == dict(
            kind_source=data.data.kind_source.name,
            kind_assoc=data.data.kind_assoc.name,
            kind_target=data.data.kind_target.name,
            uuid_source=data.data.uuid_source,
            uuid_assoc=[assoc_deleted.uuid],
            uuid_target=[getattr(assoc_deleted, uuid_target_name)],
            msg=(
                "Some targets have existing assignments awaiting cleanup. "
                "Try this request again with `force=true` or make an "
                "equivalent `PUT` request."
            )
        )
        assert data.event is None

        # NOTE: Force create. This should remove the existing uuids and replace
        #       them.
        # upsert.method = H.PUT
        assoc_data, _, _, T_assoc_recieved = upsert.assoc(data, assoc_args, force=True)

        assocs_old = T_assoc.resolve(session, uuid_assoc)
        assert not len(assocs_old)

        q_assocs_new = (
            select(T_assoc)
            .join(T_target)
            .join(T_source)
            .where(
                T_source.uuid == uuid_source,
                T_target.uuid.in_(uuid_target),
            )
        )
        assocs_new = tuple(session.execute(q_assocs_new).scalars())
        assert len(assocs_new) == 1
        assert all(not item.deleted for item in assocs_new)

        uuid_assoc_new = T_assoc.resolve_uuid(session, assocs_new)
        assert not len(uuid_assoc_new & uuid_assoc)

        # NOTE: Delete the new items. Create without force.
        upsert.force = False
        for item in assocs_new:
            session.delete(item)
        session.commit()

        upsert.force = False
        assoc_data, _, _, T_assoc_recieved = upsert.assoc(data, assoc_args)

        assocs_new = tuple(session.execute(q_assocs_new).scalars())
        assert len(assocs_new) == len(uuid_target)
        assert all(not item.deleted for item in assocs_new)
        assert not len(T_assoc.resolve_uuid(session, assocs_new) & uuid_assoc)

        # Restore.
        for item in assocs_new:
            session.delete(item)
        session.commit()

        for item in assocs_init:
            print(item.uuid)
            make_transient(item)
            session.add(item)
            session.commit()
        session.commit()
