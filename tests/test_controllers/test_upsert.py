# =========================================================================== #
from http import HTTPMethod
from typing import Set, Type

import pytest
from fastapi import HTTPException
from sqlalchemy import Update, select
from sqlalchemy.orm import make_transient

# --------------------------------------------------------------------------- #
from app.controllers.access import H
from app.controllers.base import Data
from app.controllers.create import Create
from app.controllers.delete import AssocData, Delete
from app.models import Document, Grant, KindEvent, KindObject, Level, User
from app.schemas import AssignmentCreateSchema, GrantCreateSchema
from tests.test_controllers.test_delete_assoc import (
    CASES_ASSOCS,
    BaseTestAssoc,
    create_data_from_params,
)

TEST_DETAIL = "From `test_upsert.py`."
TEST_API_ORIGIN = "./tests/test_controllers/test_upsert.py"


@pytest.fixture
def upsert(delete: Delete) -> Create:
    res = Create(
        delete.session,  # type: ignore
        dict(uuid="000-000-000"),
        HTTPMethod.POST,
        detail=TEST_DETAIL,
        api_origin=TEST_API_ORIGIN,
        delete=delete,
        access=delete.access,
    )
    return res


CASES_ASSOCS_GRANTS_NOT_OWN = [
    (None, User, "99d-99d-99d", Document, {"petshoppe--"}, Grant, {"f-fff-fff-f"}),
    (
        None,
        Document,
        "petshoppe--",
        User,
        {"99d-99d-99d", "777-777-777"},
        Grant,
        {"f-fff-fff-f", "-=-=-=-=-=-"},
    ),
]


@pytest.mark.parametrize(
    "delete, T_source, uuid_source, T_target, uuid_target, T_assoc, uuid_assoc",
    CASES_ASSOCS_GRANTS_NOT_OWN + CASES_ASSOCS[2:4],
    indirect=["delete"],
)
class TestAssoc(BaseTestAssoc):
    grant_data = GrantCreateSchema(level=Level.own)
    assignment_data = AssignmentCreateSchema()

    def test_assoc(
        self,
        upsert: Create,
        T_source: Type,
        uuid_source: str,
        T_target: Type,
        uuid_target: Set[str],
        T_assoc: Type,
        uuid_assoc: Set[str],
    ) -> None:
        data = create_data_from_params(
            upsert, T_source, uuid_source, T_target, uuid_target, T_assoc, uuid_assoc
        )
        assert data.data.uuid_source == uuid_source
        assert data.data.uuid_target == uuid_target
        session = upsert.session
        assocs_init = T_assoc.resolve(session, uuid_assoc)
        _ = self.check_mthd(upsert, data)

        match data.data.kind_assoc:
            case KindObject.grant:
                upsert.create_data = self.grant_data
                assoc_args = upsert.create_grant
            case KindObject.assignment:
                upsert.create_data = self.assignment_data
                assoc_args = upsert.create_assignment
            case kind_assoc:
                raise AssertionError(f"Invalid `{kind_assoc=}`.")

        # NOTE: Run the method without force with undeleted items. These should
        #       all exist so the event should be empty.
        assert data.event is None
        assert upsert.force is False
        assert upsert.delete.force is False
        assert upsert.method == H.POST
        assert data.data.uuid_source == uuid_source
        assert data.data.uuid_target == uuid_target

        res = upsert.assoc(data, assoc_args)
        assert len(res) == 4
        assert isinstance(res[0], Data)
        assert isinstance(assoc_data := res[1], AssocData)
        assert len(assoc_data.uuid_assoc_active) == len(uuid_assoc)
        assert len(assoc_data.uuid_target_active) == len(uuid_target)
        assert not len(assoc_data.uuid_target_deleted)
        assert not len(assoc_data.uuid_assoc_deleted)
        assert res[3] == T_assoc
        match res[2]:
            case Delete() | Update():
                pass
            case bad:
                msg = f"`res[2]` has invalid type `{type(bad)}`."
                raise AssertionError(msg)

        event = self.check_event(upsert, assoc_data, data)
        assert len(event.children) == 0
        assert data.data.uuid_source == uuid_source
        assert data.data.uuid_target == uuid_target

        # NOTE: Try to post over existing.
        uuid_assoc_deleted, *_ = uuid_assoc
        assoc_deleted = T_assoc.resolve(session, uuid_assoc_deleted)
        assoc_deleted.deleted = True
        session.add(assoc_deleted)
        session.commit()

        # This is called with `assocs` as some output is bad.
        assert data.data.uuid_source == uuid_source
        assert data.data.uuid_target == uuid_target

        rm_assoc_data, *_ = upsert.delete.try_force(data)
        assert isinstance(rm_assoc_data, AssocData)
        assert len(rm_assoc_data.uuid_assoc_active) == len(uuid_assoc) - 1
        assert len(rm_assoc_data.uuid_target_active) == len(uuid_target) - 1
        assert len(rm_assoc_data.uuid_target_deleted) == 1
        assert len(rm_assoc_data.uuid_assoc_deleted) == 1

        data.event = None
        with pytest.raises(HTTPException) as exc:
            upsert.assoc(data, assoc_args)

        err: HTTPException = exc.value
        uuid_target_name = f"uuid_{data.data.kind_target.name}"
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
            ),
        )
        assert data.event is None

        # NOTE: Force create. This should remove the existing uuids and replace
        #       them. The event returned for create without upsert is wrapped
        #       in an additional layer that will point to the deletion event.
        upsert.force = True
        upsert.delete.force = True
        data, assoc_data, _, T_assoc_recieved = upsert.assoc(data, assoc_args)
        assert isinstance(data, Data)
        assert isinstance(assoc_data, AssocData)
        assert len(assoc_data.uuid_assoc_active) == len(uuid_assoc) - 1
        assert len(assoc_data.uuid_target_active) == len(uuid_target) - 1
        assert all(uuid in uuid_assoc for uuid in assoc_data.uuid_assoc_active)
        assert all(uuid in uuid_target for uuid in assoc_data.uuid_target_active)
        assert len(assoc_data.uuid_target_deleted) == 1
        assert len(assoc_data.uuid_assoc_deleted) == 1

        event = data.event
        assert event is not None
        assert len(event.children) == 2, str(event.children)
        event_del, event_create = event.children
        if event_del.kind == KindEvent.create:
            event_del, event_create = event_create, event_del

        assert event.kind.name == "upsert"
        assert len(event_del.children) == len(uuid_target), str(event_del.children)
        assert len(event_create.children) == len(uuid_target), str(
            event_create.children
        )
        self.check_event(upsert.delete, assoc_data, data, _event=event_del)
        self.check_event(upsert, assoc_data, data, _event=event_create)

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
        assert len(assocs_new) == len(assocs_init)
        assert all(not item.deleted for item in assocs_new)

        uuid_assoc_new = T_assoc.resolve_uuid(session, assocs_new)
        assert not len(uuid_assoc_new & uuid_assoc)

        # NOTE: Delete the new items. Create without force.
        for item in assocs_new:
            session.delete(item)
        session.commit()
        upsert.force = False
        upsert.delete.force = False

        _, assoc_data_final, _, T_assoc_recieved = upsert.assoc(data, assoc_args)
        assert not len(assoc_data_final.uuid_target_deleted)
        assert not len(assoc_data_final.uuid_assoc_deleted)
        assert not len(assoc_data_final.uuid_target_active)
        assert not len(assoc_data_final.uuid_assoc_active)

        assocs_new = tuple(session.execute(q_assocs_new).scalars())
        assert len(assocs_new) == len(uuid_target)
        assert all(not item.deleted for item in assocs_new)
        assert not len(T_assoc.resolve_uuid(session, assocs_new) & uuid_assoc)

        self.check_event(upsert, assoc_data_final, data)

        # Restore.
        for item in assocs_new:
            session.delete(item)
        session.commit()

        for item in assocs_init:
            make_transient(item)
            session.add(item)
        session.commit()
