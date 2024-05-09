# =========================================================================== #
from http import HTTPMethod
from typing import Any, Dict

import pytest
from fastapi import HTTPException
from sqlalchemy import false, func, select, true

# --------------------------------------------------------------------------- #
from app import util
from app.controllers.base import Data, ResolvedGrantDocument
from app.err import ErrAssocRequestMustForce
from app.fields import Level
from app.models import Assignment, Collection, Document, Grant, User, uuids
from app.schemas import GrantCreateSchema
from dummy import DummyProvider, GetPrimaryKwargs
from tests.conftest import COUNT


@pytest.mark.parametrize("count", list(range(COUNT)))
class TestDelete:
    def test_split_assocs(self, dummy: DummyProvider, count: int):
        delete = dummy.delete(
            api_origin="TestSplitAssocs:test_split_assocs",
            force=False,
        )
        # NOTE: Start with mixed assoc deletion state. All collections are
        #       active.
        data = dummy.get_data_assignment_document(n=250)
        assert all(not item.deleted for item in data.data.collections)

        assocs_data, model_assoc = delete.split_assocs(data)
        assert model_assoc == Assignment

        assoc: Assignment
        uuid_target_deleted = set()
        for uuid_assoc in assocs_data.uuid_assoc_deleted:
            assert (
                assoc := data.data.assoc.get(uuid_assoc)
            ) is not None, "All assocs should be in data."
            assert assoc.deleted is True
            assert assoc.id_document == data.data.document.id
            uuid_target_deleted.add(assoc.uuid_collection)

        uuid_target_active = set()
        for uuid_assoc in assocs_data.uuid_target_active:
            assert (assoc := data.data.assoc.get(uuid_assoc)) is not None
            assert assoc.deleted is False
            uuid_target_active.add(assoc.uuid_collection)

        for uuid_target in assocs_data.uuid_target_none:
            assert uuid_target not in data.data.assoc
            assert uuid_target not in assocs_data.uuid_target_deleted
            assert uuid_target not in assocs_data.uuid_target_active

            q_count = (
                select(func.count(Assignment.uuid))
                .join(Collection)
                .where(
                    Assignment.id_document == data.data.document.id,
                    Collection.uuid == uuid_target,
                )
            )
            count_for_uuid = dummy.session.scalar(q_count)
            assert count_for_uuid is None or not count_for_uuid

        # NOTE: Now use only targets without assocs as specified above.
        assocs_data_init = assocs_data
        data = dummy.get_data_assignment_document(
            dict(
                get_primary_kwargs=GetPrimaryKwargs(
                    uuids=assocs_data_init.uuid_target_none
                ),
                order_by_document_count=False,
            ),
            n=250,
            document=data.data.document,
        )
        assert (
            not data.data.assoc
        ), f"None of the provided collections should assocs for document `{data.data.document.uuid}`"
        assert uuids(data.data.collections) == assocs_data_init.uuid_target_none

        assocs_data, model_assoc = delete.split_assocs(data)
        assert model_assoc == Assignment
        assert not len(assocs_data.uuid_assoc_active)
        assert not len(assocs_data.uuid_target_active)
        assert not len(assocs_data.uuid_target_deleted)
        assert not len(assocs_data.uuid_target_deleted)
        assert len(assocs_data.uuid_target_none) == len(data.data.collections)
        assert not len(assocs_data.uuid_assoc_none)

        # NOTE: only active targets.
        data = dummy.get_data_assignment_document(
            dict(
                get_primary_kwargs=GetPrimaryKwargs(
                    uuids=assocs_data_init.uuid_target_active,
                    allow_empty=True,  # NOTE: required otherwise regen.
                ),
                order_by_document_count=False,
            ),
            n=250,
            document=data.data.document,
        )
        assert uuids(data.data.collections) == assocs_data_init.uuid_target_active

        assocs_data, model_assoc = delete.split_assocs(data)
        assert model_assoc == Assignment
        assert (
            len(data.data.assoc)
            == len(data.data.target)
            == len(assocs_data.uuid_target_active)
        )
        assert (
            set(aa.uuid for aa in data.data.assoc.values())
            == assocs_data.uuid_assoc_active
        )
        assert not len(assocs_data.uuid_target_deleted)
        assert not len(assocs_data.uuid_assoc_deleted)
        assert not len(assocs_data.uuid_target_none)
        assert not len(assocs_data.uuid_assoc_none)

        # NOTE: Now only inactive target.
        data = dummy.get_data_assignment_document(
            dict(
                get_primary_kwargs=GetPrimaryKwargs(
                    uuids=assocs_data_init.uuid_target_deleted,
                    allow_empty=True,
                ),
                order_by_document_count=False,
            ),
            n=250,
            document=data.data.document,
        )
        assert uuids(data.data.target) == assocs_data_init.uuid_target_deleted

        assoc_data, model_assoc = delete.split_assocs(data)
        assert model_assoc == Assignment
        assert assoc_data.uuid_target_deleted == assocs_data_init.uuid_target_deleted

    def test_assoc(self, dummy: DummyProvider, count: int):
        delete = dummy.delete(
            api_origin="TestSplitAssocs.test_assoc",
            force=False,
            method=HTTPMethod.POST,
        )

        # NOTE: Without force.
        data = dummy.get_data_assignment_document(n=250)
        _ = delete.assoc(data)
        assert data.event is not None
        data.commit(delete.session)

        # NOTE: Verify that these documents have moved into deleted state.
        session = dummy.session
        q = select(func.count(Assignment.uuid))
        q = q.where(Assignment.uuid.in_(data.data.uuid_assignments))

        n_assignments = len(data.data.uuid_assignments)

        q_assignments_deleted = q.where(Assignment.deleted == true())
        q_assignments_active = q.where(Assignment.deleted == false())

        n_assignments_deleted = session.scalar(q_assignments_deleted)
        n_assignments_active = session.scalar(q_assignments_active)

        assert (
            n_assignments_active is not None
            and n_assignments_deleted is not None
            and n_assignments_active == 0
            and n_assignments_deleted == n_assignments
        )

        # NOTE: Now with force.
        delete.force = True
        _ = delete.assoc(data)
        assert data.event is not None
        data.commit(delete.session)

        # NOTE: Verify that these documents have been truely deleted.
        n_assignments_deleted = session.scalar(q_assignments_deleted)
        n_assignments_active = session.scalar(q_assignments_active)
        assert (
            n_assignments_active is not None
            and n_assignments_deleted is not None
            and n_assignments_active == 0 == n_assignments_deleted
        )


class TestCreate:
    @pytest.mark.parametrize("count", list(range(COUNT)))
    def test_grant_document(self, dummy: DummyProvider, count: int):
        create = dummy.create(
            api_origin="TestSplitAssocs.test_assoc",
            force=False,
            method=HTTPMethod.POST,
        )
        create.create_data = GrantCreateSchema(level=Level.modify)
        data = dummy.get_data_grant_document(
            n=10,
            get_kwargs_users=dict(other=True),
        )
        session = dummy.session

        # NOTE: Clear all existing intially.
        create.delete.force = True
        create.delete.grant_document(data)
        data.commit(session)

        create.delete.force = False
        assert data.event

        q = (
            select(func.count(Grant.uuid))
            .join(User)
            .join(Document)
            .where(
                User.uuid.in_(data.data.uuid_users),
                Document.id == data.data.document.id,
            )
        )
        assert session.scalar(q) == 0

        # NOTE: Create all.
        data_final = create.grant_document(data)
        session.add_all(tuple(data_final.data.grants.values()))
        data_final.commit(session)

        n_users = len(data_final.data.users)
        assert len(data_final.data.grants) == n_users
        assert len(data_final.data.uuid_grants) == n_users
        assert isinstance(data_final, Data)
        assert isinstance(data_final.data, ResolvedGrantDocument)
        assert data_final.event is not None
        assert session.scalar(q.where(Grant.deleted == false())) == n_users

        # NOTE: Indempotent.
        data_indem = create.grant_document(data_final)
        assert len(data_indem.data.grants) == 0
        assert len(data_indem.data.users) == 0

        # NOTE: Move into deleted state.
        assert create.delete.force is False
        data_rm = data_final.model_copy()
        data_rm.event = None
        create.delete.grant_document(data_rm)
        data_rm.commit(session)

        assert isinstance(data_rm, Data)
        assert isinstance(data_rm.data, ResolvedGrantDocument)
        assert data_rm.event is not None

        assert session.scalar(q.where(Grant.deleted == false())) == 0
        assert session.scalar(q.where(Grant.deleted == true())) == n_users

        # NOTE: Should fail without force.
        with pytest.raises(HTTPException) as err:
            create.grant_document(data_rm)

        print(err.value.detail)
        assert ErrAssocRequestMustForce.model_validate(
            err.value.detail
        ) == ErrAssocRequestMustForce(
            msg=ErrAssocRequestMustForce._msg_force,
            kind_target=data_rm.data.kind_target,
            kind_source=data_rm.data.kind_source,
            kind_assoc=data_rm.data.kind_assoc,
            uuid_target=data_rm.data.uuid_users,
            uuid_source=data_rm.data.uuid_document,
            uuid_assoc=data_rm.data.uuid_grants,
        )

        # NOTE: Recreate using force.
        create.force = True
        create.delete.force = True

        data_force = create.grant_document(data_rm)
        assert len(data_force.data.grants) == n_users
        assert not len(
            uuids(data_force.data.grants) & uuids(data.data.grants)
        ), "All grants should have been replaced."
        session.add_all(data_force.data.grants.values())
        data_force.commit(session)

        assert session.scalar(q) == n_users
        assert session.scalar(q.where(Grant.deleted == false())) == n_users
        assert session.scalar(q.where(Grant.deleted == true())) == 0
