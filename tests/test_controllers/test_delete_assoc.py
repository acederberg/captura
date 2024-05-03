# =========================================================================== #
from http import HTTPMethod
from typing import Any, Dict

import pytest
from sqlalchemy import func, select

# --------------------------------------------------------------------------- #
from app import util
from app.controllers.base import Data, ResolvedGrantDocument
from app.fields import Level
from app.models import Assignment, Collection, Document, User, uuids
from dummy import DummyProvider, GetPrimaryKwargs


@pytest.mark.parametrize("count", list(range(50)))
class TestSplitAssocs:
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
            force=True,
            method=HTTPMethod.POST,
        )

        data = dummy.get_data_assignment_document(n=250)
        assoc_data = delete.assoc(data)
        data.commit(delete.session)
