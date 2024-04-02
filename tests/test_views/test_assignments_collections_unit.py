# =========================================================================== #
import asyncio
import json
import secrets
from random import choice, randint
from typing import ClassVar, List, Set

import pytest
from pydantic import TypeAdapter
from sqlalchemy import delete, false, select, update

# --------------------------------------------------------------------------- #
from app import util
from app.controllers.access import H
from app.err import ErrAccessCollection, ErrDetail, ErrObjMinSchema
from app.fields import KindObject
from app.models import Assignment, Collection, Document
from app.schemas import (
    AsOutput,
    AssignmentSchema,
    GrantSchema,
    OutputWithEvents,
    mwargs,
)
from client.requests import Requests
from tests.dummy import DummyProvider, GetPrimaryKwargs
from tests.test_views.util import BaseEndpointTest


class CommonAssignmentsCollectionsTests(BaseEndpointTest):
    method: ClassVar[H]
    adapter = TypeAdapter(AsOutput[List[AssignmentSchema]])
    adapter_w_events = TypeAdapter(OutputWithEvents[List[AssignmentSchema]])

    @pytest.mark.asyncio
    async def test_deleted_410(self, dummy: DummyProvider, requests: Requests):
        collection, = dummy.get_collections(1, GetPrimaryKwargs(deleted=True))

        fn = self.fn(requests)
        res = await fn(collection.uuid, uuid_document=[secrets.token_urlsafe(9)])
        httperr = mwargs(
            ErrDetail[ErrObjMinSchema],
            detail=ErrObjMinSchema(
                msg=ErrObjMinSchema._msg_deleted,
                uuid_obj=collection.uuid,
                kind_obj=KindObject.collection,
            )
        )

        if err := self.check_status(requests, res, 410, httperr):
            raise err

    @pytest.mark.asyncio
    async def test_not_found_404(self, dummy: DummyProvider, requests: Requests):
        uuid_collection = secrets.token_urlsafe(9)
        uuid_document = {secrets.token_urlsafe(9) for _ in range(3)}

        fn = self.fn(requests)
        res = await fn(uuid_collection, uuid_document=uuid_document)
        httperr = mwargs(
            ErrDetail[ErrObjMinSchema],
            detail=ErrObjMinSchema(
                msg=ErrObjMinSchema._msg_dne,
                uuid_obj=uuid_collection,
                kind_obj=KindObject.collection,
            ),
        )
        if err := self.check_status(requests, res, 404, httperr):
            raise err

    @pytest.mark.asyncio
    async def test_unauthorized_401(self, dummy: DummyProvider, requests: Requests):
        assert requests.context.auth_exclude is False, "Auth should not be excluded."
        session, fn = dummy.session, self.fn(requests)

        (collection,) = dummy.get_user_collections()
        (document,) = dummy.get_collections(1)

        requests.context.auth_exclude = True
        res = await fn(collection.uuid, uuid_document=[document.uuid])
        requests.context.auth_exclude = False

        err_content = ErrDetail[str](detail="Token required.")
        if err := self.check_status(requests, res, 401, err_content):
            raise err

    @pytest.mark.asyncio
    async def test_forbidden_403(self, dummy: DummyProvider, requests: Requests):
        session = dummy.session
        user = dummy.user
        user_other = next(uwu for uwu in dummy.get_users(2) if uwu.uuid != user.uuid)
        collection, = dummy.get_user_collections(1)
        uuid_document = [secrets.token_urlsafe(9)]

        collection.id_user = user_other.id
        if self.method == H.GET:
            collection.public = False
            msg = ErrAccessCollection._msg_private
        else:
            msg = ErrAccessCollection._msg_modify

        session.add(collection)
        session.commit()


        fn = self.fn(requests)
        res = await fn(collection.uuid, uuid_document=uuid_document)
        httperr = mwargs(
            ErrDetail[ErrAccessCollection],
            detail=ErrAccessCollection(
                msg=msg,
                uuid_collection=collection.uuid,
                uuid_user_token=user.uuid,
            )
        )

        if err := self.check_status(requests, res, 403, httperr):
            raise err




class TestAssignmentsCollectionsRead(CommonAssignmentsCollectionsTests):
    method = H.GET

    def fn(self, requests: Requests):
        return requests.assignments.collections.read

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):
        session = dummy.session
        (collection,) = dummy.get_user_collections(1)
        assert not collection.deleted

        fn = self.fn(requests)

        # NOTE: Providing no parameters should return all assignments.
        res = await fn(collection.uuid)
        if err := self.check_status(requests, res, 200):
            raise err

        data = self.adapter.validate_json(res.content)

        assignment_uuids: Set[str]
        q = select(Assignment).join(Document).where(
            Assignment.id_collection == collection.id, 
            Assignment.deleted == false(),
            Document.deleted == false(),
        )
        assignments = tuple(session.scalars(q))
        assignment_uuids = Assignment.resolve_uuid(session, assignments)
        assert len(assignment_uuids) > 0

        for assignment in data.data:
            assert assignment.uuid in assignment_uuids
            q = select(Assignment).where(Assignment.uuid!=assignment.uuid)
            assignment_db = session.scalar(q.limit(1))
            assert assignment_db is not None
            assert not assignment_db.deleted

        assert len(data.data) == len(assignment_uuids)

        # NOTE: Adding limit should limit the resources. Randomize should
        #       gaurentee different order.
        limit = 10
        ress = await asyncio.gather(
            fn(collection.uuid, limit=limit),
            fn(collection.uuid, limit=limit, randomize=True),
            fn(collection.uuid, limit=limit, randomize=True),
        )
        if err := self.check_status(requests, ress, 200):
            raise err

        dd = tuple(self.adapter.validate_json(res.content) for res in ress)
        data_ordered, data_rand1, data_rand2 = dd

        assert len(data_ordered.data) == len(data_rand1.data) == len(data_rand2.data)
        if len(data_ordered.data) > 5:
            assert data_ordered.data != data_rand1.data != data_rand2.data

    @pytest.mark.asyncio
    async def test_success_200_filter_by_uuids(self, dummy: DummyProvider, requests: Requests):
        collection, = dummy.get_user_collections(1)
        fn = self.fn(requests)

        # NOTE: Read to get some document uuids for filtering.
        res = await fn(collection.uuid)
        if err := self.check_status(requests, res):
            raise err

        data_all = self.adapter.validate_json(res.content)
        assert data_all.kind == KindObject.assignment
        assert len(data_all.data) > 0

        uuid_documents_all: Set[str] = set(dd.uuid_document for dd in data_all.data)
        uuid_documents_all_list = list(uuid_documents_all)
        uuid_documents = {k for k in uuid_documents_all if randint(0,1)} 
        uuid_documents.add(choice(uuid_documents_all_list))
        n, n_total = len(uuid_documents), len(uuid_documents_all)

        # NOTE: Use all uuids and expect the same result randomized.
        res = await fn(collection.uuid, uuid_document=uuid_documents_all_list, randomize=True)
        if err := self.check_status(requests, res):
            raise err

        data_all_again = self.adapter.validate_json(res.content) 
        assert data_all_again.kind is not None
        assert len(data_all_again.data) == n_total

        # NOTE: Only tested when its likely that the data will not match.
        if n_total > 5:
            assert data_all.data != data_all_again.data

        # NOTE: Use subset
        res = await fn(collection.uuid, uuid_document=list(uuid_documents))
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind is not None
        assert len(data.data) == n




class TestAssignmentsCollectionsDelete(CommonAssignmentsCollectionsTests):
    method = H.DELETE

    def fn(self, requests: Requests):
        return requests.assignments.collections.delete

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):
        (collection,), session = dummy.get_user_collections(1), dummy.session
        documents = tuple(session.scalars(collection.q_select_documents()))
        uuid_document_list = list(dd.uuid for dd in documents)
        assert (n_documents := len(uuid_document_list)) > 0
        session.execute(
            update(Document)
            .values(deleted=False)
            .where(Document.uuid.in_(uuid_document_list))
        )
        session.commit()

        # NOTE: Verify read.
        fn_read = requests.assignments.collections.read
        res = await fn_read(collection.uuid, uuid_document=uuid_document_list)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.assignment
        assert len(data.data) == n_documents

        # NOTE: Deletion
        fn = self.fn(requests)
        res = await fn(collection.uuid, uuid_document=uuid_document_list)
        if err := self.check_status(requests, res):
            raise err

        data_read = self.adapter_w_events.validate_json(res.content)
        assert data_read.kind == KindObject.assignment
        assert len(data_read.data) == n_documents
        assert len(data_read.events) == 1
        assert len(data_read.events[0].children) == n_documents

        # NOTE: Verify with read and db.
        session.reset()
        for assignment in data.data:
            q = select(Assignment).where(Assignment.uuid==assignment.uuid)
            assignment_db = session.scalar(q.limit(1))

            assert assignment_db is not None
            assert assignment_db.deleted

        res = await fn_read(collection.uuid, uuid_document=uuid_document_list)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind is None

        # NOTE: Indempotent.
        res = await fn(collection.uuid, uuid_document=uuid_document_list)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is None
        assert len(data.events) == 1
        assert not len(data.events[0].children) 

        # NOTE: Force.
        res = await fn(collection.uuid, uuid_document=uuid_document_list, force=True)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is None
        assert len(data.data) == 0
        assert len(data.events) == 1

        session.reset()
        for assignment in data_read.data:
            q = select(Assignment).where(Assignment.uuid==assignment.uuid)
            assignment_db = session.scalar(q.limit(1))
            assert assignment_db is None








class TestAssignmentsCollectionsCreate(CommonAssignmentsCollectionsTests):
    method = H.POST

    def fn(self, requests: Requests):
        return requests.assignments.collections.create

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: DummyProvider, requests: Requests):

        session = dummy.session
        collection, = dummy.get_user_collections(1)
        documents = dummy.get_documents(9, GetPrimaryKwargs(deleted=False))
        uuid_document_list = list(dd.uuid for dd in documents)
        id_document_list = [dd.id for dd in documents]
        assert (n_documents := len(uuid_document_list)) > 1

        session.execute(
            delete(Assignment).where(Assignment.id_document.in_(id_document_list), 
                                     Assignment.id_collection == collection.id)

        )
        session.commit()

        # NOTE: Verify can read.
        fn_read = requests.assignments.collections.read
        res = await fn_read(collection.uuid, uuid_document=uuid_document_list)

        if err := self.check_status(requests, res):
            raise err


        data = self.adapter.validate_json(res.content)
        assert data.kind is None


        # NOTE: Try create.
        fn = self.fn(requests)
        res = await fn(collection.uuid, uuid_document=uuid_document_list)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind == KindObject.assignment
        assert len(data.data) == n_documents
        assert len(data.events) == 1
        assert len(data.events[0].children) == n_documents

        # NOTE: Verify with read and db
        res = await fn_read(collection.uuid, uuid_document=uuid_document_list)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.assignment
        assert len(data.data) == n_documents

        session.reset()
        for assignment in data.data:
            assignment_db = session.scalar(select(Assignment).where(Assignment.uuid == assignment.uuid).limit(1))
            assert assignment_db is not None
            assert not assignment_db.deleted

        # NOTE: Indempotent.
        res = await fn(collection.uuid, uuid_document=uuid_document_list)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is None
        assert not len(data.data)
        assert len(data.events) == 1
        assert not len(data.events[0].children)

        # ------------------------------------------------------------------- #
        # NOTE: Force. Start by deleting most.

        session.execute(
            update(Assignment).values(deleted=True).where(Assignment.id_document.in_(id_document_list[:n_documents-2]), 
                                     Assignment.id_collection == collection.id)
        )
        session.commit()

        res = await fn(collection.uuid, uuid_document=uuid_document_list)
        if err := self.check_status(requests, res, 400):
            raise err

        res = await fn(collection.uuid, uuid_document=uuid_document_list, force=True)
        if err := self.check_status(requests, res):
            raise err


