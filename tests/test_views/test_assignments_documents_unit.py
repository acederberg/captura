# =========================================================================== #
import secrets
from typing import Any, ClassVar, Dict, List, Set

import pytest
from pydantic import TypeAdapter
from sqlalchemy import delete, false, func, select

# --------------------------------------------------------------------------- #
from captura.controllers.access import H
from captura.err import (
    ErrAccessDocumentGrantBase,
    ErrAccessDocumentGrantInsufficient,
    ErrDetail,
    ErrObjMinSchema,
)
from captura.fields import KindObject, Level
from captura.models import Assignment, Collection, uuids
from captura.schemas import (
    AsOutput,
    AssignmentSchema,
    KindNesting,
    OutputWithEvents,
    mwargs,
)
from legere.requests import Requests
from simulatus import DummyProvider, GetPrimaryKwargs
from tests.conftest import COUNT
from tests.test_views.util import BaseEndpointTest


class CommonAssignmentsDocumentsTests(BaseEndpointTest):
    method: ClassVar[H]
    adapter = TypeAdapter(AsOutput[List[AssignmentSchema]])
    adapter_w_events = TypeAdapter(OutputWithEvents[List[AssignmentSchema]])

    @pytest.mark.asyncio
    async def test_deleted_410(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        (document,) = dummy.get_documents(1, GetPrimaryKwargs(deleted=True), other=True)

        fn = self.fn(requests)  # type: ignore
        res = await fn(
            document.uuid, uuid_collection={secrets.token_urlsafe(9) for _ in range(3)}
        )
        httperr = mwargs(
            ErrDetail[ErrObjMinSchema],
            detail=ErrObjMinSchema(
                msg=ErrObjMinSchema._msg_deleted,
                uuid_obj=document.uuid,
                kind_obj=KindObject.document,
            ),
        )
        if err := self.check_status(requests, res, 410, httperr):
            raise err

    @pytest.mark.asyncio
    async def test_not_found_404(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        uuid_document = secrets.token_urlsafe(9)
        uuid_collection = {secrets.token_urlsafe(9) for _ in range(3)}

        fn = self.fn(requests)
        res = await fn(uuid_document, uuid_collection=uuid_collection)
        httperr = mwargs(
            ErrDetail[ErrObjMinSchema],
            detail=ErrObjMinSchema(
                msg=ErrObjMinSchema._msg_dne,
                uuid_obj=uuid_document,
                kind_obj=KindObject.document,
            ),
        )
        if err := self.check_status(requests, res, 404, httperr):
            raise err

    @pytest.mark.asyncio
    async def test_unauthorized_401(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        assert requests.context.auth_exclude is False, "Auth should not be excluded."
        session, fn = dummy.session, self.fn(requests)

        (document,) = dummy.get_documents(1, level=Level.own)
        document.deleted = False
        session.add(document)
        session.commit()

        (collection,) = dummy.get_collections(1)

        requests.context.auth_exclude = True
        res = await fn(document.uuid, uuid_collection=[collection.uuid])
        requests.context.auth_exclude = False

        err_content = ErrDetail[str](detail="Token required.")
        if err := self.check_status(requests, res, 401, err_content):
            raise err

    @pytest.mark.asyncio
    async def test_forbidden_403(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        session, level = dummy.session, Level.view
        (document,) = dummy.get_documents(level=level, n=1)
        (collection,) = dummy.get_collections(1)
        session.merge(Assignment(uuid_document=document.uuid, uuid_collection=collection.uuid))
        session.commit()

        grant = dummy.get_document_grant(document)

        # NOTE: Only collection owners should be able to add to and remove
        #       from a collection. Reading however requires that the document
        #       be public or that the user has a grant of level view on the
        #       document.
        httperrargs: Dict[str, Any] = dict(
            uuid_user=dummy.user.uuid,
            uuid_document=document.uuid,
        )
        if self.method == H.GET:
            document.public = False
            session.delete(grant)
            httperrargs.update()
            httperr = mwargs(
                ErrDetail[ErrAccessDocumentGrantBase],
                detail=ErrAccessDocumentGrantBase(
                    msg=ErrAccessDocumentGrantBase._msg_dne,
                    level_grant_required=Level.view,
                    **httperrargs,
                ),
            )
        else:
            grant.deleted = False
            grant.level = Level.view
            session.add(grant)
            httperr = mwargs(
                ErrDetail[ErrAccessDocumentGrantInsufficient],
                detail=ErrAccessDocumentGrantInsufficient(
                    msg=ErrAccessDocumentGrantInsufficient._msg_insufficient,
                    uuid_grant=grant.uuid,
                    level_grant=grant.level,
                    level_grant_required=Level.own,
                    **httperrargs,
                ),
            )

        _ = session.add(document)
        assignment = session.scalar(
            select(Assignment).where(Assignment.uuid_document == document.uuid).limit(1)
        )
        assert assignment is not None

        assignment.deleted = False
        session.add(assignment)
        session.commit()

        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_collection=[assignment.uuid_collection])
        if err := self.check_status(requests, res, 403, httperr):
            raise err


# NOTE: The ownership of documents should work exactly as it does in grants.
#       Should find a way to reuse.
@pytest.mark.parametrize("count", [count for count in range(COUNT)])
class TestAssignmentsDocumentsRead(CommonAssignmentsDocumentsTests):
    method = H.GET

    def fn(self, requests: Requests):
        return requests.assignments.documents.read

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        session = dummy.session
        fn = self.fn(requests)

        (document,) = dummy.get_documents(level=Level.view, n=1)

        assignments = (
            Assignment(uuid_document=document.uuid, uuid_collection=cc.uuid)
            for cc in dummy.get_collections(10)
        )
        tuple(map(session.merge, assignments))
        session.commit()

        # NOTE: Providing no parameters should return all assignments.
        res = await fn(document.uuid)
        if err := self.check_status(requests, res, 200):
            raise err

        data = self.adapter.validate_json(res.content)

        q_assignment_uuids = (
            select(Assignment.uuid)
            .join(Collection)
            .where(
                Assignment.uuid_document == document.uuid,
                Assignment.deleted == false(),
                Collection.deleted == false(),
            )
        )
        # from captura import util
        # util.sql(dummy.session, q_assignment_uuids)
        assignment_uuids: Set[str]
        assignment_uuids = set(session.scalars(q_assignment_uuids))

        for assignment in data.data:
            assert assignment.uuid in assignment_uuids
            q = select(Assignment).where(Assignment.uuid == assignment.uuid)
            assignment_db = session.scalar(q.limit(1))

            assert assignment_db is not None
            assert not assignment_db.deleted

        assert len(data.data) == len(assignment_uuids) > 0

        # NOTE: Adding limit should limit the resources. Randomize should
        #       gaurentee different order.
        limit = 10
        ress = (
            await fn(document.uuid, limit=limit),
            await fn(document.uuid, limit=limit, randomize=True),
            await fn(document.uuid, limit=limit, randomize=True),
        )
        if err := self.check_status(requests, ress, 200):
            raise err

        dd = tuple(self.adapter.validate_json(res.content) for res in ress)
        data_ordered, data_rand1, data_rand2 = dd

        assert data_ordered.kind is not None
        assert data_rand1.kind is not None
        assert data_rand2.kind is not None
        assert (
            len(data_ordered.data) == len(data_rand1.data) == len(data_rand2.data) > 1
        )

        # NOTE: Because with n >= 6 entries, odds are 1/3 * 6! = 1/320 that this does not happen.
        if len(data_ordered.data) > 5:
            aa, bb, cc = (
                tuple(dd.uuid for dd in data.data)
                for data in (data_ordered, data_rand1, data_rand2)
            )
            assert aa != bb != cc


@pytest.mark.parametrize("count", [count for count in range(COUNT)])
class TestAssignmentsDocumentsDelete(CommonAssignmentsDocumentsTests):
    method = H.POST

    def fn(self, requests: Requests):
        return requests.assignments.documents.delete

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        session, fn = dummy.session, self.fn(requests)
        fn_read = requests.assignments.documents.read

        (document,) = dummy.get_documents(level=Level.own, n=1)
        collections = dummy.get_collections(10, other=None)
        uuid_collection = uuids(collections)
        uuid_collection_list = list(uuid_collection)
        n_collections = len(uuid_collection_list)
        assert len(collections)

        assignments = tuple(
            Assignment(uuid_document=document.uuid, uuid_collection=cc.uuid, deleted=False)
            for cc in collections
        )
        tuple(map(session.merge, assignments))
        session.commit()
        session.expire_all()

        n_created = session.scalar(
            q := select(func.count(Assignment.uuid)).where(
                Assignment.uuid_collection.in_([cc.uuid for cc in collections]),
                Assignment.uuid_document == document.uuid,
            )
        )
        assert n_created == n_collections

        # NOTE: Verify can read.
        res = await fn_read(document.uuid, uuid_collection=uuid_collection_list)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.assignment
        assert data.kind_nesting == KindNesting.array
        assert len(data.data) == n_collections
        assert set(dd.uuid_collection for dd in data.data) == uuid_collection

        # NOTE: Delete.
        res = await fn(document.uuid, uuid_collection=uuid_collection_list)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind == KindObject.assignment
        assert data.kind_nesting == KindNesting.array
        assert len(data.data) == n_collections
        assert set(dd.uuid_collection for dd in data.data) == uuid_collection

        assert len(data.events) == 1
        assert len(data.events[0].children) == n_collections

        # NOTE: Verify with db and try read.
        session.reset()
        for assignment in data.data:
            q = select(Assignment).where(Assignment.uuid == assignment.uuid)
            assignment_db = session.scalar(q.limit(1))
            assert assignment_db is not None
            assert assignment_db.deleted is True, "Assignment should be deleted."

        res = await fn(document.uuid, uuid_collection=uuid_collection_list)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind is None

        # NOTE: Indepotence.
        res = await fn(document.uuid, uuid_collection=uuid_collection_list)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is None
        assert len(data.events) == 1
        assert len(data.events[0].children) == 0

        # NOTE: Force.
        res = await fn(document.uuid, uuid_collection=uuid_collection_list, force=True)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind == KindObject.assignment
        assert len(data.data) == n_collections
        assert len(data.events) == 1
        assert len(data.events[0].children) == n_collections

        # NOTE: Verify with the database.
        session.reset()
        for assignment in data.data:
            q = select(Assignment).where(Assignment.uuid == assignment.uuid)
            assignment_db = session.scalar(q.limit(1))
            assert assignment_db is None


@pytest.mark.parametrize("count", [count for count in range(COUNT)])
class TestAssignmentsDocumentsCreate(CommonAssignmentsDocumentsTests):
    method = H.POST

    def fn(self, requests: Requests):
        return requests.assignments.documents.create

    @pytest.mark.asyncio
    async def test_success_200(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        session, fn = dummy.session, self.fn(requests)
        fn_read = requests.assignments.documents.read

        (document,) = dummy.get_documents(n=1, level=Level.own)

        # NOTE: Delete all assignments for this document.
        q = delete(Assignment).where(Assignment.uuid_document == document.uuid)
        session.execute(q)
        session.commit()

        collections = dummy.get_collections(other=None, n=10)
        uuid_collection_list = [cc.uuid for cc in collections]
        n_collections = len(uuid_collection_list)

        # uuid_collection = Collection.resolve_uuid(dummy.session, collections)
        # uuid_collection_list = list(uuid_collection)
        # assert (n_collections := len(uuid_collection)) > 1

        # NOTE: Assignments should not exist.
        res = await fn_read(document.uuid, uuid_collection=uuid_collection_list)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind is None

        # NOTE: Try create.
        res = await fn(document.uuid, uuid_collection=uuid_collection_list)
        if err := self.check_status(requests, res, 201):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is KindObject.assignment
        assert len(data.data) == n_collections
        assert len(data.events) == 1
        assert len(data.events[0].children) == n_collections

        # NOTE: db and read verify.
        session.reset()
        for assignment in data.data:
            q = select(Assignment).where(Assignment.uuid == assignment.uuid)
            assignment_db = session.scalar(q.limit(1))
            assert assignment_db is not None
            assert assignment_db.deleted is False

        res = await fn_read(document.uuid, uuid_collection=uuid_collection_list)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.assignment
        assert len(data.data) == n_collections

        # NOTE: Indempotent.
        res = await fn(document.uuid, uuid_collection=uuid_collection_list)
        if err := self.check_status(requests, res, 201):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is None

        # ------------------------------------------------------------------- #
        # NOTE: Force. Start by ensuring at least one assignment is deleted.
        #       First the endpoint should tell us to use force.
        fn_rm = requests.assignments.documents.delete
        uuid_collection_list_rm = uuid_collection_list[: n_collections - 1]
        n_collections_rm = len(uuid_collection_list_rm)

        res = await fn_rm(
            document.uuid,
            uuid_collection=uuid_collection_list_rm,
        )
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert n_collections_rm == len(data.data)
        uuids_b4 = set(aa.uuid for aa in data.data)

        # NOTE: Ensure that all but one were deleted.
        res = await fn_read(document.uuid, uuid_collection=uuid_collection_list_rm)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind is None

        res = await fn_read(document.uuid, uuid_collection=uuid_collection_list)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.assignment
        assert len(data.data) == 1

        # NOTE: Force create. Should recreate all.
        res = await fn(document.uuid, uuid_collection=uuid_collection_list)
        if err := self.check_status(requests, res, 400):
            raise err

        res = await fn(
            document.uuid,
            uuid_collection=uuid_collection_list,
            force=True,
        )
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind == KindObject.assignment
        assert len(data.data) == n_collections - 1  # bc all but one rmd
        assert len(data.events) == 1
        assert len(data.events[0].children) == 2

        # requests.context.console_handler.handle(
        #     request_handler_data=RequestHandlerData(
        #         response=res,
        #         data=data.model_dump(mode="json"),
        #     )
        # )
        print(
            set(
                (ee.uuid_obj, ee.kind_obj) for ee in data.events[0].children[0].children
            )
        )
        assert len(data.events[0].children[1].children) == n_collections - 1
        assert len(data.events[0].children[0].children) == n_collections - 1

        # NOTE: Verify with read.
        res = await fn_read(document.uuid, uuid_collection=uuid_collection_list)
        if err := self.check_status(requests, res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind == KindObject.assignment
        assert len(data.data) == n_collections

        uuids_after = set(aa.uuid for aa in data.data)
        assert not len(uuids_b4 & uuids_after)
