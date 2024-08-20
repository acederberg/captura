# =========================================================================== #
import asyncio
import json
from http import HTTPMethod
from typing import List

import httpx
import pytest
from sqlalchemy import and_, delete, select, update
from sqlalchemy.orm import Session, sessionmaker

# --------------------------------------------------------------------------- #
from captura import __version__, util
from captura.models import (
    AssocCollectionDocument,
    ChildrenCollection,
    ChildrenUser,
    Collection,
    KindEvent,
    KindObject,
    User,
)
from captura.schemas import AssignmentSchema, EventSchema
from legere.requests import AssignmentRequests, Requests

from . import util

# NOTE: The `requests` fixture must exist in module scope directly.
from .util import BaseTestViews

logger = util.u.get_logger(__name__)


class TestAssignmentView(BaseTestViews):
    T = AssignmentRequests

    @classmethod
    @util.checks_event
    def check_event(
        cls,
        response: httpx.Response,
        *,
        uuid_document: List[str] | None,
        uuid_assignment: List[str] | None,
        restore: bool = False,
        event: EventSchema | None = None,
        **overwrite,
    ) -> EventSchema:
        """One function for event checking.

        This will make tests more readable.
        """

        url = "/assignments/collections"
        request = response.request
        event = event or EventSchema.model_validate_json(response.content)
        expect_common = dict(
            api_version=__version__,
            uuid_user=util.DEFAULT_UUID,
            kind_obj=KindObject.assignment,
        )

        match request.method:
            case HTTPMethod.GET:
                msg = "`GET` should not return an `EventSchema`."
                raise AssertionError(msg)
            case HTTPMethod.POST:
                expect_common.update(
                    api_origin=f"POST {url}/<uuid>",
                    kind=KindEvent.create,
                    detail="Assignment created.",
                )
            case HTTPMethod.DELETE:
                expect_common.update(
                    api_origin=f"DELETE {url}/<uuid>",
                    kind=KindEvent.delete,
                    detail="Assignment deleted.",
                )
            case _:
                raise ValueError(f"Unexpected method `{request.method}`.")

        expect_common.update(overwrite)

        # NOTE: This is done here and not in the pattern match since these
        #       should have a similar structure.
        # NOTE: This response is returned when the database has an entry staged
        #       for deletion but it is restored. For `POST` requests it is
        #       included only in the child events hence the logic below.
        if not restore:
            util.event_compare(event, expect_common)
        elif request.method == "POST":
            util.event_compare(event, expect_common)
            expect_common.update(detail="Assignment restored.")
        else:
            expect_common.update(detail="Assignment restored.")
            util.event_compare(event, expect_common)
        assert event.kind_obj == KindObject.collection
        assert event.uuid_obj == util.DEFAULT_UUID_COLLECTION

        for item in event.children:
            util.event_compare(item, expect_common)
            assert len(item.children) == 1
            assert item.kind_obj == KindObject.document
            if uuid_document is not None:
                assert item.uuid_obj in uuid_document

            subitem, *_ = item.children
            util.event_compare(subitem, expect_common)
            assert len(subitem.children) == 0
            assert subitem.kind_obj == KindObject.assignment
            if uuid_assignment is not None:
                assert subitem.uuid_obj in uuid_assignment

        return event

    @classmethod
    def add_assocs(
        cls,
        sessionmaker: sessionmaker[Session],
        deleted=False,
    ) -> List[AssocCollectionDocument]:
        with sessionmaker() as session:
            user = User.if_exists(session, util.DEFAULT_UUID)
            collection = Collection.if_exists(session, util.DEFAULT_UUID_COLLECTION)
            session.execute(
                delete(AssocCollectionDocument).where(
                    AssocCollectionDocument.id_collection == collection.id
                )
            )
            session.commit()

            # Added refreshed assocs
            assocs = [
                AssocCollectionDocument(
                    id_collection=collection.id,
                    id_document=dd.id,
                    deleted=deleted,
                )
                for dd in user.documents.values()
            ]
            session.add_all(assocs)
            session.commit()
            return assocs

    @pytest.mark.asyncio
    async def test_read_assignment(
        self,
        requests: Requests,
        sessionmaker: sessionmaker[Session],
    ):
        assocs = self.add_assocs(sessionmaker)

        # Make sure that the collection has some assignments.
        res = await requests.collections.read(
            util.DEFAULT_UUID_COLLECTION,
            ChildrenCollection.documents,
        )
        if err := util.check_status(res):
            raise err

        result = res.json()
        assert isinstance(result, list)
        if len(result) != len(assocs):
            raise ValueError(
                "Expected the same number of documents for collection "
                f"`{util.DEFAULT_UUID_COLLECTION}` as inserted associations."
            )

        # Make sure the number of assignments read is correct.
        res = await requests.assignments.read(util.DEFAULT_UUID_COLLECTION)
        if err := util.check_status(res):
            raise err

        result = res.json()
        assert isinstance(result, list)
        assign = list(AssignmentSchema.model_validate(item) for item in result)
        if len(assign) != len(assocs):
            raise ValueError(
                "Expected the same number of documents for collection "
                f"`{util.DEFAULT_UUID_COLLECTION}` as documents from `GET "
                "/collections/<uuid>/collections`."
            )

    @pytest.mark.asyncio
    async def test_get_assignment_deleted(
        self,
        requests: Requests,
        sessionmaker: sessionmaker[Session],
    ):
        # Verify that assignments staged for deletion cannot be read.
        self.add_assocs(sessionmaker, deleted=True)
        res = await requests.assignments.read(util.DEFAULT_UUID_COLLECTION)
        if err := util.check_status(res, 200):
            raise err

        result = res.json()
        assert isinstance(result, list)
        if len(result):
            msg = "Expected no results for assignments staged for deletion."
            raise AssertionError(msg)

        # Verify that the collection does not get documents for assignments
        # staged for deletion.
        res = await requests.collections.read(
            util.DEFAULT_UUID_COLLECTION,
            ChildrenCollection.documents,
        )
        if err := util.check_status(res, 200):
            raise err
        elif not isinstance(result := res.json(), list):
            raise AssertionError("Result should be a dict.")
        elif len(result):
            msg = "Expected no results for assignments staged for deletion."
            msg += f"Got `{json.dumps(result)}`."
            raise AssertionError(msg)

    @pytest.mark.asyncio
    async def test_post_assignment(
        self, requests: Requests, sessionmaker: sessionmaker[Session]
    ):
        with sessionmaker() as session:
            conds = and_(
                AssocCollectionDocument.id_collection == Collection.id,
                Collection.uuid == util.DEFAULT_UUID_COLLECTION,
            )
            session.execute(delete(AssocCollectionDocument).where(conds))
            session.commit()

        # There should not be documents or assignments
        res_docs_coll, res_docs_users, res_assign = await asyncio.gather(
            requests.collections.read(
                util.DEFAULT_UUID_COLLECTION, ChildrenCollection.documents
            ),
            requests.users.read(util.DEFAULT_UUID, ChildrenUser.documents),
            requests.assignments.read(util.DEFAULT_UUID_COLLECTION),
        )
        if err := util.check_status(res_docs_coll, 200):
            raise err
        results = res_docs_coll.json()
        assert isinstance(results, list)  # TODO: Fix return types.
        assert not len(results), "Expected no documents for collection."

        if err := util.check_status(res_assign, 200):
            raise err
        results = res_assign.json()
        assert isinstance(results, list)
        assert not len(results), "Expected no assingment for collection."

        if err := util.check_status(res_docs_users, 200):
            raise err
        results = res_docs_users.json()
        assert isinstance(results, dict)
        assert len(results), "Expected documents for user."
        uuid_document = list(results.keys())

        # Post new assignments, assign all user documents to this user.
        res = await requests.assignments.create(
            util.DEFAULT_UUID_COLLECTION,
            uuid_document,
        )
        if err := util.check_status(res, 201):
            raise err
        event, err = self.check_event(
            res,
            uuid_document=uuid_document,
            uuid_assignment=None,
        )
        if err is not None:
            raise err

        # Read assignment UUIDs to check events.
        with sessionmaker() as session:
            q = select(AssocCollectionDocument.uuid).where(conds)
            uuid_assignment: List[str] = list(session.execute(q).scalars())

        if len(uuid_assignment) != len(uuid_document):
            raise AssertionError(
                "There should  be an equal number of assignments and documents"
                f" for this collection `{len(uuid_document)=}` and "
                f"`{len(uuid_assignment)=}`."
            )

        check_event_arg = dict(
            uuid_document=uuid_document, uuid_assignment=uuid_assignment
        )
        event, err = self.check_event(res, **check_event_arg)
        if err is not None:
            raise err
        assert len(event.children) == len(
            uuid_document
        ), "Expected an event for event document."

        # Verify reads, indempotent
        ress = await asyncio.gather(
            requests.assignments.create(util.DEFAULT_UUID_COLLECTION, uuid_document),
            requests.assignments.read(util.DEFAULT_UUID_COLLECTION),
            requests.collections.read(
                util.DEFAULT_UUID_COLLECTION,
                ChildrenCollection.documents,
            ),
        )
        errs = (e for rr in ress if (e := util.check_status(rr)) is not None)
        if err := next(errs, None):
            raise err

        res, res_assign, res_collection = ress
        assert len(res_assign.json()) == len(uuid_document)
        assert set(item["uuid"] for item in res_collection.json()) == set(uuid_document)

        event, err = self.check_event(res, **check_event_arg)
        if err is not None:
            raise err
        assert len(event.children) == 0

        # Verify reactivates those staged for deletion.
        with sessionmaker() as session:
            session.execute(update(AssocCollectionDocument).values(deleted=True))
            session.commit()
        res = await requests.assignments.create(
            util.DEFAULT_UUID_COLLECTION,
            uuid_document,
        )
        if err := util.check_status(res, 201):
            raise err

        event, err = self.check_event(res, **check_event_arg, restore=True)
        if err is not None:
            raise err
        assert len(event.children) == len(uuid_document)

    @pytest.mark.asyncio
    async def test_delete_assignment(
        self,
        requests: Requests,
        sessionmaker: sessionmaker[Session],
    ):
        # Create and read assignments.
        assocs = self.add_assocs(sessionmaker, deleted=False)
        res = await requests.assignments.read(util.DEFAULT_UUID_COLLECTION)
        if err := util.check_status(res, 200):
            raise err

        assignments = list(AssignmentSchema.model_validate(item) for item in res.json())
        assert len(assignments) == len(assocs)

        uuid_document: List[str]
        uuid_assignment: List[str]
        _ = zip(*((assign.uuid_document, assign.uuid) for assign in assignments))
        uuid_document, uuid_assignment = (list(v) for v in _)
        assert uuid_document and uuid_assignment

        # Delete assignments and verify events.
        res = await requests.assignments.delete(
            util.DEFAULT_UUID_COLLECTION, uuid_document, False
        )
        if err := util.check_status(res, 200):
            raise err

        event, err = self.check_event(
            res, uuid_document=uuid_document, uuid_assignment=uuid_assignment
        )
        if err is not None:
            raise err
        assert len(event.children) == (n := len(uuid_document))

        # indempotent
        res, res_assign, res_collection = await asyncio.gather(
            requests.assignments.delete(
                util.DEFAULT_UUID_COLLECTION,
                uuid_document,
            ),
            requests.assignments.read(util.DEFAULT_UUID_COLLECTION),
            requests.collections.read(
                util.DEFAULT_UUID_COLLECTION, ChildrenCollection.documents
            ),
        )
        if err := util.check_status(res):
            raise err

        event = EventSchema.model_validate_json(res.content)
        event, err = self.check_event(
            res, uuid_document=uuid_document, uuid_assignment=uuid_assignment
        )
        if err is not None:
            raise err
        assert len(event.children) == 0

        # Verify assignments cannot be read.
        if err := util.check_status(res_assign, 200):
            raise err

        assert not len(res_assign.json())

        if err := util.check_status(res_collection, 200):
            raise err

        assert not len(res_collection.json())

        # Restore assignments
        res = await requests.assignments.delete(
            util.DEFAULT_UUID_COLLECTION, uuid_document, restore=True
        )
        if err := util.check_status(res, 200):
            raise err

        event, err = self.check_event(
            res,
            uuid_document=uuid_document,
            uuid_assignment=uuid_assignment,
            restore=True,
        )
        assert len(event.children) == len(uuid_document)

        if err is not None:
            raise err
        assert len(event.children) == n

        # BONUS: Verify that documents and assignments can be read.
        res_collection, res_assign = await asyncio.gather(
            requests.collections.read(
                util.DEFAULT_UUID_COLLECTION,
                ChildrenCollection.documents,
            ),
            requests.assignments.read(util.DEFAULT_UUID_COLLECTION),
        )

        if err := util.check_status(res_collection, 200):
            raise err
        elif err := util.check_status(res_assign, 200):
            raise err

        assert len(res_collection.json()) == n
        assert len(res_collection.json()) == n

    def test_assignment_restore_from_event(self, requests: Requests):
        # Read user and their docs
        ...
