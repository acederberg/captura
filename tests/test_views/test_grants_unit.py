import abc
import secrets
from random import random
from typing import Any, AsyncGenerator, Callable, ClassVar, Generator, List

import httpx
import pytest
import pytest_asyncio
from app.auth import Auth
from app.config import MySqlConfig
from app.fields import KindObject, Level, LevelStr, PendingFrom, PendingFromStr
from app.models import Document, Grant, User
from app.schemas import (AsOutput, EventSchema, GrantSchema, KindNesting,
                         KindSchema, OutputWithEvents)
from client.handlers import CONSOLE
from client.requests import Requests
from fastapi import FastAPI
from pydantic import TypeAdapter
from sqlalchemy import Tuple, false, func, literal_column, select, true
from sqlalchemy.orm import Session
from tests.config import PytestConfig
from tests.conftest import PytestClientConfig
from tests.dummy import Dummy
from tests.test_views.util import check_status

N_CASES: int = 1

# Keeps manual assets out and bypasses reloading of other tables.
@pytest.fixture(scope="session")
def sessionmaker_dummy(config: PytestConfig):
    kwargs_host = config.mysql.host.model_dump()
    kwargs_host["database"]
    MySqlConfig(host=MySqlHostConfig.model_validate(kwargs_host))




class BaseEndpointTest(abc.ABC):
    """Use this template to save some time:

    .. code:: python

        async def test_unauthorized_401(self, dummy: Dummy, requests: Requests):
            "Test unauthorized access."
            ...

        async def test_not_found_404(self, dummy: Dummy, requests: Requests):
            "Test not found response."
            ...

        async def test_deleted_410(self, dummy: Dummy, requests: Requests):
            "Test deleted object"
            ...
    """

    adapter: ClassVar[TypeAdapter]


    @pytest.fixture(scope="class")
    def dummy(self, sessionmaker_dummy, auth: Auth) -> Generator[Dummy, None, None]:
        with sessionmaker_dummy() as session:
            yield Dummy(auth, session, use_existing=True)

    @pytest_asyncio.fixture(scope="function")
    async def requests(
        self,
        app: FastAPI | None,
        dummy: Dummy,
        client_config: PytestClientConfig,
        async_client: httpx.AsyncClient,
    ) -> AsyncGenerator[Requests, Any]:
        async with httpx.AsyncClient(app=app) as client:
            yield dummy.requests(client_config, client)

    # ----------------------------------------------------------------------- #
    # Errors

    @abc.abstractmethod
    async def test_unauthorized_401(self, dummy: Dummy, requests: Requests):
        "Test unauthorized access."
        ...

    @abc.abstractmethod
    async def test_not_found_404(self, dummy: Dummy, requests: Requests):
        "Test not found response."
        ...

    @abc.abstractmethod
    async def test_deleted_410(self, dummy: Dummy, requests: Requests):
        "Test deleted object"
        ...


    def document_user_uuids(self, dummy: Dummy, document: Document, limit: int | None = None, **kwargs) -> List[str]:
        q_users = document.q_select_users(**kwargs).where(Grant.level < Level.own).order_by(func.random()).limit(limit or 10)
        users = tuple(dummy.session.scalars(q_users))
        return list(User.resolve_uuid(dummy.session, users))

# =========================================================================== #


class CommonDocumentGrantsTests(BaseEndpointTest):
    adapter = TypeAdapter(AsOutput[List[GrantSchema]])
    adapter_w_events = TypeAdapter(OutputWithEvents[List[GrantSchema]])

    # ----------------------------------------------------------------------- #
    # Errors
    # NOTE: These should apply to all endpoints.;

    @pytest.mark.asyncio
    async def test_unauthorized_401(
        self,
        dummy: Dummy,
        requests: Requests,
    ):
        "Test unauthorized access."

    @pytest.mark.asyncio
    async def test_forbidden_403_insufficient(
        self,
        dummy: Dummy,
        requests: Requests,
    ):
        "Test cannot access when not an owner."
        document = dummy.get_document(Level.modify)
        assert not document.deleted, "Document should not be deleted."

        grant = dummy.get_grant(document)
        assert not grant.deleted, "Grant should not be deleted."
        assert not grant.pending, "Grant should not be pending."
        grant.level = Level.modify

        session = dummy.session
        session.add(grant)
        session.commit()

        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=[dummy.user.uuid])
        if err := check_status(res, 403):
            raise err

    @pytest.mark.asyncio
    async def test_forbidden_403_pending(
        self,
        dummy: Dummy,
        requests: Requests,
    ):
        "Test cannot use when ownership is pending."
        kwargs= dict(pending=True, exclude_pending=False)
        document = dummy.get_document(Level.modify, **kwargs)
        assert not document.deleted, "Document should not be deleted."

        grant = dummy.get_grant(document, **kwargs)
        assert not grant.deleted, "Grant should not be deleted."
        assert grant.pending, "Grant should be pending."

        grant.level = Level.modify
        session = dummy.session
        session.add(grant)
        session.commit()

        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=[dummy.user.uuid])
        if err := check_status(res, 403):
            raise err


    @pytest.mark.asyncio
    async def test_not_found_404(
        self,
        dummy: Dummy,
        requests: Requests,
    ):
        "Test not found response with bad document uuid."
        fn = self.fn(requests)
        res = await fn(secrets.token_urlsafe(9), uuid_user=[dummy.user.uuid])
        if err := check_status(res, 404):
            raise err

    @pytest.mark.asyncio
    async def test_410_deleted_grant(
        self,
        dummy: Dummy,
        requests: Requests,
    ):
        "Test cannot use grant is deleted."
        kwargs = dict(exclude_pending=False, exclude_deleted=False)
        document = dummy.get_document(
            Level.own, **kwargs
        )
        assert not document.deleted, "Document should not be deleted."

        # NOTE: Deletedness should supercede pendingness.
        grant = dummy.get_grant(document, **kwargs)
        grant.deleted = True
        
        session = dummy.session
        session.add(grant)
        session.commit()

        assert grant.deleted, "Grant should be deleted."
        assert grant.level == Level.own, "Grant level should be `own`."

        # session = dummy.session
        # session.add(grant)
        # session.commit()

        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=[dummy.user.uuid])
        if err := check_status(res, 410):
            raise err

    @pytest.mark.asyncio
    async def test_deleted_410(
        self,
        dummy: Dummy,
        requests: Requests,
    ):
        "Test deleted document"

        # NOTE: Select deleted documents with undeleted grants (not likely to 
        #       happen but probably worth testing incase deletion is broken).
        #       `exclude_deleted` is `True` in `get_grant` since excluded 
        #       documents are deleted.
        document = dummy.get_document(Level.view, deleted=True)
        assert document.deleted, "Document should be deleted."

        grant = dummy.get_grant(document, exclude_deleted=False)
        grant.deleted = False
        grant.pending = False

        session = dummy.session
        session.add(grant)
        session.commit()

        assert grant.deleted is False, "Grant should not be deleted."
        assert grant.pending is False, "Grant should not be pending."

        uuid_user = self.document_user_uuids(dummy, document)

        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=uuid_user)
        if err := check_status(res, 410):
            raise err




# NOTE: Test classes will be per endpoint. They will be parameterized with many
#       dummies. I found it helpful to look directly at the documentation to
#       come up with tests. The goal here is to test at a very fine scale.
class TestDocumentGrantsRead(CommonDocumentGrantsTests):

    def fn(self, requests: Requests):
        return requests.grants.documents.read
    # ----------------------------------------------------------------------- #
    # Features

    def check_success(
        self,
        dummy: Dummy,
        res: httpx.Response,
        *,
        pending: bool = False,
        level: Level | None = None,
        allow_empty: bool = False,
    ) -> AsOutput[List[GrantSchema]]:
        if err := check_status(res, 200):
            raise err

        data: AsOutput[List[GrantSchema]]
        data = self.adapter.validate_json(res.content)

        if allow_empty and data.kind == None:
            return data

        assert data.kind == KindObject.grant
        assert data.kind_nesting == KindNesting.array

        # NOTE: Does not serve pending grants unless specified. Never serves
        #       deleted grants.
        for item in data.data:
            _item_loaded = dummy.session.get(Grant, item.uuid)
            assert _item_loaded is not None
            assert not _item_loaded.deleted, "Item should not be deleted."

            item_loaded = GrantSchema.model_validate(_item_loaded)
            assert item.pending is pending
            assert item_loaded.pending is pending

            if level is None:
                continue

            assert item.level.value >= level.value

        return data

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: Dummy, requests: Requests):
        "Test a successful response."

        fn = self.fn(requests)
        document = dummy.get_document(Level.own)
        assert not document.deleted

        grant = dummy.get_grant(document)
        assert grant.pending is False, "Grant should not be pending."
        assert grant.deleted is False, "Grant should not be deleted."
        # grant.deleted = False
        # grant.pending = False
        session = dummy.session
        session.add(grant)
        session.commit()


        res = await fn(document.uuid)
        self.check_success(dummy, res, pending=False)

    @pytest.mark.asyncio
    async def test_success_200_pending(self, dummy: Dummy, requests: Requests):
        "Test the pending query parameter."

        fn = self.fn(requests)
        document = dummy.get_document(Level.own, exclude_pending=True)

        res = await fn(document.uuid, pending=True)
        self.check_success(dummy, res, pending=True)

    @pytest.mark.asyncio
    async def test_success_200_pending_from(self, dummy: Dummy, requests: Requests):
        "Test the pending_from query parameter."

        # NOTE: Should return nothing when `create` and `pending`. Want mix of
        #       user ids that are pending and not.
        fn = self.fn(requests)
        document = dummy.get_document(Level.own, pending_from=PendingFrom.created)
        grant = dummy.get_grant(document)

        assert grant.deleted is False
        assert grant.pending is False


        # NOTE: Check against created. Created is never pending.
        user_uuids = [dummy.user.uuid]
        res = await fn(document.uuid, uuid_user=user_uuids, pending_from=PendingFromStr.created)

        data = self.check_success(dummy, res)
        assert len(data.data) == 1
        grant, = data.data
        assert grant.pending_from == PendingFrom.created

        # No results expected.
        res = await fn(document.uuid, uuid_user=user_uuids, pending_from=PendingFromStr.created, pending=True)
        if err := check_status(res):
            raise err

        data = self.adapter.validate_json(res.content)
        assert data.kind is None

        # NOTE: Check against granter
        user_uuids = self.document_user_uuids(dummy, document, exclude_pending=False, limit=100)
        res = await fn(document.uuid, uuid_user=user_uuids, pending_from=PendingFromStr.granter, pending=True)
        data = self.check_success(dummy, res, pending=True)
        assert all(item.pending_from == PendingFrom.granter for item in data.data)


    @pytest.mark.asyncio
    async def test_success_200_level(self, dummy: Dummy, requests: Requests):
        "Test the pending query parameter."

        # NOTE: Documents without grants are not generated by `dummy` as every
        #       document generated has an ownership grant, just like those that
        #       should be generated by the API.

        document = dummy.get_document(Level.own, exclude_pending=False)
        assert not document.deleted

        fn = self.fn(requests)
        mt_count = 0
        for level in list(Level):
            for pending in (True, False):
                res = await fn(
                    document.uuid,
                    pending=pending,
                    level=LevelStr(level.name),
                )
                data = self.check_success(
                    dummy, res, level=level, pending=pending, allow_empty=True
                )
                if data.kind is None:
                    mt_count += 1

        if mt_count == 6:
            raise AssertionError("All empty! Check dummy data.")

@pytest.mark.asyncio
class TestDocumentGrantsRevoke(CommonDocumentGrantsTests):

    def fn(self, requests: Requests):
        return requests.grants.documents.revoke

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: Dummy, requests: Requests):

        document = dummy.get_document(Level.own, exclude_pending=True)
        assert not document.deleted

        q_users = document.q_select_users().where(Grant.level < Level.own)
        users = tuple(dummy.session.scalars(q_users))
        uuid_user = list(User.resolve_uuid(dummy.session, users))

        q_grants_count_not_rm = (
            select(func.count(literal_column("uuid")))
            .select_from(
                document.q_select_grants(uuid_user, exclude_deleted=True) # type: ignore
                .where(Grant.level < Level.own, Grant.deleted == false())
            )
        )
        grants_count_initial = dummy.session.scalar(q_grants_count_not_rm)
        assert grants_count_initial is not None
        assert grants_count_initial > 0

        fn = self.fn(requests)
        res = await fn(document.uuid, uuid_user=uuid_user)

        if err := check_status(res, 200):
            raise err

        grants_count_second = dummy.session.scalar(q_grants_count_not_rm)
        assert grants_count_second is not None
        assert grants_count_second == 0

        # TODO: Check events.

        # NOTE: All of the grants from earlier should now be in a deleted state
        q_grants_count_rm = (
            select(func.count(literal_column("uuid")))
            .select_from(
                document.q_select_grants(uuid_user, exclude_deleted=False) # type: ignore
                .where(Grant.level < Level.own, Grant.deleted == true())
            )
        )
        grants_count_rm = dummy.session.scalar(q_grants_count_rm)
        assert grants_count_rm is not None
        assert grants_count_rm > 0
        assert grants_count_rm == grants_count_initial

        # NOTE: Should return empty when filtering by deleted ids.
        fn_read = requests.grants.documents.read
        res_read = await fn_read(document.uuid, uuid_user=uuid_user)

        if err := check_status(res_read, 200):
            raise err

        data = self.adapter.validate_json(res_read.content)
        assert data.kind is None

        res = await fn(document.uuid, uuid_user=uuid_user, force=True)

        # TODO: Check indepotence.

    @pytest.mark.asyncio
    async def test_forbidden_403_cannot_reject_other_owner(self, dummy: Dummy, requests: Requests):
        assert False


class TestDocumentGrantsApprove(CommonDocumentGrantsTests):

    def fn(self, requests: Requests):
        return requests.grants.documents.approve

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: Dummy, requests: Requests):

        # Get owned document
        document = dummy.get_document(Level.own)
        assert not document.deleted

        grant = dummy.get_grant(document)
        assert not grant.pending
        assert not grant.deleted
        assert grant.level == Level.own

        # NOTE: Find pending users and run against read.
        uuid_users_pending_from_granter = self.document_user_uuids(dummy, document, pending=True, exclude_pending=False, pending_from=PendingFrom.granter)
        fn_read = requests.grants.documents.read
        res_pending = await fn_read(
            document.uuid,
            uuid_user=uuid_users_pending_from_granter,
            pending=True,
            pending_from=PendingFrom.created,
        )

        if err := check_status(res_pending):
            raise err

        # NOTE: Data is gaurenteed nonempty since users known.
        data = self.adapter.validate_json(res_pending.content)
        assert data.kind is KindObject.grant
        assert data.kind_nesting is KindNesting.array

        uuid_users_pending_from_granter_recieved = set(item.uuid for item in data.data)
        assert len(uuid_users_pending_from_granter_recieved) == len(uuid_users_pending_from_granter)

        fn = self.fn(requests)
        res= await fn(document.uuid, uuid_user = uuid_users_pending_from_granter)
        if err := check_status(res):
            raise err

        # Check data returned.
        data = self.adapter_w_events.validate_json(res.content)
        assert data.events is not None

        for item in data.data:
            assert not item.pending
            assert not item.deleted
            assert item.uuid in uuid_users_pending_from_granter_recieved

        # TODO: check events

        # NOTE: Reading should result in empty since all approved.
        res = await fn_read(document.uuid, uuid_user=uuid_users_pending_from_granter, pending=True,)
        if err := check_status(res_pending):
            raise err

        data = self.adapter.validate_json(res_pending.content)
        assert data.kind is None

        # NOTE: Check indempotence. 
        res = await fn(document.uuid, uuid_user=uuid_users_pending_from_granter)
        if err := check_status(res):
            raise err

        data = self.adapter_w_events.validate_json(res.content)
        assert data.kind is None
        assert data.events is None


class TestDocumentGrantsInvite(CommonDocumentGrantsTests):

    def fn(self, requests: Requests):
        return requests.grants.documents.invite

    @pytest.mark.asyncio
    async def test_success_200(self, dummy: Dummy, requests: Requests):
        assert False


