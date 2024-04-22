# =========================================================================== #
import asyncio
from typing import Set

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import BaseDDLElement, delete, false, func, select, update
from sqlalchemy.orm import Session

# --------------------------------------------------------------------------- #
from app import util
from app.auth import Token
from app.controllers.base import (
    Data,
    ResolvedCollection,
    ResolvedDocument,
    ResolvedUser,
)
from app.fields import KindObject, Level, PendingFrom
from app.models import Collection, Document, Event, Grant, User, resolve_model, uuids
from app.schemas import AsOutput, DocumentSchema, OutputWithEvents
from tests.config import PytestClientConfig, PyTestClientProfileConfig
from tests.conftest import client_config
from tests.dummy import DummyHandler, DummyProvider, GetPrimaryKwargs


@pytest.mark.parametrize(
    "count", [(None, k) for k in range(5)]
)  # , indirect=["dummy"])
class TestDummyProvider:
    """Because if this is not tested then tests are unstable."""

    def test_mk(self, dummy_handler: DummyHandler, session: Session, count: int):
        """Just check the dummy provided by the fixture. :meth:`mk` is called
        within the constructor and the dummy should be fresh."""

        dummy = DummyProvider(dummy_handler.config, session)
        session, uuid = dummy.session, dummy.user.uuid

        # NOTE: Verify that collections exist.
        q = select(func.count(Collection.uuid)).where(
            Collection.id_user == dummy.user.id
        )
        assert (n := session.scalar(q)) is not None and n > 0

        # NOTE: Various document checks. (1) check that dummy has its own
        #       `created` documents, (2) check that dummy has grants to other
        #       items. (3)

        q = select(func.count(Grant.uuid)).where(
            Grant.id_user == dummy.user.id,
            Grant.pending_from == PendingFrom.created,
        )
        assert (n := session.scalar(q)) is not None and n > 0

        q = select(func.count(Grant.pending_from.distinct()))
        q = q.where(
            Grant.id_user == dummy.user.id,
            Grant.pending_from != PendingFrom.created,
        )
        assert (n := session.scalar(q)) is not None and n > 0

        q = select(func.count(Grant.level.distinct()))
        q = q.where(Grant.id_user == dummy.user.id)
        assert session.scalar(q) == 3

        q = select(func.count(Grant.pending.distinct()))
        assert session.scalar(q) == 2

    def test_randomize_primary(self, dummy: DummyProvider, count: int):
        # NOTE: Should be undeleted and public.
        kwargs = GetPrimaryKwargs(deleted=None, public=True)
        documents = dummy.get_documents(100, kwargs, other=True)
        assert (n := len(documents)) > 0
        assert all(dd.public for dd in documents)
        # assert all(not dd.deleted for dd in documents)

        uuid_document = uuids(documents)
        dummy.randomize_primary(Document, uuid_document)
        dummy.session.expire_all()

        documents_again = dummy.get_documents(
            n,
            GetPrimaryKwargs(
                public=None,
                deleted=None,
                uuids=uuid_document,
            ),
            other=True,
        )
        assert len(documents_again) == n
        assert not all(dd.public for dd in documents), str(n)
        # assert not all(dd.deleted for dd in documents), str(n)

    def test_get_primary(self, dummy: DummyProvider, count: int):
        for deleted in (True, False, None):
            for public in (True, False, None):
                collections = dummy.get_primary(
                    Collection,
                    3,
                    deleted=deleted,
                    public=public,
                    retry=False,
                )
                assert isinstance(collections, tuple)
                assert len(collections) == 3

                for collection in collections:
                    if deleted is not None:
                        assert collection.deleted is deleted
                    if public is not None:
                        assert collection.public is public

        dummy.get_collections_retry_callback()
        collections = dummy.get_primary(
            Collection,
            3,
            callback=lambda q: q.join(User).where(User.uuid == dummy.user.uuid),
            retry=False,
        )
        assert 3 >= isinstance(collections, tuple) and len(collections) > 0
        assert all(isinstance(cc, Collection) for cc in collections)

        bad = set(cc.uuid_user for cc in collections if cc.uuid_user != dummy.user.uuid)
        if bad:
            msg = f"Unexpected user uuids for collections: `{bad}`."
            raise AssertionError(msg)

    def test_get_users(self, dummy: DummyProvider, count: int):
        for _ in range(10):
            users = dummy.get_users(5)
            assert isinstance(users, tuple) and 0 < (n_res := len(users)) <= 5
            assert all(isinstance(uu, User) for uu in users)

            # NOTE: User uuid users to test `other`
            # uuid_users = set(uu.uuid for uu in users)
            uuid_users = {dummy.user.uuid}

            get_primary_kwargs = GetPrimaryKwargs(uuids=uuid_users, allow_empty=True)
            users = dummy.get_users(1, get_primary_kwargs)
            assert len(users) == 1

            users = dummy.get_users(1, get_primary_kwargs, other=True)
            assert len(users) == 0

    def test_get_collections(self, dummy: DummyProvider, count: int):
        collections = dummy.get_collections(5, other=False)
        n = len(collections)
        assert isinstance(collections, tuple), 0 < (n) <= 5
        assert all(cc.uuid_user == dummy.user.uuid for cc in collections)
        assert all(not cc.deleted for cc in collections)

        # NOTE: There should be nothing as the uuids specified are `other`.
        #       That is, the results returned when `other` is `True` should
        #       be disjoint from the results returned when it is `False`.
        uuid_collections = set(cc.uuid for cc in collections)
        get_primary_kwargs = GetPrimaryKwargs(
            uuids=uuid_collections,
            retry=False,
        )
        with pytest.raises(AssertionError) as err:
            collections = dummy.get_collections(5, get_primary_kwargs, other=True)
            assert not len(collections)

        err_msg = str(err.value)
        assert "Could not find test data for " in err_msg
        assert "table `collections` after `0` randomizations." in err_msg

        get_primary_kwargs.update(allow_empty=True)
        collections = dummy.get_collections(5, get_primary_kwargs, other=True)
        assert not len(collections), "No collections should have been returned."

        # NOTE: With `other` and `uuids` set everything should go fine.
        dummy.get_collections(5, get_primary_kwargs, other=False)
        collections = dummy.get_collections(5, get_primary_kwargs, other=False)
        assert len(collections) == n

        # NOTE: Get other collections.
        collections_other = dummy.get_collections(5, other=True)
        n_other = len(collections_other)
        assert isinstance(collections_other, tuple), 0 < n_other <= 5
        assert all(cc.uuid_user != dummy.user.uuid for cc in collections_other)
        uuid_collections_other = set(cc.uuid for cc in collections_other)

        get_primary_kwargs = GetPrimaryKwargs(retry=False, uuids=uuid_collections_other)
        collections_other = dummy.get_collections(5, get_primary_kwargs, other=True)
        assert len(collections_other) == n_other

    def test_get_documents(self, dummy: DummyProvider, count: int):
        kwargs = GetPrimaryKwargs(
            retry=False,
            allow_empty=True,
        )
        dummy.get_documents_retry_callback()

        for level in list(Level):
            documents = dummy.get_documents(10, kwargs, level=level, other=False)
            assert isinstance(documents, tuple)
            assert all(isinstance(dd, Document) for dd in documents)
            assert (n := len(documents)) > 0
            uuid_documents = uuids(documents)

            # NOTE: Verify grants.
            q_grants = (
                select(Grant)
                .join(Document)
                .where(
                    Grant.id_user == dummy.user.id,
                    Document.uuid.in_(uuid_documents),
                )
            )
            # util.sql(dummy.session, q_grants)
            grants = tuple(dummy.session.scalars(q_grants))
            assert len(grants) == n
            assert all(gg.level.value >= level.value for gg in grants)
            assert all(
                not gg.deleted and not gg.pending and gg.level.value >= level.value
                for gg in grants
            )

            grants_computed = tuple(dummy.get_document_grant(dd) for dd in documents)
            assert len(grants_computed) == n
            assert uuids(grants) == uuids(grants_computed)

            # NOTE: Get the same docs using uuids.
            kwargs.update(uuids=uuid_documents)
            docs_from_uuids = dummy.get_documents(10, kwargs, other=None)
            uuid_docs_from_uuids = uuids(docs_from_uuids)

            assert uuid_docs_from_uuids == uuid_documents

        # NOTE: Get docs that do not belong the dummy user.
        kwargs = GetPrimaryKwargs(retry=False)
        documents = dummy.get_documents(10, kwargs, other=True)
        uuid_documents = uuids(documents)
        q_grants = (
            select(func.count(Grant.uuid))
            .join(Document)
            .where(
                Document.uuid.in_(uuid_documents),
                Grant.id_user == dummy.user.id,
            )
        )
        n_grants = dummy.session.scalar(q_grants)
        assert not n_grants

    # @pytest.mark.skip
    # def test_get_document_grant(self):
    #     """Tested in ``test_documents``."""
    #     ...

    @pytest.mark.asyncio
    async def test_get_events(
        self,
        client_config: PyTestClientProfileConfig,
        dummy: DummyProvider,
        count: int,
        app,
    ):
        documents = dummy.get_documents(other=False, level=Level.own, n=3)
        uuid_documents = uuids(documents)

        # NOTE: Delete some documents so events exist for the user.
        def check_result(response: httpx.Response, uuid_events: Set[str]):
            assert response.status_code == 200

            data = OutputWithEvents[DocumentSchema].model_validate_json(
                response.content
            )
            assert data.kind == KindObject.document
            assert data.kind_nesting is None
            assert len(data.events)

            uuid_events_item = set(item.uuid for item in data.events)
            uuid_events |= uuid_events_item

        async with httpx.AsyncClient(app=app) as client:
            requests = dummy.requests(client_config, client)
            uuid_events = set()

            reqs = (requests.documents.delete(uuid) for uuid in uuid_documents)
            tuple(
                map(
                    lambda res: check_result(res, uuid_events),
                    await asyncio.gather(*reqs),
                )
            )
            assert len(uuid_events)

        # NOTE: Make sure events exist first.
        dummy.session.reset()

        q = select(func.count(Event.uuid)).where(Event.uuid_user == dummy.user.uuid)
        n_total = dummy.session.scalar(q)
        assert n_total is not None
        assert n_total > 0, f"No events were generated for user `{dummy.user.uuid}`."

        # NOTE: Get own events. **1**
        events = dummy.get_events(10, other=False)
        assert len(events), "Events not found."
        assert all(ee.uuid_user == dummy.user.uuid for ee in events)
        uuid_events = set(ee.uuid for ee in events)

        # NOTE: Should not turn up anything when owned ids are specified but
        #       other is specified. ``allow_empty`` is ``True``. **2**
        kwargs = GetPrimaryKwargs(uuids=uuid_events, retry=False)
        events = dummy.get_events(10, kwargs, other=True)
        assert not len(events)

        # NOTE: Get other events. **3**
        events = dummy.get_events(10, other=True)
        assert all(ee.uuid_user != dummy.user.uuid for ee in events)

        # NOTE: Dual to **2**.
        kwargs = GetPrimaryKwargs(uuids=uuid_events, retry=False)
        events = dummy.get_events(10, kwargs, other=True)
        assert not len(events)

    @pytest.mark.asyncio
    async def test_requests(
        self,
        client_config: PytestClientConfig,
        dummy: DummyProvider,
        count: int,
        app: FastAPI | None,
    ):

        async with httpx.AsyncClient(app=app) as client:
            requests = dummy.requests(client_config, client)
            res = await requests.users.read(dummy.user.uuid)

            assert (
                res.status_code == 200
            ), f"`/users/{{uuid}}` should work. `{res.json()}`."

            profile = requests.context.config.profile
            assert profile is not None
            assert profile.uuid_user == dummy.user.uuid
            assert (
                Token.model_validate(
                    dummy.auth.decode(requests.context.headers["authorization"])
                )
                == dummy.token
            )

    def test_token(self, dummy: DummyProvider, count: int):
        token = dummy.token
        assert isinstance(token, Token) and token.uuid == dummy.user.uuid
        assert token.admin == dummy.user.admin

        token_from_enc = Token.model_validate(
            dummy.auth.decode(dummy.token_encoded, header=False)
        )
        assert token_from_enc == dummy.token

    def test_info_mark_used(self, dummy: DummyProvider, count: int):
        session = dummy.session
        session.refresh(dummy.user)
        initial_count = len(dummy.user.content["dummy"]["used_by"])

        dummy.info_mark_used("test_info_mark_used")
        session.commit()
        session.refresh(dummy.user)

        final_count = len(dummy.user.content["dummy"]["used_by"])
        assert final_count == initial_count + 1

    def test_info_mark_tainted(self, dummy: DummyProvider, count: int):
        session = dummy.session
        session.refresh(dummy.user)
        tainted_initial = dummy.user.content["dummy"]["tainted"]

        dummy.info_mark_tainted(not tainted_initial)
        session.commit()
        session.refresh(dummy.user)

        tainted_final = dummy.user.content["dummy"]["tainted"]
        assert tainted_final == (not tainted_initial)

    def test_info_is_tainted(self, dummy: DummyProvider, count: int):
        session = dummy.session
        session.refresh(dummy.user)
        n_used_by = len(dummy.user.content["dummy"]["used_by"])

        # NOTE: Marking the data as tainted should result in false.
        dummy.info_mark_tainted()
        session.commit()
        session.refresh(dummy.user)

        assert dummy.info_is_tainted(n_used_by + 1), "Dummy tainted directly."

        # NOTE: Tainted by lowering the maximum use.
        dummy.info_mark_tainted(False)
        session.commit()
        session.refresh(dummy.user)

        assert dummy.info_is_tainted(n_used_by - 1), "Dummy tainted indirectly."
        assert not dummy.info_is_tainted(
            n_used_by + 1
        ), "Too few uses for indirect tainting."

    def test_get_data_user(self, dummy: DummyProvider, count: int):
        data = dummy.get_users_data()
        assert isinstance(data, Data)
        assert isinstance(data.data, ResolvedUser)

    def test_get_data_document(self, dummy: DummyProvider, count: int):
        data = dummy.get_documents_data(level=Level.view)
        assert isinstance(data, Data)
        assert isinstance(data.data, ResolvedDocument)

    def test_get_data_collection(self, dummy: DummyProvider, count: int):
        data = dummy.get_collections_data()
        assert isinstance(data, Data)
        assert isinstance(data.data, ResolvedCollection)

    # def test_data(self, dummy: DummyProvider, count: int):
    #     assert False

    def test_get_primary_retry(self, dummy: DummyProvider, count: int):
        """Verify that ``get_primary`` is robust."""

        # NOTE: Delete dummy collections.
        q_rm = delete(Collection).where(Collection.id_user == dummy.user.id)

        session = dummy.session
        session.execute(q_rm)
        session.commit()

        kwargs = GetPrimaryKwargs(retry=False, allow_empty=True)
        collections = dummy.get_collections(5, kwargs, other=False)
        assert isinstance(collections, tuple) and not len(collections)

        # NOTE: Try using the retry feature.
        kwargs.update(retry=True, allow_empty=False)
        collections = dummy.get_collections(5, kwargs, other=False)
        assert isinstance(collections, tuple)
        assert len(collections)

        # NOTE: Delete dummy documents where the user is designated as the
        #       ``creator`` and grants on remaining documents.
        q_documents_created = select(Document).where(
            Grant.id_user == dummy.user.id,
            Grant.pending_from == PendingFrom.created,
        )
        for doc in session.scalars(q_documents_created):
            session.delete(doc)

        session.commit()

        session.execute(delete(Grant).where(Grant.id_user == dummy.user.id))
        session.commit()

        # NOTE: Confirm document and grant removal with db and `get_documents`.
        q = select(func.count(Grant.uuid)).where(Grant.id_user == dummy.user.id)
        assert not session.scalar(q), "No grants should remain for dummy user."

        kwargs = GetPrimaryKwargs(
            retry=False, allow_empty=True, deleted=None, public=None
        )
        docs = dummy.get_documents(10, kwargs, other=False, level=Level.view)
        assert not len(docs), "No documents should have been found."

        kwargs.update(retry=True, allow_empty=False)
        docs = dummy.get_documents(10, kwargs, other=False, level=Level.view)


class TestDummyHandler:
    def test_dispose(self, dummy_handler: DummyHandler):
        with dummy_handler.sessionmaker() as session:
            dummy = DummyProvider(dummy_handler.config, session)
            uuid_users = uuids(dummy.get_users(5, other=True))
            session.execute(
                update(User)
                .values(
                    info=func.JSON_ARRAY_APPEND(
                        User.content, "$.dummy.used_by", "test_clean"
                    ),
                )
                .where(User.uuid.in_(uuid_users))
            )
            session.commit()

        dummy_handler.dispose(maximum_use_count=1, uuids=uuid_users)

        with dummy_handler.sessionmaker() as session:
            q_remaining = select(func.count(User.uuid)).where(User.uuid.in_(uuid_users))
            n_remaining = session.scalar(q_remaining)

            assert n_remaining == 0
