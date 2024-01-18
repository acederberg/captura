import asyncio
from .test_assignments import TestAssignmentView
from http import HTTPMethod

import secrets
from typing import (
    List,
)

import httpx
import pytest
from app import __version__, util
from app.auth import Auth
from app.models import (
    AssocCollectionDocument,
    AssocUserDocument,
    ChildrenCollection,
    Collection,
    Document,
    KindEvent,
    KindObject,
    User,
)
from app.schemas import (
    CollectionMetadataSchema,
    CollectionSchema,
    EventSchema,
)
from client.requests import (
    CollectionRequests,
    ChildrenUser,
    Requests,
    UserRequests,
)
from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from . import util

# NOTE: The `requests` fixture must exist in module scope directly.
from .util import requests, BaseTestViews


class TestCollectionView(BaseTestViews):
    T = CollectionRequests

    @pytest.fixture
    def client_user(self, client: CollectionRequests) -> UserRequests:
        return UserRequests.from_(client)

    @pytest.mark.asyncio
    async def test_read_collection(self, client: CollectionRequests):
        """General test of `GET /collection/<uuid>`."""

        # Read some collections.
        res = await client.read(util.DEFAULT_UUID_COLLECTION)
        if err := util.check_status(res, 200):
            raise err

        data = res.json()
        assert isinstance(data, dict)
        collection = CollectionSchema.model_validate(data)
        assert collection.uuid == util.DEFAULT_UUID_COLLECTION

    @pytest.mark.asyncio
    async def test_read_collection_cannot_deleted(
        self,
        client: CollectionRequests,
        sessionmaker: sessionmaker[Session],
    ):
        """Verify that items staged for deletion cannot be obtianed through
        `GET /collection/<uuid>`.
        """

        with sessionmaker() as session:
            # Make sure is not staged for deletion and verify can read.
            collection = Collection.if_exists(session, util.DEFAULT_UUID_COLLECTION)
            collection.deleted = False
            session.add(collection)
            session.commit()

            res = await client.read(util.DEFAULT_UUID_COLLECTION)
            if err := util.check_status(res, 200):
                raise err

            data = res.json()
            assert isinstance(data, dict)
            CollectionSchema.model_validate(data)

            # Stage collection for deletion
            collection.deleted = True
            session.add(collection)
            session.commit()
            res = await client.read(util.DEFAULT_UUID_COLLECTION)
            if err := util.check_status(res, 404):
                raise err

    @pytest.mark.asyncio
    async def test_read_collection_private(
        self, client: CollectionRequests, sessionmaker: sessionmaker[Session]
    ):
        """Verify that private collections are only visible to those who are
        the owner on `GET /collection/<uuid>`.
        """

        with sessionmaker() as session:
            # Make sure a user can read their own private collection.
            user = User.if_exists(session, util.DEFAULT_UUID)
            collection = Collection.if_exists(session, util.DEFAULT_UUID_COLLECTION)
            collection.user = user
            collection.public = False
            collection.deleted = False
            session.add(collection)
            session.commit()

            res = await client.read(util.DEFAULT_UUID_COLLECTION)
            if err := util.check_status(res, 200):
                raise err
            data = res.json()
            assert isinstance(data, dict)

            # Assign the default collection to a new user and make it private.
            user_new = User.if_exists(session, "99d-99d-99d")
            collection.user = user_new
            session.add(collection)
            session.commit()

            res = await client.read(util.DEFAULT_UUID_COLLECTION)
            if err := util.check_status(res, 403):
                raise err

            # Make default collection public again.
            # Leave it with the other user.
            collection.public = True
            session.add(collection)
            session.commit()

            res = await client.read(util.DEFAULT_UUID_COLLECTION)
            if err := util.check_status(res, 200):
                raise err
            data = res.json()
            assert isinstance(data, dict)

            collection.user = user
            session.add(collection)
            session.commit()

    @classmethod
    @util.checks_event
    def check_event(
        cls,
        res: httpx.Response,
        *,
        uuid_document: List[str] | None,
        uuid_assignment: List[str] | None,
        restore: bool = False,
    ) -> EventSchema:
        url = "/collections"
        request = res.request
        event = EventSchema.model_validate_json(res.content)
        event_expected = dict(
            api_version=__version__,
            uuid_user=util.DEFAULT_UUID,
            kind_obj=KindObject.collection,
        )

        match request.method:
            case HTTPMethod.GET:
                raise ValueError("`GET` should not return events.")
            case HTTPMethod.DELETE:
                event_expected.update(
                    kind=KindEvent.delete,
                    detail=f"Collection {'restored' if restore else 'deleted'}.",
                    api_origin=f"DELETE {url}/<uuid>",
                )
            case HTTPMethod.POST:
                event_expected.update(
                    kind=KindEvent.create,
                    detail="Collection created.",
                    api_origin=f"POST {url}",
                )
            case HTTPMethod.PATCH:
                event_expected.update(
                    kind=KindEvent.update,
                    detail="Collection updated.",
                    api_origin=f"PATCH {url}/<uuid>.",
                )
            case _:
                raise ValueError(f"Unexpected method `{request.method}`.")

        util.event_compare(event, event_expected)
        if (
            request.method == HTTPMethod.POST.value
            or request.method == HTTPMethod.DELETE.value
        ):
            if event.children:
                assert len(event.children) == 1
                (event_assocs,) = event.children
                TestAssignmentView.check_event(
                    res,
                    uuid_document=uuid_document,
                    uuid_assignment=uuid_assignment,
                    restore=restore,
                    event=event_assocs,
                )
        else:
            raise ValueError("Not ready")
            ...

        return event

    @pytest.mark.asyncio
    async def test_create_collection(
        self,
        client: CollectionRequests,
        client_user: UserRequests,
        sessionmaker: sessionmaker[Session],
    ):
        """General test of `POST /collection/<uuid>`."""

        async def check_created_documents(event):
            res = await client.read(
                event.uuid_obj,
                ChildrenCollection.documents,
            )
            if err := util.check_status(res, 200):
                raise err
            data = res.json()
            assert isinstance(data, list)
            assert len(data) == len(event.children)

        collections_created_uuids: List[str] = list()
        with sessionmaker() as session:
            user = User.if_exists(session, util.DEFAULT_UUID)
            uuid_document = list(
                session.execute(
                    select(Document.uuid)
                    .join(AssocUserDocument)
                    .where(AssocUserDocument.id_user == user.id)
                ).scalars()
            )
            session.execute(update(Document).values(deleted=False))
            session.commit()
            assert len(uuid_document) > 0, "Expected documents for user 1."

        # Test with documents that are not deleted.
        res = await client.create(
            name=f"Test Create Collection `1-{secrets.token_urlsafe()}`.",
            description="This is created by `test_create_collection`.",
            public=True,
            uuid_document=uuid_document,
        )
        if err := util.check_status(res, 201):
            raise err

        with sessionmaker() as session:
            uuid_assignment = list(
                session.execute(
                    select(AssocCollectionDocument.uuid)
                    .join(Collection)
                    .where(
                        Collection.uuid == util.DEFAULT_UUID_COLLECTION,
                    )
                ).scalars()
            )

        check_event_args = dict(
            uuid_document=uuid_document,
            uuid_assignment=uuid_assignment,
        )
        event, err = self.check_event(res, **check_event_args)
        if err is not None:
            raise err
        assert len(event.children)

        await check_created_documents(event)
        collections_created_uuids.append(event.uuid_obj)

        with sessionmaker() as session:
            # Stage some documents for deletion and make sure that documents
            # staged for deletion do not get added to the collection.
            session.execute(update(Document).values(deleted=True))
            session.commit()

        res = await client.create(
            name=f"Test Create Collection `2-{secrets.token_urlsafe()}`",
            description="This is created by `test_create_collection`.",
            public=True,
            uuid_document=uuid_document,
        )
        if err := util.check_status(res, 201):
            raise err

        event = EventSchema.model_validate_json(res.content)
        assert len(event.children) == 0
        self.check_event(res, **check_event_args)

        await check_created_documents(event)
        collections_created_uuids.append(event.uuid_obj)

        with sessionmaker() as session:
            # Collection should have no documents

            # NOTE: Verify that public documents can be added to the
            #       collection. Notice that this document is userless.
            session.execute(update(Document).values(deleted=False))
            session.add(
                document_new := Document(
                    name="Test Create Collection Public Document",
                    description="This document should be public and not deleted.",
                    content=b"You're momma iz so _.",
                    format="md",
                    public=True,
                )
            )
            session.commit()

            res = await client.create(
                name=f"Test Create Collection `3-{secrets.token_urlsafe()}",
                description="This is created by `test_create_collection`.",
                public=True,
                uuid_document=[document_new.uuid],
            )
            if err := util.check_status(res, 201):
                raise err

            event = EventSchema.model_validate_json(res.content)
            assert len(event.children) == 1
            check_event(event)
            await check_created_documents(event)
            collections_created_uuids.append(event.uuid_obj)

            # NOTE: Veryify that private documents belonging to abother user
            #       (or in this case no user) cannot be added.
            document_new.public = False
            session.add(document_new)
            session.commit()

            res = await client.create(
                name="Test Create Collection 4",
                description="This is created by `test_create_collection`.",
                public=True,
                uuid_document=[document_new.uuid],
            )
            if err := util.check_status(res, 201):
                raise err

            event, err = self.check_event(res, **check_event_args)
            assert len(event.children) == 0
            if err is not None:
                raise err

            await check_created_documents(event)
            collections_created_uuids.append(event.uuid_obj)

            # NOTE: Veryify that the created collections exist.
            # BONUS: Using the `client_user` fixture.
            res = await client_user.read(
                util.DEFAULT_UUID,
                ChildrenUser.collections,
                collections_created_uuids,
            )
            if err := util.check_status(res, 200):
                raise err

            collections = {
                uuid: CollectionMetadataSchema.model_validate(data)
                for uuid, data in res.json().items()
            }
            assert len(collections) == 4
            assert all(key in collections_created_uuids for key in collections)

            # BONUS: Make sure that deletion filtering works for the user client
            session.execute(
                update(Collection)
                .where(Collection.uuid.in_(collections_created_uuids))
                .values(deleted=True)
            )
            session.commit()

            res = await client_user.read(
                util.DEFAULT_UUID,
                ChildrenUser.collections,
                collections_created_uuids,
            )
            if err := util.check_status(res, 200):
                raise err
            assert len(res.json()) == 0, "Collections should be staged for deletion."

    @pytest.mark.asyncio
    async def test_create_collection_deleted_documents(
        self,
        client: CollectionRequests,
        client_user: UserRequests,
        sessionmaker: sessionmaker[Session],
        auth: Auth,
    ):
        """Verify that deleted documents will not be assigned to a posted
        collection.
        """

        # NOTE: Acting as user `99d-99d-99d`.
        client.token = auth.encode({"uuid": "99d-99d-99d"})
        client_user.token = client.token

        with sessionmaker() as session:
            user = User.if_exists(session, "99d-99d-99d")
            u = update(Collection).where(Collection.id_user == user.id)
            session.execute(u.values(deleted=True))
            session.commit()

            res = await client.create(
                name="Test Create Collection Delete Documents",
                description="Tests that deleted documents cannot be posted with a new collection.",
                public=False,
            )
            if err := util.check_status(res, 201):
                raise err

            event = EventSchema.model_validate_json(res.content)
            assert event.api_origin == "POST /collections"
            assert event.api_version == __version__
            assert event.uuid_user == "99d-99d-99d"
            assert event.uuid is not None
            assert event.kind == KindEvent.create
            assert event.kind_obj == KindObject.collection
            assert len(event.children) == 0, "Documents should have not been assigned."

            # BONUS: Verify that the collection exists for the user but cannot
            #        be accessed by others when private.
            async def user_read_and_check(expect: int):
                res = await client_user.read(
                    "99d-99d-99d",
                    ChildrenUser.collections,
                    event.uuid_obj,
                )
                if err := util.check_status(res, 200):
                    raise err
                data = res.json()
                assert len(data) == expect

                res = await client.read(event.uuid_obj)
                if err := util.check_status(res, 200 if expect else 403):
                    raise err

            # NOTE: Act like user `000-000-000` so that access controllers are
            #       used.
            client.token = auth.encode({"uuid": util.DEFAULT_UUID})
            client_user.token = client.token
            await user_read_and_check(0)

            # Bonus: Change access to public and verify that non-owning users
            #        can access.
            session.execute(u.values(public=True))
            session.commit()

            await user_read_and_check(1)

    @pytest.mark.asyncio
    async def test_delete_collection(
        self,
        requests: Requests,
        sessionmaker: sessionmaker[Session],
    ):
        """General test of `DELETE /collection/<uuid>`."""

        uuid_collection = util.DEFAULT_UUID_COLLECTION

        # Add some documents.
        res_docs = await requests.users.read(util.DEFAULT_UUID, ChildrenUser.documents)
        if err := util.check_status(res_docs, 200):
            raise err

        assert isinstance(data := res_docs.json(), dict)
        assert len(data), "Expected documents for user."
        uuid_document = list(data.keys())
        assert len(uuid_document)

        res_assign = await requests.assignments.create(uuid_collection, uuid_document)
        if err := util.check_status(res_assign):
            raise err

        event, err = TestAssignmentView.check_event(
            res_assign,
            uuid_assignment=None,
            uuid_document=uuid_document,
        )
        assert len(event.children) == len(uuid_document)
        if err is not None:
            raise err

        with sessionmaker() as session:
            collection = Collection.if_exists(session, uuid_collection)
            res = session.execute(
                q := select(AssocCollectionDocument.uuid)
                .select_from(Collection)
                .join(AssocCollectionDocument)
                .where(Collection.uuid == uuid_collection)
            )
            uuid_assignment = list(res.scalars())
            assert len(uuid_assignment) == len(
                uuid_document
            ), "For every document there should be exactly on assignment."

        res = await requests.collections.delete(uuid_collection)
        if err := util.check_status(res, 200):
            raise err

        check_event_args = dict(
            uuid_document=uuid_document,
            uuid_assignment=uuid_assignment,
        )
        event, err = self.check_event(res, **check_event_args)
        if err is not None:
            raise err
        assert len(event.children) == 1
        assert len(event.children[0].children) == len(uuid_document)

        # indempotent
        res = await requests.collections.delete(uuid_collection)
        if err := util.check_status(res, 200):
            raise err

        event, err = self.check_event(res, **check_event_args)
        if err is not None:
            raise err
        assert len(event.children) == 1
        assert len(event.children[0].children) == 0

        # Verify directly with database
        with sessionmaker() as session:
            cond = Collection.uuid == uuid_collection
            collection = session.execute(select(Collection).where(cond)).scalar()
            assert collection is not None
            assert collection.deleted

            assocs = set(
                session.execute(
                    select(AssocCollectionDocument.uuid)
                    .select_from(Document)
                    .join(AssocCollectionDocument)
                    .join(Collection)
                    .where(cond, AssocCollectionDocument.deleted)
                ).scalars()
            )
            assert len(assocs) == len(uuid_assignment)

        # Verify not available through endpoints.
        res, res_assign = await asyncio.gather(
            requests.collections.read(uuid_collection),
            requests.assignments.read(uuid_collection),
        )
        if err := util.check_status((res, res_assign), 404):
            raise err

        # BONUS: Cannot reactivate assignments directly
        res_assign = await requests.assignments.create(
            uuid_collection,
            uuid_document,
        )
        if err := util.check_status(res_assign, 404):
            raise err

        # Restore
        res = await requests.collections.delete(uuid_collection, restore=True)
        if err := util.check_status(res):
            raise err

        with sessionmaker() as session:
            uuid_assignment_restored = set(
                session.execute(
                    select(AssocCollectionDocument.uuid).where(
                        AssocCollectionDocument.uuid.in_(uuid_assignment),
                        AssocCollectionDocument.deleted == False,
                    )
                ).scalars()
            )
            assert len(uuid_assignment_restored) == len(uuid_assignment)

        event, err = self.check_event(res, **check_event_args, restore=True)
        if err is not None:
            raise err
        assert len(event.children) == 1
        assert len(event.children[0].children) == len(uuid_document)

        # Verify
        res, res_assign = await asyncio.gather(
            requests.collections.read(uuid_collection),
            requests.assignments.read(uuid_collection),
        )
        if err := util.check_status((res, res_assign), 200):
            raise err

    @pytest.mark.asyncio
    async def test_delete_collection_access(self, client: CollectionRequests):
        """Users should only be able to delete their own collections with
        `DELETE /collection/<uuid>`. They should not be able to delete
        universal (userless) collections either."""

    @pytest.mark.asyncio
    async def test_patch_collection(self, requests: Requests, auth: Auth):
        """General test of `PATCH /collection/<uuid>`."""

        fields = {"uuid_user", "name", "description", "public"}
        uuid_collection = util.DEFAULT_UUID_COLLECTION

        # Make a collection public and change its name
        res = await requests.collections.update(
            uuid_collection,
            name=(name := "Test `PATCH /collection`."),
            public=True,
        )
        if err := util.check_status(res, 200):
            raise err

        fields = {"public", "name"}
        common = dict(
            kind_obj=KindObject.collection,
            api_origin="PATCH /collections/<uuid>",
            uuid_obj=util.DEFAULT_UUID_COLLECTION,
            uuid_user=util.DEFAULT_UUID,
            detail="Collection updated",
        )
        event, err = util.check_event_update(None, res, fields, **common)
        if err := util.check_status(res, 200):
            raise err
        assert len(event.children) == 2

        res = await requests.collections.read(uuid_collection)
        if err := util.check_status(res, 200):
            raise err
        collection = CollectionSchema.model_validate_json(res.content)
        assert collection.name == name
        assert collection.public == True

        # Transfer ownership
        uuid_user = "99d-99d-99d"
        res = await requests.collections.update(
            uuid_collection, uuid_user=uuid_user, public=False
        )
        if (err := util.check_status(res)) is not None:
            raise err

        common["detail"] = None
        fields = {"public"}
        event, err = util.check_event_update(None, res, fields, **common)
        if err is not None:
            raise err

        # Verify readability.
        res = await requests.collections.read(uuid_collection)
        if err := util.check_status(res, 403):
            raise err

        token_initial = requests.token
        token_secondary = auth.encode({"uuid": "99d-99d-99d"})
        requests.update_token(token_secondary)
        assert requests.token == token_secondary
        assert requests.collections.token == token_secondary

        res = await requests.collections.read(uuid_collection)
        if err := util.check_status(res):
            raise err

    @pytest.mark.asyncio
    async def test_patch_collection_access(self, client: CollectionRequests):
        """Users should only be able to update their own collections with
        `PATCH /collection/<uuid>`. They should not be able to update
        universal (userless) collections either."""
        ...
