import asyncio
from http import HTTPMethod
import functools
import itertools
from certifi import where

from yaml.events import Event
from sqlalchemy import func
import json
import secrets
import sys
from typing import (
    Any,
    AsyncGenerator,
    Callable,
    Concatenate,
    Dict,
    Iterable,
    List,
    ParamSpec,
    Self,
    Set,
    Tuple,
    Type,
)

import httpx
import pytest
import pytest_asyncio
import yaml
from app import __version__, util
from app.__main__ import main
from app.auth import Auth
from app.models import (
    AssocCollectionDocument,
    AssocUserDocument,
    ChildrenCollection,
    Collection,
    Document,
    KindEvent,
    Level,
    KindObject,
    User,
)
from app.schemas import (
    AssignmentSchema,
    CollectionMetadataSchema,
    CollectionSchema,
    EventSchema,
    GrantSchema,
    UserSchema,
)
from app.views import AppView, GrantView
from client.config import DefaultsConfig
from client.requests import (
    AssignmentRequests,
    BaseRequests,
    CollectionRequests,
    GrantRequests,
    ChildrenUser,
    Level,
    Requests,
    UserRequests,
)
from fastapi import HTTPException
from sqlalchemy import delete, select, update, and_
from sqlalchemy.orm import Session, make_transient, sessionmaker

from .conftest import PytestClientConfig

logger = util.get_logger(__name__)
CURRENT_APP_VERSION = __version__
DEFAULT_UUID_COLLECTION: str = "foo-ooo-ool"
DEFAULT_UUID_DOCS: str = "aaa-aaa-aaa"
DEFAULT_UUID: str = "000-000-000"
DEFAULT_TOKEN_PAYLOAD = dict(uuid=DEFAULT_UUID)
EVENT_COMMON_FIELDS = {"api_origin", "api_version", "kind", "uuid_user", "detail"}


@pytest_asyncio.fixture(params=[DEFAULT_TOKEN_PAYLOAD])
async def requests(
    client_config: PytestClientConfig,
    async_client: httpx.AsyncClient,
    auth: Auth,
    request,
    T: Type[BaseRequests] = Requests,
) -> BaseRequests:
    token = auth.encode(request.param or DEFAULT_TOKEN_PAYLOAD)
    return T(client_config, async_client, token=token)


def event_compare(event: EventSchema, expect_common: Dict[str, Any]) -> None:
    assert event.uuid is not None
    for field in EVENT_COMMON_FIELDS:
        value = getattr(event, field, None)
        value_expect = expect_common.get(field)
        if value is None:
            raise ValueError(f"`expect.{field}` should not be `None`.")
        elif value_expect is None:
            msg = f"`expect_common[{field}]` should not be `None`."
            raise ValueError(msg)
        if value != value_expect:
            raise AssertionError(
                f"Field `{field}` of event `{event.uuid}` should have "
                f"value `{value_expect}` but has value `{value}`."
            )


P = ParamSpec("P")


def checks_event(
    fn: Callable[Concatenate[Any, httpx.Response, P], EventSchema]
) -> Callable[
    Concatenate[Any, httpx.Response, P],
    Tuple[EventSchema, AssertionError | None],
]:
    """Turn assertions in `check_event` methods into more useful messages.

    Generally :param:`fn` should be decorated with classmethod after decoration
    with this.
    """

    @functools.wraps(fn)
    def wrapper(
        cls: Any,
        res: httpx.Response,
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> Tuple[EventSchema, AssertionError | None]:
        event: EventSchema | None = None
        err: AssertionError | None = None
        try:
            event = fn(cls, res, *args, **kwargs)
        except AssertionError as _err:
            # Yes, it is a joke.
            cerial = json.dumps(res.json(), indent=2)
            msg = " ".join(_err.args)
            msg = "\n".join((msg, f"Event `{cerial}`."))
            err = AssertionError(msg)

        if event is None:
            event = EventSchema.model_validate_json(res.content)

        return event, err

    return wrapper


@checks_event
def check_event_update(
    _,
    res: httpx.Response,
    fields: Set[str],
    *,
    kind_obj: str,
    api_origin: str,
    uuid_obj: str,
    uuid_user: str,
    detail: str,
) -> EventSchema:
    event = EventSchema.model_validate_json(res.content)
    common = dict(api_version=__version__, kind=KindEvent.update)
    common.update(
        kind_obj=kind_obj,
        api_origin=api_origin,
        uuid_user=uuid_user,
        uuid_obj=uuid_obj,
    )
    event_compare(event, common)
    assert event.detail == detail
    for item in event.children:
        assert not len(item.children)
        event_compare(event, common)

        assert detail in item.detail
        assert any(field in item.detail for field in fields)

    return event


class BaseTestViews:
    T: Type[BaseRequests]

    @pytest_asyncio.fixture(params=[DEFAULT_TOKEN_PAYLOAD])
    async def client(
        self,
        client_config: PytestClientConfig,
        async_client: httpx.AsyncClient,
        auth: Auth,
        request,
    ):
        token = auth.encode(request.param)
        return self.T(client_config, async_client, token=token)

    @pytest.fixture(scope="session", autouse=True)
    def invoke_loader(self, load_tables, setup_cleanup):
        ...


def check_status(
    response: httpx.Response | Tuple[httpx.Response, ...], expect: int | None = None
) -> AssertionError | None:
    # DO RECURSE
    if isinstance(response, tuple):
        errs = "\n".join(
            str(err)
            for rr in response
            if (err := check_status(rr, expect=expect)) is not None
        )
        if not errs:
            return None

        return AssertionError(errs)

    if expect is None:
        match response.request.method:
            case HTTPMethod.POST:
                expect = 201
            case _:
                expect = 200

    # BASE CASE
    if response.status_code == expect:
        return None

    req_json = (req := response.request).read().decode()
    try:
        raw = response.json()
    except json.JSONDecodeError:
        raw = None

    res_json = json.dumps(raw, indent=2) if raw is not None else raw

    msg = f"`{req.method} {req.url}` "
    if req_json:
        msg += f"with body `{req_json}`"
    msg = (
        f"Unexpected status code `{response.status_code}` (expected "
        f"`{expect}`) from {msg}. The response included the following "
        f"detail: {res_json}."
    )
    if auth := req.headers.get("authorization"):
        msg += f"\nAuthorization: {auth}"

    return AssertionError(msg)


class TestUserViews(BaseTestViews):
    T = UserRequests

    @pytest.mark.asyncio
    async def test_get_user(self, client: UserRequests):
        "Test for the very limitted (at the moment) GET /users/{uuid}"
        # good is the default user, other is almost certain not to exist.
        good, bad = await asyncio.gather(
            *(client.read(uuid) for uuid in (DEFAULT_UUID, "foobarz"))
        )
        if err := check_status(good, 200):
            raise err
        elif err := check_status(bad, 404):
            raise err

        assert isinstance(result := good.json(), dict)
        assert result["uuid"] == DEFAULT_UUID

        assert bad.status_code == 404

    @pytest.mark.asyncio
    @pytest.mark.parametrize("client", [{}], indirect=["client"])
    async def test_access_no_token(self, client: UserRequests):
        """Test `GET /users/{uuid}` without a token.

        Users should be able to access articles.
        """

        client.token = None
        read, update, delete = await asyncio.gather(
            client.read(DEFAULT_UUID),
            client.update(DEFAULT_UUID, name="woops"),
            client.delete(DEFAULT_UUID),
        )
        if err := check_status(read, 200):
            raise err
        elif err := check_status(update, 401):
            raise err
        elif err := check_status(delete, 401):
            raise err

    # TODO: Add a test that collaborators can see this users account.
    @pytest.mark.asyncio
    async def test_get_user_public(self, client: UserRequests):
        """Test GET /users/{uuid} for a private user.

        Eventually the queries should deal with 'deactivation' via API
        eventually.
        """
        response = await client.update(DEFAULT_UUID, public=False)
        if err := check_status(response, 200):
            raise err

        response = await client.read(DEFAULT_UUID)
        if err := check_status(response, 204):
            raise err

        response = await client.update(DEFAULT_UUID, public=True)
        if err := check_status(response, 200):
            raise err

        response = await client.read(DEFAULT_UUID)
        if err := check_status(response, 200):
            raise err
        result = response.json()
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_get_user_deleted(
        self, client: UserRequests, sessionmaker: sessionmaker[Session]
    ):
        """Test `GET /users/{uuid}` on a user that has been deleted.

        This endpoint should state that the user has been deleted but provide a
        response with a `404` status code."""

        async def get_all(status) -> Tuple[httpx.Response, ...]:
            res = await asyncio.gather(
                client.read(DEFAULT_UUID),
                client.read(DEFAULT_UUID, ChildrenUser.documents),
                client.read(DEFAULT_UUID, ChildrenUser.collections),
            )
            if err := next((check_status(rr, status) for rr in res), None):
                raise err
            return res

        async def delete(restore=False):
            response = await client.delete(DEFAULT_UUID, restore=restore)
            if err := check_status(response, 200):
                raise err
            event = EventSchema.model_validate_json(response.content)
            restore_str = "restore" if restore else "delete"
            assert event.detail == f"User {restore_str}d."
            assert event.kind == KindEvent.delete
            assert event.uuid_parent is None
            assert isinstance(event.children, list)

            for child in event.children:
                assert child.kind == KindEvent.delete
                assert child.uuid_parent == event.uuid
                if child.kind_obj == KindObject.document:
                    assert child.detail == f"Document {restore_str}d."
                elif child.kind_obj == KindObject.collection:
                    assert child.detail == f"Collection {restore_str}d."
                else:
                    raise AssertionError(f"Unexpected event with `{child.kind_obj=}`.")

        with sessionmaker() as session:
            session.execute(update(Document).values(deleted=False))
            session.execute(update(Collection).values(deleted=False))
            session.commit()

        res = await get_all(200)
        _, res_docs, res_coll = res
        assert len(res_docs.json()), "Expected user to have documents."
        assert len(res_coll.json()), "Expected user to have collections."

        await delete()

        res = await get_all(204)
        bad = list(rr.request.url for rr in res if rr.request.content)
        if len(bad):
            raise ValueError(
                f"Expected no user content for user `{DEFAULT_UUID}`, but "
                "content was not returned from the following endpoints "
                f"despite returning a `204` status code: `{bad}`."
            )

        await delete(restore=True)

        res = await get_all(200)
        _, res_docs, res_coll = res
        assert len(res_docs.json()), "Expected user to have documents restored."
        assert len(res_coll.json()), "Expected user to have collections restored."

    @pytest.mark.asyncio
    async def test_patch_user(self, client: UserRequests):
        new_name = secrets.token_hex(4)
        good, bad = await asyncio.gather(
            *(
                client.update(uuid, name=new_name)
                for uuid in (DEFAULT_UUID, "99d-99d-99d")
            )
        )
        if err := check_status(good):
            raise err
        elif err := check_status(bad, 403):
            raise err

        updated = await client.read(DEFAULT_UUID)
        if err := check_status(updated):
            raise err

        assert isinstance(result := updated.json(), dict)
        assert result["uuid"] == DEFAULT_UUID
        assert result["name"] == new_name

    @pytest.mark.asyncio
    async def test_delete_user(self, client: UserRequests):
        # NOTE: Don't worry about getting, there is a separate test for that.
        res = await client.delete(DEFAULT_UUID)
        if err := check_status(res):
            raise err
        event = EventSchema.model_validate_json(res.content)
        assert event.uuid_user == DEFAULT_UUID
        assert event.uuid_obj == DEFAULT_UUID
        assert event.detail == "User deleted."
        n = len(event.children)

        res = await client.delete(DEFAULT_UUID, restore=True)
        if err := check_status(res):
            raise err
        event = EventSchema.model_validate_json(res.content)
        assert event.uuid_user == DEFAULT_UUID
        assert event.uuid_obj == DEFAULT_UUID
        assert event.detail == "User restored."
        assert len(event.children) == n

    @pytest.mark.asyncio
    async def test_delete_user_not_owned(self, client: UserRequests):
        res = await client.delete("99d-99d-99d")
        if err := check_status(res, 403):
            raise err
        assert (
            res.json()["detail"] == "Users can only delete/restore their own account."
        )

    @pytest.mark.asyncio
    async def test_create(self, client: UserRequests):
        def check_common(event: EventSchema):
            assert event.uuid_user is not None
            if not client.config.remote:
                assert event.api_version == CURRENT_APP_VERSION
            assert event.api_origin == "POST /users"
            assert event.kind == KindEvent.create

        p = util.Path.test_assets("test-user-create.yaml")
        res = await client.create(p)
        if err := check_status(res, 201):
            raise err

        # NOTE: The expected number of results changes when the document is
        #       changed. Per the note in the document, do not change it without
        #       testing it first.
        event = EventSchema.model_validate_json(res.content)
        check_common(event)
        assert event.detail == "User created."
        assert event.kind_obj == KindObject.user

        n_collections, n_documents = 0, 0
        for ee in event.children:
            check_common(event)
            if ee.kind_obj == KindObject.collection:
                assert ee.detail == "Collection created."
                n_collections += 1
            elif ee.kind_obj == KindObject.document:
                assert ee.detail == "Document created."
                n_documents += 1
            else:
                raise AssertionError(
                    f"Expected no events of `kind_obj={event.kind_obj}`."
                )

        # Verify counts
        if n_collections != 4:
            raise AssertionError("Expected to find four collections.")
        elif n_documents != 3:
            raise AssertionError("Expected to find three documents.")

        uuid: str = event.uuid_user  # type: ignore
        res = await asyncio.gather(
            client.read(uuid),
            client.read(uuid, ChildrenUser.documents),
            client.read(uuid, ChildrenUser.collections),
        )
        if err := next((check_status(rr, 200) for rr in res), None):
            raise err

        res_user, res_docs, res_collections = res
        user = UserSchema.model_validate_json(res_user.content)
        assert user.name == "test create"
        assert user.description == "test user for test create."
        assert user.url_image == "http://github.com/acederberg"
        assert user.uuid == uuid

        documents, collections = res_docs.json(), res_collections.json()
        assert len(documents) == 3
        assert len(collections) == 4


class TestGrantView(BaseTestViews):
    T = GrantRequests

    @pytest.mark.asyncio
    async def test_read_grants_user(
        self,
        client: GrantRequests,
        sessionmaker: sessionmaker[Session],
    ):
        """Test functionality of `GET /grants/user/<uuid>`."""
        res = await client.read_user("000-000-000")
        if err := check_status(res, 200):
            raise err

        raw = res.json()
        assert isinstance(raw, list)

        grants = list(GrantSchema.model_validate(item) for item in raw)
        assert (n := len(grants)) > 0, "Expected grants."

        # Grants should specify only one user.
        uuids, uuids_users = zip(*((gg.uuid, gg.uuid_user) for gg in grants))
        assert set(uuids_users) == {"000-000-000"}

        # Number of grants should equal the number of entries the owner has in
        # this table.
        with sessionmaker() as session:
            results = list(
                session.execute(
                    select(AssocUserDocument).where(AssocUserDocument.uuid.in_(uuids))
                ).scalars()
            )
            assert len(results) == n

    @pytest.mark.asyncio
    async def test_read_grants_user_only_user(self, client: GrantRequests):
        """Test that a user can only read their own grants.

        In the future, admins will be able to read grants of arbitrary users.
        """
        res = await client.read_user("99d-99d-99d")
        if err := check_status(res, 403):
            raise err
        assert res.json()["detail"] == dict(msg="Users can only read their own grants.")

    @pytest.mark.asyncio
    async def test_read_grants_document(
        self,
        client: GrantRequests,
        sessionmaker: sessionmaker[Session],
    ):
        res = await client.read_document(DEFAULT_UUID_DOCS)
        if err := check_status(res, 200):
            raise err

        with sessionmaker() as session:
            user = session.execute(
                select(User).where(User.uuid == DEFAULT_UUID)
            ).scalar()
            assert user is not None
            assoc = session.execute(
                select(AssocUserDocument).where(
                    AssocUserDocument.id_user == user.id,
                    AssocUserDocument.id_document.in_(
                        select(Document.id).where(
                            Document.uuid == DEFAULT_UUID_DOCS,
                        )
                    ),
                )
            ).scalar()
            assert assoc is not None
            assert assoc.level == Level.own

            assoc.level = Level.view
            session.add(assoc)
            session.commit()

            res = await client.read_document(DEFAULT_UUID_DOCS)
            if err := check_status(res, 403):
                raise err

            result = res.json()["detail"]
            assert result["msg"] == "User must have grant of level `own`."

            session.delete(assoc)
            session.commit()

            res = await client.read_document(DEFAULT_UUID_DOCS)
            if err := check_status(res, 403):
                raise err

            result = res.json()["detail"]
            assert result["msg"] == "No grant for document."

            make_transient(assoc)
            assoc.level = Level.own
            session.add(assoc)
            session.commit()

    @pytest.mark.asyncio
    async def test_post_grant(
        self, client: GrantRequests, sessionmaker: sessionmaker[Session]
    ):
        def check_common(event):
            assert event.api_origin == "POST /grants/documents/<uuid>"
            assert event.uuid_user == DEFAULT_UUID, "Should be token user."
            assert event.detail == "Grants issued."
            assert event.kind == KindEvent.grant

        # Manually remove existing grants.
        with sessionmaker() as session:
            try:
                user = User.if_exists(session, "99d-99d-99d")
                document = Document.if_exists(session, DEFAULT_UUID_DOCS)
            except HTTPException:
                raise AssertionError("Could not find expected user/document.")
            session.execute(
                delete(AssocUserDocument).where(
                    AssocUserDocument.id_document == document.id,
                    AssocUserDocument.id_user == user.id,
                )
            )
            session.commit()

        # Expects one grant because DEFAULT_UUID should own this doc.
        # Read grants with api.
        res = await client.read_document(DEFAULT_UUID_DOCS)
        if err := check_status(res, 200):
            raise err
        grants = list(GrantSchema.model_validate(item) for item in res.json())
        assert len(grants) == 1, "Expected one grant."
        initial_grant = grants[0]
        assert initial_grant.uuid_user == DEFAULT_UUID

        # Recreate grants
        res = await client.create(
            DEFAULT_UUID_DOCS,
            ["99d-99d-99d"],
            level=Level.own,  # type: ignore
        )
        if err := check_status(res, 201):
            raise err

        # Check layer one
        event = EventSchema.model_validate_json(res.content)
        check_common(event)
        assert event.uuid_obj == DEFAULT_UUID_DOCS
        assert event.kind_obj == KindObject.document

        # Check layer two
        assert len(event.children) == 1
        event_user, *_ = event.children
        check_common(event_user)

        assert event_user.uuid_obj == "99d-99d-99d"
        assert event_user.kind_obj == KindObject.user

        # Check layer three
        assert len(event_user.children) == 1
        event_assoc, *_ = event_user.children
        check_common(event_assoc)

        uuid_assoc = event_assoc.uuid_obj
        assert event_assoc.kind_obj == KindObject.grant
        assert not len(event_assoc.children)

        # Read again
        res = await client.read_document(DEFAULT_UUID_DOCS)
        if err := check_status(res, 200):
            raise err

        grants = list(GrantSchema.model_validate(item) for item in res.json())
        assert (n := len(grants)) == 2, f"Expected two grants, got `{n}`."

        # POST to test indempotence.
        res = await client.create(DEFAULT_UUID_DOCS, ["99d-99d-99d"])
        if err := check_status(res, 201):
            raise err

        event = EventSchema.model_validate_json(res.content)
        check_common(event)
        assert event.uuid_obj == DEFAULT_UUID_DOCS
        assert event.kind_obj == KindObject.document

        # There should be no child events as no grant should have been created.

    @pytest.mark.asyncio
    async def test_cannot_grant_unowned(
        self, client: GrantRequests, sessionmaker: sessionmaker[Session]
    ):
        """Make sure that a user cannot `POST /grants/documents/<uuid>` unless
        they actually own that particular document."""

    @pytest.mark.asyncio
    async def test_cannot_revoke_other_owner(self, client: GrantRequests):
        """Make sure that a document owner cannot
        `DELETE /grants/documents/<uuid>` another owner of the document."""

    @pytest.mark.asyncio
    async def test_cannot_read_unowned(self, client: GrantRequests):
        """Verify that a user cannot `GET /grants/documents/<uuid>` unless they
        actuall own that document."""

    @pytest.mark.asyncio
    async def test_delete_grant(
        self,
        client: GrantRequests,
        sessionmaker: sessionmaker[Session],
    ):
        def check_common(event):
            assert event.api_origin == "DELETE /grants/documents/<uuid>"
            assert event.uuid_user == DEFAULT_UUID, "Should be token user."
            assert event.kind == KindEvent.grant

        p = await client.read_document(DEFAULT_UUID_DOCS)
        if err := check_status(p, 200):
            raise err

        grants = list(GrantSchema.model_validate(gg) for gg in p.json())
        assert (n_grants_init := len(grants)), "Expected grants."

        # Get initial grant to compare against event.
        initial_grant = next(
            (gg for gg in grants if gg.uuid_user == "99d-99d-99d"), None
        )
        assert (
            initial_grant is not None
        ), "There should be a grant on `aaa-aaa-aaa` for `99d-99d-99d`."

        res = await client.delete(DEFAULT_UUID_DOCS, ["99d-99d-99d"])
        if err := check_status(res):
            raise err

        # Check layer one
        event = EventSchema.model_validate_json(res.content)
        check_common(event)
        assert event.uuid_obj == DEFAULT_UUID_DOCS
        assert event.kind_obj == KindObject.document
        assert event.detail == "Grants revoked."

        # Check layer two
        assert len(event.children) == 1
        event_user, *_ = event.children
        check_common(event_user)

        assert event_user.uuid_obj == "99d-99d-99d"
        assert event_user.kind_obj == KindObject.user
        assert event_user.detail == f"Grant `{initial_grant.level}` revoked."

        # Check layer three
        assert len(event_user.children) == 1
        event_assoc, *_ = event_user.children
        check_common(event_assoc)

        assert event_assoc.uuid_obj == initial_grant.uuid
        assert event_assoc.kind_obj == KindObject.grant
        assert event_assoc.detail == f"Grant `{initial_grant.level}` revoked."
        assert not len(event_assoc.children)

        # Verify with database
        with sessionmaker() as session:
            document = session.execute(
                select(Document).where(Document.uuid == DEFAULT_UUID_DOCS)
            ).scalar()
            assert document is not None
            user = session.execute(
                select(User).where(User.uuid == "99d-99d-99d")
            ).scalar()
            assert user is not None

            assoc = session.execute(
                select(AssocUserDocument).where(
                    AssocUserDocument.id_document == document.id,
                    AssocUserDocument.id_user == user.id,
                )
            ).scalar()
            assert assoc is None

        # Read grants again.
        res = await client.read_document(DEFAULT_UUID_DOCS, [DEFAULT_UUID])
        if err := check_status(res, 200):
            raise err

        grants = [GrantSchema.model_validate(item) for item in res.json()]
        assert len(grants) == n_grants_init - 1, "Expected one less grant."
        grant_final = next((gg for gg in grants if gg.uuid_user == "99d-99d-99d"), None)
        assert (
            grant_final is None
        ), "Expected no grants for `99d-99d-99d` on `aaa-aaa-aaa`."

        res = await client.create(
            DEFAULT_UUID_DOCS,
            [DEFAULT_UUID],
            level=Level.own,  # type: ignore
        )
        if err := check_status(res, 201):
            raise err


class TestAssignmentView(BaseTestViews):
    T = AssignmentRequests

    @classmethod
    def add_assocs(
        cls,
        sessionmaker: sessionmaker[Session],
        deleted=False,
    ) -> List[AssocCollectionDocument]:
        with sessionmaker() as session:
            user = User.if_exists(session, DEFAULT_UUID)
            collection = Collection.if_exists(session, DEFAULT_UUID_COLLECTION)
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
            DEFAULT_UUID_COLLECTION,
            ChildrenCollection.documents,
        )
        if err := check_status(res):
            raise err

        result = res.json()
        assert isinstance(result, list)
        if len(result) != len(assocs):
            raise ValueError(
                "Expected the same number of documents for collection "
                f"`{DEFAULT_UUID_COLLECTION}` as inserted associations."
            )

        # Make sure the number of assignments read is correct.
        res = await requests.assignments.read(DEFAULT_UUID_COLLECTION)
        if err := check_status(res):
            raise err

        result = res.json()
        assert isinstance(result, list)
        assign = list(AssignmentSchema.model_validate(item) for item in result)
        if len(assign) != len(assocs):
            raise ValueError(
                "Expected the same number of documents for collection "
                f"`{DEFAULT_UUID_COLLECTION}` as documents from `GET "
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
        res = await requests.assignments.read(DEFAULT_UUID_COLLECTION)
        if err := check_status(res, 200):
            raise err

        result = res.json()
        assert isinstance(result, list)
        if len(result):
            msg = "Expected no results for assignments staged for deletion."
            raise AssertionError(msg)

        # Verify that the collection does not get documents for assignments
        # staged for deletion.
        res = await requests.collections.read(
            DEFAULT_UUID_COLLECTION,
            ChildrenCollection.documents,
        )
        if err := check_status(res, 200):
            raise err
        elif not isinstance(result := res.json(), list):
            raise AssertionError("Result should be a dict.")
        elif len(result):
            msg = "Expected no results for assignments staged for deletion."
            msg += f"Got `{json.dumps(result)}`."
            raise AssertionError(msg)

    @classmethod
    @checks_event
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
            uuid_user=DEFAULT_UUID,
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
            event_compare(event, expect_common)
        elif request.method == "POST":
            event_compare(event, expect_common)
            expect_common.update(detail="Assignment restored.")
        else:
            expect_common.update(detail="Assignment restored.")
            event_compare(event, expect_common)
        assert event.kind_obj == KindObject.collection
        assert event.uuid_obj == DEFAULT_UUID_COLLECTION

        for item in event.children:
            event_compare(item, expect_common)
            assert len(item.children) == 1
            assert item.kind_obj == KindObject.document
            if uuid_document is not None:
                assert item.uuid_obj in uuid_document

            subitem, *_ = item.children
            event_compare(subitem, expect_common)
            assert len(subitem.children) == 0
            assert subitem.kind_obj == KindObject.assignment
            if uuid_assignment is not None:
                assert subitem.uuid_obj in uuid_assignment

        return event

    @pytest.mark.asyncio
    async def test_post_assignment(
        self, requests: Requests, sessionmaker: sessionmaker[Session]
    ):
        with sessionmaker() as session:
            conds = and_(
                AssocCollectionDocument.id_collection == Collection.id,
                Collection.uuid == DEFAULT_UUID_COLLECTION,
            )
            session.execute(delete(AssocCollectionDocument).where(conds))
            session.commit()

        # There should not be documents or assignments
        res_docs_coll, res_docs_users, res_assign = await asyncio.gather(
            requests.collections.read(
                DEFAULT_UUID_COLLECTION, ChildrenCollection.documents
            ),
            requests.users.read(DEFAULT_UUID, ChildrenUser.documents),
            requests.assignments.read(DEFAULT_UUID_COLLECTION),
        )
        if err := check_status(res_docs_coll, 200):
            raise err
        results = res_docs_coll.json()
        assert isinstance(results, list)  # TODO: Fix return types.
        assert not len(results), "Expected no documents for collection."

        if err := check_status(res_assign, 200):
            raise err
        results = res_assign.json()
        assert isinstance(results, list)
        assert not len(results), "Expected no assingment for collection."

        if err := check_status(res_docs_users, 200):
            raise err
        results = res_docs_users.json()
        assert isinstance(results, dict)
        assert len(results), "Expected documents for user."
        uuid_document = list(results.keys())

        # Post new assignments, assign all user documents to this user.
        res = await requests.assignments.create(
            DEFAULT_UUID_COLLECTION,
            uuid_document,
        )
        if err := check_status(res, 201):
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
            requests.assignments.create(DEFAULT_UUID_COLLECTION, uuid_document),
            requests.assignments.read(DEFAULT_UUID_COLLECTION),
            requests.collections.read(
                DEFAULT_UUID_COLLECTION,
                ChildrenCollection.documents,
            ),
        )
        errs = (e for rr in ress if (e := check_status(rr)) is not None)
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
            DEFAULT_UUID_COLLECTION,
            uuid_document,
        )
        if err := check_status(res, 201):
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
        res = await requests.assignments.read(DEFAULT_UUID_COLLECTION)
        if err := check_status(res, 200):
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
            DEFAULT_UUID_COLLECTION, uuid_document, False
        )
        if err := check_status(res, 200):
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
                DEFAULT_UUID_COLLECTION,
                uuid_document,
            ),
            requests.assignments.read(DEFAULT_UUID_COLLECTION),
            requests.collections.read(
                DEFAULT_UUID_COLLECTION, ChildrenCollection.documents
            ),
        )
        if err := check_status(res):
            raise err

        event = EventSchema.model_validate_json(res.content)
        event, err = self.check_event(
            res, uuid_document=uuid_document, uuid_assignment=uuid_assignment
        )
        if err is not None:
            raise err
        assert len(event.children) == 0

        # Verify assignments cannot be read.
        if err := check_status(res_assign, 200):
            raise err

        assert not len(res_assign.json())

        if err := check_status(res_collection, 200):
            raise err

        assert not len(res_collection.json())

        # Restore assignments
        res = await requests.assignments.delete(
            DEFAULT_UUID_COLLECTION, uuid_document, restore=True
        )
        if err := check_status(res, 200):
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
                DEFAULT_UUID_COLLECTION,
                ChildrenCollection.documents,
            ),
            requests.assignments.read(DEFAULT_UUID_COLLECTION),
        )

        if err := check_status(res_collection, 200):
            raise err
        elif err := check_status(res_assign, 200):
            raise err

        assert len(res_collection.json()) == n
        assert len(res_collection.json()) == n


class TestCollectionView(BaseTestViews):
    T = CollectionRequests

    @pytest.fixture
    def client_user(self, client: CollectionRequests) -> UserRequests:
        return UserRequests.from_(client)

    @pytest.mark.asyncio
    async def test_read_collection(self, client: CollectionRequests):
        """General test of `GET /collection/<uuid>`."""

        # Read some collections.
        res = await client.read(DEFAULT_UUID_COLLECTION)
        if err := check_status(res, 200):
            raise err

        data = res.json()
        assert isinstance(data, dict)
        collection = CollectionSchema.model_validate(data)
        assert collection.uuid == DEFAULT_UUID_COLLECTION

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
            collection = Collection.if_exists(session, DEFAULT_UUID_COLLECTION)
            collection.deleted = False
            session.add(collection)
            session.commit()

            res = await client.read(DEFAULT_UUID_COLLECTION)
            if err := check_status(res, 200):
                raise err

            data = res.json()
            assert isinstance(data, dict)
            CollectionSchema.model_validate(data)

            # Stage collection for deletion
            collection.deleted = True
            res = await client.read(DEFAULT_UUID_COLLECTION)
            if err := check_status(res, 404):
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
            user = User.if_exists(session, DEFAULT_UUID)
            collection = Collection.if_exists(session, DEFAULT_UUID_COLLECTION)
            collection.user = user
            collection.public = False
            session.add(collection)
            session.commit()

            res = await client.read(DEFAULT_UUID_COLLECTION)
            if err := check_status(res, 200):
                raise err
            data = res.json()
            assert isinstance(data, dict)

            # Assign the default collection to a new user and make it private.
            user_new = User.if_exists(session, DEFAULT_UUID)
            collection.user = user_new
            session.add(collection)
            session.commit()

            res = await client.read(DEFAULT_UUID_COLLECTION)
            if err := check_status(res, 403):
                raise err

            # Make default collection public again.
            # Leave it with the other user.
            collection.public = True
            session.add(collection)
            session.commit()

            res = await client.read(DEFAULT_UUID_COLLECTION)
            if err := check_status(res, 200):
                raise err
            data = res.json()
            assert isinstance(data, dict)

            collection.user = user
            session.add(collection)
            session.commit()

    @classmethod
    @checks_event
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
            uuid_user=DEFAULT_UUID,
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
                    detail="Collection created`.",
                    api_origin=f"POST {url}/<uuid>",
                )
            case HTTPMethod.PATCH:
                event_expected.update(
                    kind=KindEvent.update,
                    detail="Collection updated.",
                    api_origin=f"PATCH {url}/<uuid>.",
                )
            case _:
                raise ValueError(f"Unexpected method `{request.method}`.")

        event_compare(event, event_expected)
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
            if err := check_status(res, 200):
                raise err
            data = res.json()
            assert isinstance(data, list)
            assert len(data) == len(event.children)

        collections_created_uuids: List[str] = list()
        with sessionmaker() as session:
            user = User.if_exists(session, DEFAULT_UUID)
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
        if err := check_status(res, 201):
            raise err

        with sessionmaker() as session:
            uuid_assignment = list(
                session.execute(
                    select(AssocCollectionDocument.uuid)
                    .join(Collection)
                    .where(
                        Collection.uuid == DEFAULT_UUID_COLLECTION,
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
        if err := check_status(res, 201):
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
            if err := check_status(res, 201):
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
            if err := check_status(res, 201):
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
                DEFAULT_UUID,
                ChildrenUser.collections,
                collections_created_uuids,
            )
            if err := check_status(res, 200):
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
                DEFAULT_UUID,
                ChildrenUser.collections,
                collections_created_uuids,
            )
            if err := check_status(res, 200):
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
            if err := check_status(res, 201):
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
                if err := check_status(res, 200):
                    raise err
                data = res.json()
                assert len(data) == expect

                res = await client.read(event.uuid_obj)
                if err := check_status(res, 200 if expect else 404):
                    raise err

            # NOTE: Act like user `000-000-000` so that access controllers are
            #       used.
            client.token = auth.encode({"uuid": DEFAULT_UUID})
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

        uuid_collection = DEFAULT_UUID_COLLECTION

        # Add some documents.
        res_docs = await requests.users.read(DEFAULT_UUID, ChildrenUser.documents)
        if err := check_status(res_docs, 200):
            raise err

        assert isinstance(data := res_docs.json(), dict)
        assert len(data), "Expected documents for user."
        uuid_document = list(data.keys())
        assert len(uuid_document)

        res_assign = await requests.assignments.create(uuid_collection, uuid_document)
        if err := check_status(res_assign):
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
        if err := check_status(res, 200):
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
        if err := check_status(res, 200):
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
        if err := check_status((res, res_assign), 404):
            raise err

        # BONUS: Cannot reactivate assignments directly
        res_assign = await requests.assignments.create(
            uuid_collection,
            uuid_document,
        )
        if err := check_status(res_assign, 404):
            raise err

        # Restore
        res = await requests.collections.delete(uuid_collection, restore=True)
        if err := check_status(res):
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
        if err := check_status((res, res_assign), 200):
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
        uuid_collection = DEFAULT_UUID_COLLECTION

        # Make a collection public and change its name
        res = await requests.collections.update(
            uuid_collection,
            name=(name := "Test `PATCH /collection`."),
            public=True,
        )
        if err := check_status(res, 200):
            raise err

        fields = {"public", "name"}
        common = dict(
            kind_obj=KindObject.collection,
            api_origin="PATCH /cofllection",
            uuid_obj=DEFAULT_UUID_COLLECTION,
            uuid_user=DEFAULT_UUID,
            detail="Collection updated",
        )
        event, err = check_event_update(None, res, fields, **common)
        if err := check_status(res, 200):
            raise err
        assert len(event.children) == 2

        res = await requests.collections.read(uuid_collection)
        if err := check_status(res, 200):
            raise err
        collection = CollectionSchema.model_validate_json(res.content)
        assert collection.name == name
        assert collection.public == True

        # Transfer ownership
        uuid_user = "99d-99d-99d"
        res = await requests.collections.update(
            uuid_collection, uuid_user=uuid_user, public=False
        )
        if (err := check_status(res)) is not None:
            raise err

        event, err = check_event_update(None, res, fields, **common)
        if err is not None:
            raise err

        # Verify readability.
        res = await requests.collections.read(uuid_collection)
        if err := check_status(res, 403):
            raise err

        requests.update_token(auth.encode({"uuid": "99d-99d-99d"}))

        res = await requests.collections.read(uuid_collection)
        if err := check_status(res):
            raise err

    @pytest.mark.asyncio
    async def test_patch_collection_access(self, client: CollectionRequests):
        """Users should only be able to update their own collections with
        `PATCH /collection/<uuid>`. They should not be able to update
        universal (userless) collections either."""
        ...
