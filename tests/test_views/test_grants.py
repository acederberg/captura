import pytest
from app import __version__, util
from app.models import (
    AssocUserDocument,
    Document,
    KindEvent,
    Level,
    KindObject,
    User,
)
from app.schemas import (
    EventSchema,
    GrantSchema,
)
from client.requests import (
    GrantRequests,
)
from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, make_transient, sessionmaker

from . import util

# NOTE: The `requests` fixture must exist in module scope directly.
from .util import requests, BaseTestViews


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
        if err := util.check_status(res, 200):
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
        if err := util.check_status(res, 403):
            raise err
        assert res.json()["detail"] == dict(msg="Users can only read their own grants.")

    @pytest.mark.asyncio
    async def test_read_grants_document(
        self,
        client: GrantRequests,
        sessionmaker: sessionmaker[Session],
    ):
        res = await client.read_document(util.DEFAULT_UUID_DOCS)
        if err := util.check_status(res, 200):
            raise err

        with sessionmaker() as session:
            user = session.execute(
                select(User).where(User.uuid == util.DEFAULT_UUID)
            ).scalar()
            assert user is not None
            assoc = session.execute(
                select(AssocUserDocument).where(
                    AssocUserDocument.id_user == user.id,
                    AssocUserDocument.id_document.in_(
                        select(Document.id).where(
                            Document.uuid == util.DEFAULT_UUID_DOCS,
                        )
                    ),
                )
            ).scalar()
            assert assoc is not None
            assert assoc.level == Level.own

            assoc.level = Level.view
            session.add(assoc)
            session.commit()

            res = await client.read_document(util.DEFAULT_UUID_DOCS)
            if err := util.check_status(res, 403):
                raise err

            result = res.json()["detail"]
            assert result["msg"] == "User must have grant of level `own`."

            session.delete(assoc)
            session.commit()

            res = await client.read_document(util.DEFAULT_UUID_DOCS)
            if err := util.check_status(res, 403):
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
            assert event.uuid_user == util.DEFAULT_UUID, "Should be token user."
            assert event.detail == "Grants issued."
            assert event.kind == KindEvent.grant

        # Manually remove existing grants.
        with sessionmaker() as session:
            try:
                user = User.if_exists(session, "99d-99d-99d")
                document = Document.if_exists(session, util.DEFAULT_UUID_DOCS)
            except HTTPException:
                raise AssertionError("Could not find expected user/document.")
            session.execute(
                delete(AssocUserDocument).where(
                    AssocUserDocument.id_document == document.id,
                    AssocUserDocument.id_user == user.id,
                )
            )
            session.commit()

        # Expects one grant because util.DEFAULT_UUID should own this doc.
        # Read grants with api.
        res = await client.read_document(util.DEFAULT_UUID_DOCS)
        if err := util.check_status(res, 200):
            raise err
        grants = list(GrantSchema.model_validate(item) for item in res.json())
        assert len(grants) == 1, "Expected one grant."
        initial_grant = grants[0]
        assert initial_grant.uuid_user == util.DEFAULT_UUID

        # Recreate grants
        res = await client.create(
            util.DEFAULT_UUID_DOCS,
            ["99d-99d-99d"],
            level=Level.own,  # type: ignore
        )
        if err := util.check_status(res, 201):
            raise err

        # Check layer one
        event = EventSchema.model_validate_json(res.content)
        check_common(event)
        assert event.uuid_obj == util.DEFAULT_UUID_DOCS
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
        res = await client.read_document(util.DEFAULT_UUID_DOCS)
        if err := util.check_status(res, 200):
            raise err

        grants = list(GrantSchema.model_validate(item) for item in res.json())
        assert (n := len(grants)) == 2, f"Expected two grants, got `{n}`."

        # POST to test indempotence.
        res = await client.create(util.DEFAULT_UUID_DOCS, ["99d-99d-99d"])
        if err := util.check_status(res, 201):
            raise err

        event = EventSchema.model_validate_json(res.content)
        check_common(event)
        assert event.uuid_obj == util.DEFAULT_UUID_DOCS
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
            assert event.uuid_user == util.DEFAULT_UUID, "Should be token user."
            assert event.kind == KindEvent.grant

        p = await client.read_document(util.DEFAULT_UUID_DOCS)
        if err := util.check_status(p, 200):
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

        res = await client.delete(util.DEFAULT_UUID_DOCS, ["99d-99d-99d"])
        if err := util.check_status(res):
            raise err

        # Check layer one
        event = EventSchema.model_validate_json(res.content)
        check_common(event)
        assert event.uuid_obj == util.DEFAULT_UUID_DOCS
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
                select(Document).where(Document.uuid == util.DEFAULT_UUID_DOCS)
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
        res = await client.read_document(util.DEFAULT_UUID_DOCS, [util.DEFAULT_UUID])
        if err := util.check_status(res, 200):
            raise err

        grants = [GrantSchema.model_validate(item) for item in res.json()]
        assert len(grants) == n_grants_init - 1, "Expected one less grant."
        grant_final = next((gg for gg in grants if gg.uuid_user == "99d-99d-99d"), None)
        assert (
            grant_final is None
        ), "Expected no grants for `99d-99d-99d` on `aaa-aaa-aaa`."

        res = await client.create(
            util.DEFAULT_UUID_DOCS,
            [util.DEFAULT_UUID],
            level=Level.own,  # type: ignore
        )
        if err := util.check_status(res, 201):
            raise err
