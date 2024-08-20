# =========================================================================== #
import asyncio
from http import HTTPMethod
from typing import Any, Dict, List

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import delete, literal_column, select
from sqlalchemy.orm import Session, make_transient, sessionmaker

# --------------------------------------------------------------------------- #
from captura import __version__, util
from captura.auth import Auth
from captura.models import (
    AssocUserDocument,
    ChildrenUser,
    Document,
    KindEvent,
    KindObject,
    Level,
    User,
)
from captura.schemas import DocumentSchema, EventSchema, GrantSchema
from legere.requests import GrantRequests, Requests

from . import util

# NOTE: The `requests` fixture must exist in module scope directly.
from .util import BaseTestViews


class TestGrantView(BaseTestViews):
    T = GrantRequests

    @classmethod
    @util.checks_event
    def check_event(
        cls,
        response: httpx.Response,
        *,
        level: Level,
        uuid_document: str,
        uuid_user: List[str] | None,
        uuid_grant: List[str] | None,
        restore: bool = False,
        event: EventSchema | None = None,
        **overwrite,
    ) -> EventSchema:
        request = response.request
        event = event or EventSchema.model_validate_json(response.content)
        expect_common: Dict[str, Any] = dict(
            api_version=__version__,
            uuid_user=util.DEFAULT_UUID,
            kind_obj=KindObject.assignment,
        )

        match [request.method]:
            case [HTTPMethod.POST]:
                expect_common.update(
                    api_origin="POST /grants/documents/<uuid>",
                    detail="Grants issued.",
                    kind=KindEvent.grant,
                )
            case [HTTPMethod.DELETE]:
                expect_common.update(
                    api_origin="DELETE /grants/documents/<uuid>",
                    detail="Grants revoked.",
                    kind=KindEvent.grant,
                )
            case _:
                raise ValueError(f"Unexpected method `{request.method}`.")

        expect_common.update(overwrite)

        # if not restore:
        #     util.event_compare(event, expect_common)
        # elif request.method == "POST":
        #     util.event_compare(event, expect_common)
        #     expect_common.update(detail="Grant restored.")
        # else:
        #     expect_common.update(detail="Grant.")
        #     util.event_compare(event, expect_common)

        util.event_compare(event, expect_common)
        assert event.kind_obj == KindObject.document
        assert event.uuid_obj == uuid_document

        detail = expect_common["detail"].replace(" ", f" `{level.name}` ")
        detail = detail.replace("Grants", "Grant")
        expect_common["detail"] = detail

        for item in event.children:
            util.event_compare(item, expect_common)
            assert len(item.children) == 1
            assert item.kind_obj == KindObject.user
            if uuid_user is not None:
                assert item.uuid_obj in uuid_user, "Unexpected grantee id."

            subitem, *_ = item.children
            util.event_compare(subitem, expect_common)
            assert len(subitem.children) == 0
            assert subitem.kind_obj == KindObject.grant
            if uuid_grant is not None:
                assert subitem.uuid_obj in uuid_grant

        return event

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
        uuid_user, uuid_grantee = util.DEFAULT_UUID, ["99d-99d-99d"]
        uuid_document = util.DEFAULT_UUID_DOCS

        # Manually remove existing grants.
        with sessionmaker() as session:
            try:
                user = User.if_exists(session, "99d-99d-99d")
                document = Document.if_exists(session, uuid_document)
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
        res = await client.read_document(uuid_document)
        if err := util.check_status(res, 200):
            raise err
        grants = list(GrantSchema.model_validate(item) for item in res.json())
        assert len(grants) == 1, "Expected one grant."
        initial_grant = grants[0]
        assert initial_grant.uuid_user == uuid_user
        uuid_grant = [initial_grant.uuid]

        # Recreate grants
        res = await client.create(uuid_document, uuid_grantee, level=Level.own)
        if err := util.check_status(res, 201):
            raise err

        res_read = await client.read_document(uuid_document, uuid_grantee)
        if err := util.check_status(res_read, 200):
            raise err
        grants = list(GrantSchema.model_validate(item) for item in res_read.json())
        assert len(grants) == 1, "Expected one grant."
        grant = grants[0]
        assert grant.uuid_document == uuid_document
        assert grant.uuid_user in uuid_grantee
        assert grant.level == Level.own
        uuid_grant.append(grant.uuid)

        check_event_args: Dict[str, Any] = dict(
            level=Level.own,
            uuid_document=uuid_document,
            uuid_user=uuid_grantee,
            uuid_grant=uuid_grant,
        )
        event, err = self.check_event(res, **check_event_args)
        if err:
            raise err
        assert len(event.children) == 1

        # POST to test indempotence.
        res = await client.create(util.DEFAULT_UUID_DOCS, ["99d-99d-99d"])
        if err := util.check_status(res, 201):
            raise err

        event, err = self.check_event(res, **check_event_args)
        if err:
            raise err
        assert len(event.children) == 0

    @pytest.mark.asyncio
    async def test_delete_grant(
        self, requests: Requests, sessionmaker: sessionmaker[Session], auth: Auth
    ):
        uuid_document = util.DEFAULT_UUID_DOCS
        uuid_user = util.DEFAULT_UUID
        uuid_grantee = "99d-99d-99d"

        # Delete existing grants for document and verify that cannot be read
        # here or from the users endpoint.
        with sessionmaker() as session:
            document = Document.if_exists(session, uuid_document)
            document.public = False  # Verify important for visibility tests.
            session.add(document)
            session.commit()

            q_uuid_assignment = select(literal_column("uuid")).select_from(
                document.q_select_grants()
            )
            session.execute(
                delete(AssocUserDocument).where(
                    AssocUserDocument.uuid.in_(q_uuid_assignment)
                )
            )
            session.commit()

        res, res_documents, res_users = await asyncio.gather(
            requests.grants.read_document(uuid_document, [uuid_grantee, uuid_user]),
            requests.documents.read(uuid_document),
            requests.users.read(
                uuid_grantee,
                ChildrenUser.documents,
                [uuid_document],
            ),
        )
        if err := util.check_status((res, res_documents), 403):
            raise err
        elif err := util.check_status(res_users):
            raise err

        assert not len(
            res_users.json()
        ), f"No content should exist for document `{uuid_document}`."

        # Recreate the grant directly. Verify visibility
        with sessionmaker() as session:
            document = Document.if_exists(session, uuid_document)
            session.add(
                AssocUserDocument(
                    id_document=document.id,
                    id_user=User.if_exists(session, uuid_user).id,
                    level=Level.own,
                )
            )
            session.commit()

        res, res_documents = await asyncio.gather(
            requests.grants.read_document(uuid_document),
            requests.documents.read(uuid_document),
        )
        if err := util.check_status((res_documents, res), 200):
            raise err

        assert len(res.json()) == 1, "Expected one grant."

        # Create and verify.
        res = await requests.grants.create(
            uuid_document, uuid_user=[uuid_grantee], level=Level.modify
        )
        if err := util.check_status(res):
            raise err

        with sessionmaker() as session:
            document = Document.if_exists(session, uuid_document)
            q_uuid_grant = document.q_select_grants({uuid_grantee})
            uuid_grant = list(session.execute(q_uuid_grant).scalars())
            assert len(uuid_grant) == 1, "Expected one grant."

        check_event_args: Dict[str, Any] = dict(
            level=Level.modify,
            uuid_document=uuid_document,
            uuid_user=[uuid_grantee],
            uuid_grant=uuid_grant,
        )
        event, err = self.check_event(res, **check_event_args)
        if err:
            raise err
        assert len(event.children) == 1
        assert event.children[0].children[0].uuid_obj in uuid_grant

        res = await requests.grants.read_document(uuid_document)
        if err := util.check_status(res):
            raise err

        grants = list(GrantSchema.model_validate(gg) for gg in res.json())
        assert len(grants) == 2, "Expected two grants."

        (initial_grant,) = (item for item in grants if item.uuid_user == uuid_grantee)
        assert initial_grant.uuid_document == document.uuid
        assert initial_grant.uuid_user == uuid_grantee
        assert initial_grant.level == Level.modify

        # Verify visibility as grantee.
        requests.update_token(auth.encode(dict(uuid=uuid_grantee)))
        res, res_grants, res_docs, res_users = await asyncio.gather(
            requests.grants.read_document(uuid_document),
            requests.grants.read_user(uuid_grantee, uuid_document=[uuid_document]),
            requests.documents.read(uuid_document),
            requests.users.read(
                uuid_user,
                ChildrenUser.documents,
                [uuid_document],
            ),
        )
        if err := util.check_status((res_grants, res_docs, res_users)):
            raise err

        grants_found = res_grants.json()
        assert len(grants_found) == 1
        gg = GrantSchema.model_validate(grants_found[0])
        assert gg.uuid_document == uuid_document
        assert gg.uuid_user == uuid_grantee
        assert gg.uuid in uuid_grant

        if err := util.check_status(res, 403):
            raise err

        # NOTE: User with grant level `modify` should not be able to read
        #       grants. A user must have grant level `owner`.
        document = DocumentSchema.model_validate_json(res_docs.content)
        assert document.uuid == uuid_document

        # NOTE: Return to default user.
        requests.update_token(auth.encode(dict(uuid=uuid_user)))

        # Delete
        res = await requests.grants.delete(uuid_document, ["99d-99d-99d"])
        if err := util.check_status(res):
            raise err

        event, err = self.check_event(res, **check_event_args)
        if err:
            raise err
        assert len(event.children) == 1
        assert event.children[0].children[0].uuid_obj in uuid_grant

        # Delete again.
        res = await requests.grants.delete(uuid_document, ["99d-99d-99d"])
        if err := util.check_status(res):
            raise err

        event, err = self.check_event(res, **check_event_args)
        if err:
            raise err
        assert len(event.children) == 0

        # Read grants as revokee.
        requests.update_token(auth.encode(dict(uuid=uuid_grantee)))
        res, res_documents = await asyncio.gather(
            requests.grants.read_document(uuid_document),
            requests.documents.read(uuid_document),
        )
        if err := util.check_status((res, res_documents), 403):
            raise err

        # Read grants as revoker
        requests.update_token(auth.encode(dict(uuid=uuid_user)))
        res = await requests.grants.read_document(uuid_document)
        if err := util.check_status(res, 200):
            raise err

        grants = [GrantSchema.model_validate(item) for item in res.json()]
        assert len(grants) == 1, "Expected one grant."
        assert not any(gg.uuid_user == "99d-99d-99d" for gg in grants)

        # Restore
        # res = await requests.grants.delete(uuid_document, ["99d-99d-99d"], restore =True)
        # if err := util.check_status(res):
        #     raise err

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
