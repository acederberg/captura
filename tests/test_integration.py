# =========================================================================== #
import asyncio
import secrets
from random import choice, choices, randint, random
from typing import Any, Dict, List

import httpx
import pytest
import pytest_asyncio
import typer
from fastapi import FastAPI
from pydantic import TypeAdapter
from sqlalchemy import update
from sqlalchemy.orm import sessionmaker as sessionmaker_

# --------------------------------------------------------------------------- #
from app.auth import Auth, Token, TokenPermissionTier
from app.err import ErrAssocRequestMustForce, ErrDetail
from app.fields import ChildrenUser, KindObject, Level, LevelStr
from app.models import Grant
from app.schemas import (
    AsOutput,
    AssignmentSchema,
    DocumentSchema,
    GrantSchema,
    OutputWithEvents,
    UserSchema,
    mwargs,
)
from client import Requests
from client.config import ProfileConfig
from client.handlers import AssertionHandler, ConsoleHandler
from client.requests.base import ContextData
from tests.config import PytestClientConfig


@pytest_asyncio.fixture
async def rr(app: FastAPI | None, client_config: PytestClientConfig, auth: Auth):
    """Requests client with built in assertions."""

    # NOTE: Somehow create a token client
    uuid = "000-000-000"
    client_config = client_config.model_copy()
    client_config.profiles.update(
        {
            uuid: mwargs(
                ProfileConfig,
                uuid_user=uuid,
                token=auth.encode(dict(uuid=uuid, permissions=["tier:admin"])),
            )
        }
    )
    client_config.use.profile = uuid

    async with httpx.AsyncClient(app=app) as client:
        requests = Requests(
            ContextData(
                openapi=False,
                config=client_config,
                console_handler=ConsoleHandler(client_config),
            ),
            client,
            handler=AssertionHandler(client_config),
        )

        yield requests


@pytest.mark.skip
@pytest.mark.asyncio
async def test_from_nothing(rr: Requests, auth: Auth, sessionmaker: sessionmaker_):
    """Something like requests that might be recieved from a browser client."""

    # ----------------------------------------------------------------------- #
    # As Admin

    hd = await rr.send(
        rr.u.req_create(
            rr.context_wrapped,
            name="test_from_nothing",
            description="test_from_nothing",
            email=f"test{secrets.token_urlsafe()}@example.com",
        ),
        adapter=TypeAdapter(OutputWithEvents[UserSchema]),
    )
    assert isinstance(hd.data, OutputWithEvents)
    assert isinstance(hd.data.data, UserSchema)
    assert hd.expect_status == 201

    uuid_user = hd.data.data.uuid
    ctx, adapter = rr.context_wrapped, TypeAdapter(AsOutput[UserSchema])
    hd = await rr.send(
        rr.u.req_read(ctx, uuid_user),
        adapter=adapter,
    )
    assert hd.expect_status == 200
    assert isinstance(hd.data, AsOutput)
    assert isinstance(hd.data.data, UserSchema)

    token = mwargs(Token, uuid=uuid_user, tier=TokenPermissionTier.paid)
    profile_config = mwargs(
        ProfileConfig, uuid_user=uuid_user, token=token.encode(auth)
    )
    rr.context.config.profiles.update({uuid_user: profile_config})
    rr.context.config.use.profile = uuid_user
    assert rr.context.config.profile is not None
    assert rr.context.config.profile.uuid_user == uuid_user

    # ----------------------------------------------------------------------- #
    # As Created Profile

    # NOTE: Verify and update profile.
    await rr.users.read(uuid_user)

    name_user = f"test_from_nothing_{secrets.token_urlsafe()}"
    req = rr.u.req_update(ctx, uuid_user, name=name_user)
    hd = await rr.send(req, adapter=adapter)
    assert hd.expect_status == 200
    assert hd.data.data.uuid == uuid_user
    assert hd.data.data.name == name_user

    req = rr.users.req_read(ctx, uuid_user)
    hd = await rr.send(req, adapter=adapter)
    assert hd.expect_status == 200
    assert hd.data.data.uuid == uuid_user
    assert hd.data.data.name == name_user

    # NOTE: Try to update somebody elses user.
    await rr.gather(
        rr.u.req_update(ctx, "000-000-000", name="acederberg"),
        rr.u.req_delete(ctx, "000-000-000"),
        expect_status=403,
    )

    # NOTE: Create a few collectons and documents
    hds = await rr.gather(
        *(
            mk(
                ctx,
                name=f"test_from_nothing_{secrets.token_urlsafe()}",
                description=f"Collection of `{uuid_user}`.",
                public=False,
            )
            for mk in (rr.d.req_create, rr.c.req_create)
            for _ in range(5)
        ),
    )

    uuid_collections = list(
        hd.data["data"]["uuid"] for hd in hds if hd.data["kind"] == "collections"
    )
    assert len(uuid_collections) == 5

    uuid_documents = list(
        hd.data["data"]["uuid"] for hd in hds if hd.data["kind"] == "documents"
    )
    assert len(uuid_documents) == 5

    hd_collections, hd_documents = await rr.gather(
        rr.users.req_search(
            ctx, uuid_user, child=ChildrenUser.collections, uuids=uuid_collections
        ),
        rr.users.req_search(
            ctx, uuid_user, child=ChildrenUser.documents, uuids=uuid_documents
        ),
    )
    assert len(hd_collections.data["data"]) == 5
    assert len(hd_documents.data["data"]) == 5

    # ----------------------------------------------------------------------- #
    # NOTE: Assign documents to collections via collections.
    hds = await rr.gather(
        *(
            rr.a.c.req_create(ctx, uuid, uuid_document=uuid_documents)
            for uuid in uuid_collections
        ),
        adapter=TypeAdapter(OutputWithEvents[List[AssignmentSchema]]),
    )

    assert len(hds) == 5
    assert all(
        isinstance(hd.data, OutputWithEvents)
        and isinstance(hd.data.data, list)
        and len(hd.data.data) == 5
        for hd in hds
    )
    n_assignments = sum(len(hd.data.data) for hd in hds)
    assert n_assignments == 25
    uuid_assignments = set(item.uuid for hd in hds for item in hd.data.data)

    # NOTE: Read assignments via documents.
    hds = await rr.gather(
        *(rr.a.d.req_read(ctx, uuid) for uuid in uuid_documents),
        adapter=TypeAdapter(AsOutput[List[AssignmentSchema]]),
    )
    assert len(hds) == 5
    assert all(
        isinstance(hd.data, AsOutput)
        and isinstance(hd.data.data, list)
        and len(hd.data.data) == 5
        for hd in hds
    )
    assert n_assignments == sum(len(hd.data.data) for hd in hds)
    assert all(item.uuid in uuid_assignments for hd in hds for item in hd.data.data)

    # NOTE: Delete assignments via documents
    reqs = (
        rr.a.d.req_delete(ctx, uuid, uuid_collection=uuid_collections)
        for uuid in uuid_documents
    )
    hd = await rr.gather(*reqs)

    # NOTE: Now read assignments via collections. There should be none left.
    reqs = (rr.a.d.req_read(ctx, uuid) for uuid in uuid_documents)
    hds = await rr.gather(*reqs, adapter=TypeAdapter(AsOutput[List[AssignmentSchema]]))
    assert all(hd.data.kind is None for hd in hds)
    assert sum(len(hd.data.data) for hd in hds) == 0

    # NOTE: Create assignments via collection
    hds = await rr.gather(
        *(
            rr.a.c.req_create(
                ctx, uuid, uuid_document=choices(uuid_documents, k=randint(1, 5))
            )
            for uuid in uuid_collections
        ),
        adapter=TypeAdapter(OutputWithEvents[List[AssignmentSchema]]),
    )
    assert len(hds) == 5
    assert all(
        isinstance(hd.data, OutputWithEvents)
        and isinstance(hd.data.data, list)
        and len(hd.data.data) > 0
        for hd in hds
    )

    # ----------------------------------------------------------------------- #
    # NOTE: Invite other users to documents.

    req = rr.u.req_search(ctx, uuid_user, limit=10)
    hd = await rr.send(req, adapter=TypeAdapter(AsOutput[List[UserSchema]]))
    assert isinstance(hd.data, AsOutput)
    assert isinstance(hd.data.data, list)
    assert all(isinstance(item, UserSchema) for item in hd.data.data)
    uuid_user = list(item.uuid for item in hd.data.data)

    kwargs: Dict[str, Any] = dict(level=LevelStr.view, uuid_user=uuid_user)
    req = (rr.g.d.req_invite(ctx, uuid, **kwargs) for uuid in uuid_documents)
    hds = await rr.gather(*req, adapter=OutputWithEvents[List[GrantSchema]])

    # NOTE: Read nonpending grants. On this read no data.
    kwargs.update(pending=False)
    hds = await rr.gather(
        *(rr.g.d.req_read(ctx, uuid, **kwargs) for uuid in uuid_documents),
        adapter=AsOutput[List[GrantSchema]],
    )
    assert all(isinstance(hd, AsOutput) and hd.data.kind == None for hd in hds)

    # NOTE: Read pending grants.
    kwargs.update(pending=True)
    hds = await rr.gather(
        *(rr.g.d.req_read(ctx, uuid, **kwargs) for uuid in uuid_documents),
        adapter=AsOutput[List[GrantSchema]],
    )

    assert all(
        isinstance(hd, AsOutput)
        and hd.data.kind == KindObject.grant
        and len(hd.data.data) == len(uuid_user)
        for hd in hds
    )
    assert hd.data.kind == KindObject.grant
    uuid_grants = list(item.uuid for hd in hds for item in hd.data.data)

    # NOTE: Make grants no longer pending.
    with sessionmaker() as session:
        q = update(Grant).values(pending=False).where(Grant.uuid.in_(uuid_grants))
        session.execute(q)
        session.commit()

    # NOTE: Read pending grants. There should now be none.
    hds = await rr.gather(
        *(rr.g.d.req_read(ctx, uuid, **kwargs) for uuid in uuid_documents),
        adapter=AsOutput[List[GrantSchema]],
    )
    assert all(isinstance(hd, AsOutput) and hd.kind is None for hd in hds)


@pytest.mark.asyncio
async def test_force(rr: Requests, sessionmaker: sessionmaker_):

    uuid_user = "000-000-000"
    (rr.context).config.use.profile = uuid_user
    assert rr.context.config.profile.uuid_user == uuid_user

    ctx = rr.context_wrapped

    # ----------------------------------------------------------------------- #
    # Grant cases.

    # NOTE: Read some users to create grants for.
    hd = await rr.send(
        rr.users.req_search(ctx, uuid_user=uuid_user, limit=5, randomize=True),
        adapter=AsOutput[list[UserSchema]],
    )
    uuid_user = [item.uuid for item in hd.data.data if item.uuid != uuid_user]
    assert (n_users := len(uuid_user)) > 0

    hd = await rr.send(
        rr.d.req_create(ctx, name="test_force", description="test_force"),
        adapter=AsOutput[DocumentSchema],
    )
    assert isinstance(hd.data, AsOutput)
    assert isinstance(hd.data.data, DocumentSchema)
    assert hd.data.data.name == "test_force" == hd.data.data.description
    uuid_document = hd.data.data.uuid

    # NOTE: Read own grant
    req = rr.d.g.req_read(ctx, uuid_document)
    hd = await rr.send(req, adapter=AsOutput[List[GrantSchema]])
    assert isinstance(hd.data, AsOutput) and isinstance(hd.data.data, list)
    assert hd.data.kind == KindObject.grant
    assert len(hd.data.data) == 1

    # NOTE: Ensure exists by read and add grants.
    await rr.send(rr.d.req_read(ctx, uuid_document))
    req_create = rr.d.g.req_invite(ctx, uuid_document, uuid_user=uuid_user)
    hd = await rr.send(req_create, adapter=AsOutput[List[GrantSchema]])
    assert isinstance(hd.data, AsOutput) and isinstance(hd.data.data, list)
    assert all(isinstance(item, GrantSchema) for item in hd.data.data)
    uuid_grants = list(item.uuid for item in hd.data.data)

    assert len(uuid_grants) == n_users

    # NOTE: Read new grants.
    kwargs: Dict[str, Any] = dict(uuid_user=uuid_user, pending=False)
    req = rr.d.g.req_read(ctx, uuid_document, **kwargs)
    hd = await rr.send(req, adapter=AsOutput[List[GrantSchema]])
    assert isinstance(hd.data, AsOutput)
    assert hd.data.kind is None

    kwargs["pending"] = True
    req = rr.d.g.req_read(ctx, uuid_document, **kwargs)
    hd = await rr.send(req, adapter=AsOutput[List[GrantSchema]])
    assert isinstance(hd.data, AsOutput) and isinstance(hd.data.data, list)
    assert hd.data.kind == KindObject.grant
    assert len(hd.data.data) == n_users
    assert all(item.uuid in uuid_grants for item in hd.data.data)

    # NOTE: Move grants out of pending state. Re-read
    with sessionmaker() as session:
        q = update(Grant).values(pending=False).where(Grant.uuid.in_(uuid_grants))
        session.execute(q)
        session.commit()

    kwargs.update(pending=False)
    req = rr.d.g.req_read(ctx, uuid_document, **kwargs)
    hd = await rr.send(req, adapter=AsOutput[List[GrantSchema]])
    assert all(item.uuid in uuid_grants for item in hd.data.data)
    assert len(hd.data.data) == len(uuid_grants)

    # NOTE: Indempotent to create. Then destroy.
    hd = await rr.send(req_create, adapter=AsOutput[List[GrantSchema]])
    assert isinstance(hd.data, AsOutput) and isinstance(hd.data.data, list)
    assert hd.data.kind is None and not len(hd.data.data)

    req = rr.g.d.req_revoke(ctx, uuid_document, uuid_user=uuid_user)
    hd = await rr.send(req, adapter=OutputWithEvents[List[GrantSchema]])
    assert isinstance(hd.data, OutputWithEvents) and isinstance(hd.data.data, list)
    assert hd.data.kind == KindObject.grant and len(hd.data.data) == n_users

    # NOTE: Read to verify is in deleted state.
    req = rr.g.d.req_read(ctx, uuid_document, **kwargs)
    hd = await rr.send(req, adapter=AsOutput[List[GrantSchema]])
    assert isinstance(hd.data, AsOutput)
    assert isinstance(hd.data.data, list)
    assert hd.data.kind is None

    kwargs.update(pending=True)
    req = rr.g.d.req_read(ctx, uuid_document, **kwargs)
    hd = await rr.send(req, adapter=AsOutput[List[GrantSchema]])
    assert isinstance(hd.data, AsOutput)
    assert isinstance(hd.data.data, list)

    # NOTE: Try to recreate.
    req_create = rr.d.g.req_invite(ctx, uuid_document, uuid_user=uuid_user, force=False)
    req = await rr.send(
        req_create,
        expect_status=400,
        expect_err=mwargs(
            ErrDetail[ErrAssocRequestMustForce],
            detail=mwargs(
                ErrAssocRequestMustForce,
                msg=ErrAssocRequestMustForce._msg_force,
                kind_target=KindObject.user,
                kind_source=KindObject.document,
                kind_assoc=KindObject.grant,
                uuid_source=uuid_document,
                uuid_target=uuid_user,
                uuid_assoc=uuid_grants,
            ),
        ),
    )

    # NOTE: Move grants out of pending state. Deleting pending grants is an
    #       edge case.
    with sessionmaker() as session:
        q = update(Grant).values(pending=True).where(Grant.uuid.in_(uuid_grants))
        session.execute(q)
        session.commit()

    req_create = rr.d.g.req_invite(ctx, uuid_document, uuid_user=uuid_user, force=True)
    req = await rr.send(req_create, adapter=AsOutput[List[GrantSchema]])
