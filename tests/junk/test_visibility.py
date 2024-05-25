"""Enforce consistent use of the rules for endpoint responses for deleted and 
publiic. The rules are as follows:

1. When an item is has ``deleted`` set to ``True``, it requests for it should 
   return a `404` status with ``JSON`` content specifying that the item exists.
2. When an item has ``private`` set to ``True``, it should only be visible to 
   those with the correct grants/foreign keys.
"""

# =========================================================================== #
from typing import Awaitable, Callable, ParamSpec

import httpx
import pytest

# --------------------------------------------------------------------------- #
from client.requests import Requests

from . import util


class TestPublic:
    @pytest.mark.asyncio
    async def test_users(self, requests: Requests): ...

    @pytest.mark.asyncio
    async def test_grants(self, requests: Requests): ...

    @pytest.mark.asyncio
    async def test_collections(self, requests: Requests): ...

    @pytest.mark.asyncio
    async def test_documents(self, requests: Requests): ...

    @pytest.mark.asyncio
    async def test_assignments(self, requests: Requests): ...

    @pytest.mark.asyncio
    async def test_events(self, requests: Requests): ...


RequestLambda = Callable[[], Awaitable[httpx.Response]]


P = ParamSpec("P")


class TestDeleted:
    # TODO: This should include tests for all of the things pertaining to the
    #       user and their restoration. This replaces and existing test.
    @pytest.mark.asyncio
    async def test_users(self, requests: Requests):
        users = requests.users
        res = await users.delete(util.DEFAULT_UUID)
        if err := util.check_status(res):
            raise err

        # TODO: factor out check_event from users so event may be checked.
        res = await users.read(util.DEFAULT_UUID)
        if err := util.check_status(res, 404):
            raise err

        res = await users.delete(util.DEFAULT_UUID, restore=True)
        if err := util.check_status(res):
            raise err

        res = await users.read(util.DEFAULT_UUID)
        if err := util.check_status(res):
            raise err

    @pytest.mark.asyncio
    async def test_grants(self, requests: Requests): ...

    @pytest.mark.asyncio
    async def test_collections(self, requests: Requests): ...

    @pytest.mark.asyncio
    async def test_documents(self, requests: Requests): ...

    @pytest.mark.asyncio
    async def test_assignments(self, requests: Requests): ...

    @pytest.mark.asyncio
    async def test_events(self, requests: Requests): ...
