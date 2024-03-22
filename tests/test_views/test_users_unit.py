
import pytest
from client.requests import Requests
from tests.dummy import DummyProvider
from tests.test_views.util import BaseEndpointTest


class CommonUserTests(BaseEndpointTest):

    @pytest.mark.asyncio
    async def test_unauthorized_401(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test unauthorized access."
        assert False

    @pytest.mark.asyncio
    async def test_unauthorized_403(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test only user can access."
        assert False

    @pytest.mark.asyncio
    async def test_unauthorized_404(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test no such user."
        assert False

