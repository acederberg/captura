
import pytest
from client.requests import Requests
from tests.dummy import DummyProvider
from tests.test_views.util import BaseEndpointTest


class CommonUsersGrantsTests(BaseEndpointTest):

    @pytest.mark.asyncio
    async def test_unauthorized_401(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test unauthorized access."
        assert False


    @pytest.mark.asyncio
    async def test_forbidden_403(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        """User must be logged in as user."""
        assert False

    @pytest.mark.asyncio
    async def test_not_found_404(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test not found response with bad document uuid."
        assert False

    @pytest.mark.asyncio
    async def test_deleted_410(
        self,
        dummy: DummyProvider,
        requests: Requests,
    ):
        "Test deleted document"
        assert False


class TestUsersGrantsRequest(CommonUsersGrantsTests):
    "For example requesting access to a document."

    def test_success_200(self, dummy: DummyProvider, requests: Requests):
        "Test requesting a grant. Ask for access and verify the grant."
        assert False

    def test_forbidden_403_only_public_documents(self, dummy: DummyProvider, requests: Requests):
        """Test requesting a grant on a public document.

        Cannot ask for access to a private document, but filtering by private
        documents should be allowed for all other endpoint methods.
        """
        assert False

class TestUsersGrantsRead(CommonUsersGrantsTests):
    def test_success_200(self, dummy: DummyProvider, requests: Requests):
        """Test user can read own grants."""
        assert False

    def test_success_200_private_pending(self, dummy: DummyProvider, requests: Requests):
        """Test can read user pending grants for private documents.
        """
        assert False

    def test_success_200_pending_from(self, dummy: DummyProvider, requests: Requests):
        """Test the `pending_from` query parameter.
        """
        assert False

class TestUsersGrantsReject(CommonUsersGrantsTests):
    def test_success_200(self, dummy: DummyProvider, requests: Requests):
        """User can remove own grants."""
        assert False


class TestUsersGrantsAccept(CommonUsersGrantsTests):
    def test_success_200(self, dummy: DummyProvider, requests: Requests):
        """User can accept own grants."""
        assert False


