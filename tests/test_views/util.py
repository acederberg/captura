# =========================================================================== #
import abc
import functools
import json
from http import HTTPMethod
from typing import (
    Any,
    AsyncGenerator,
    Callable,
    ClassVar,
    Concatenate,
    Dict,
    Generator,
    List,
    ParamSpec,
    Set,
    Tuple,
)

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from pydantic import TypeAdapter
from sqlalchemy import func

# --------------------------------------------------------------------------- #
from app.auth import Auth
from app.err import ErrDetail
from app.fields import Level
from app.models import Document, Grant, User
from app.schemas import EventSchema
from client.handlers import CONSOLE, AssertionHandler
from client.requests import Requests
from dummy import DummyHandler, DummyProvider

from ..conftest import COUNT, PytestClientConfig

DEFAULT_UUID_COLLECTION: str = "foo-ooo-ool"
DEFAULT_UUID_DOCS: str = "aaa-aaa-aaa"
DEFAULT_UUID: str = "000-000-000"
DEFAULT_TOKEN_PAYLOAD = dict(uuid=DEFAULT_UUID)
EVENT_COMMON_FIELDS = {"api_origin", "api_version", "kind", "uuid_user"}


# =========================================================================== #
# Checks and compares


def event_compare(
    event: EventSchema, expect_common: Dict[str, Any], ignore: Set[str] = set()
) -> None:
    assert event.uuid is not None
    for field in EVENT_COMMON_FIELDS - ignore:
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


# =========================================================================== #
# ObjectpRe


class BaseEndpointTest(abc.ABC):
    """Use this template to save some time:

    .. code:: python

        async def test_unauthorized_401(self, dummy: DummyProvider, requests: Requests):
            "Test unauthorized access."
            ...

        async def test_not_found_404(self, dummy: DummyProvider, requests: Requests):
            "Test not found response."
            ...

        async def test_deleted_410(self, dummy: DummyProvider, requests: Requests):
            "Test deleted object"
            ...
    """

    adapter: ClassVar[TypeAdapter]
    adapter_w_events: ClassVar[TypeAdapter]

    @pytest.fixture(scope="function")
    def dummy(self, dummy) -> Generator[DummyProvider, None, None]:
        dummy.user.deleted = False

        session = dummy.session
        session.add(dummy.user)
        session.commit()
        session.refresh(dummy.user)

        yield dummy

    @pytest_asyncio.fixture(scope="function")
    async def requests(
        self,
        app: FastAPI | None,
        dummy: DummyProvider,
        client_config: PytestClientConfig,
        # async_client: httpx.AsyncClient,
    ) -> AsyncGenerator[Requests, Any]:
        async with httpx.AsyncClient(app=app) as client:
            yield dummy.requests(client_config, client, handler_methodize=False)

    def check_status(
        self,
        requests: Requests,
        response: httpx.Response | Tuple[httpx.Response, ...],
        expect: int | None = None,
        err: ErrDetail | None = None,
    ) -> AssertionError | None:
        # handler = AssertionHandler(requests.context.config)
        hd, ee = requests.handler.check_status(
            response, expect_err=err, expect_status=expect
        )
        return ee

    # ----------------------------------------------------------------------- #
    # Errors

    @abc.abstractmethod
    async def test_unauthorized_401(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        "Test unauthorized access."
        ...

    @abc.abstractmethod
    async def test_not_found_404(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        "Test not found response."
        ...

    @abc.abstractmethod
    async def test_deleted_410(
        self, dummy: DummyProvider, requests: Requests, count: int
    ):
        "Test deleted object"
        ...

    def document_user_uuids(
        self,
        dummy: DummyProvider,
        document: Document,
        limit: int | None = None,
        **kwargs,
    ) -> List[str]:
        q_users = (
            document.q_select_users(**kwargs)
            .where(Grant.level < Level.own)
            .order_by(func.random())
            .limit(limit or 10)
        )
        users = tuple(dummy.session.scalars(q_users))
        return list(User.resolve_uuid(dummy.session, users))


class BaseEndpointTestPrimaryCreateMixins:
    @pytest.mark.skip
    @pytest.mark.asyncio
    async def test_not_found_404(
        self, dummy: DummyProvider, requests: Requests, count: int
    ): ...

    @pytest.mark.skip
    @pytest.mark.asyncio
    async def test_deleted_410(
        self, dummy: DummyProvider, requests: Requests, count: int
    ): ...

    @pytest.mark.skip
    @pytest.mark.asyncio
    async def test_forbidden_403(
        self, dummy: DummyProvider, requests: Requests, count: int
    ): ...


# =========================================================================== #


# @checks_event
# def check_event_update(
#     _,
#     res: httpx.Response,
#     fields: Set[str],
#     *,
#     kind_obj: str,
#     api_origin: str,
#     uuid_obj: str,
#     uuid_user: str,
#     detail: str | None = None,
# ) -> EventSchema:
#     event = EventSchema.model_validate_json(res.content)
#     common: Dict[str, Any] = dict(
#         api_version=__version__,
#         kind=KindEvent.update,
#     )
#     common.update(
#         kind_obj=kind_obj,
#         api_origin=api_origin,
#         uuid_user=uuid_user,
#         uuid_obj=uuid_obj,
#     )
#     event_compare(event, common, ignore={"detail"})
#     if detail is not None:

#         assert detail in event.detail
#
#     for item in event.children:
#         assert not len(item.children)
#         event_compare(event, common, ignore={"detail"})
#
#         if detail is not None:
#             assert detail in item.detail
#
#         if "ownership transfered" in item.detail:
#             continue
#
#         bad = set(field for field in fields if field not in item.detail)
#         if bad:
#             raise AssertionError(
#                 f"Detail `{item.detail}` of event `{item.uuid}` should "
#                 f"contain one of the following: `{bad}`."
#             )
#
#     return event
