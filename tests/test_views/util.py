from http import HTTPMethod
from typing import Tuple
import pytest
import functools
import json
from typing import Dict, Any, Set, Callable, ParamSpec, Concatenate
from app import util as u
from app.schemas import EventSchema
from app.models import KindEvent
from app import __version__
import pytest_asyncio
import httpx
from app.auth import Auth
from client.requests import Requests
from client.base import BaseRequest
from ..conftest import PytestClientConfig

from typing import Type

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
    T: Type[BaseRequest] = Requests,
) -> BaseRequest:
    token = auth.encode(request.param or DEFAULT_TOKEN_PAYLOAD)
    return T(client_config, async_client, token=token)


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
    detail: str | None = None,
) -> EventSchema:
    event = EventSchema.model_validate_json(res.content)
    common: Dict[str, Any] = dict(
        api_version=__version__,
        kind=KindEvent.update,
    )
    common.update(
        kind_obj=kind_obj,
        api_origin=api_origin,
        uuid_user=uuid_user,
        uuid_obj=uuid_obj,
    )
    event_compare(event, common, ignore={"detail"})
    if detail is not None:
        assert detail in event.detail

    for item in event.children:
        assert not len(item.children)
        event_compare(event, common, ignore={"detail"})

        if detail is not None:
            assert detail in item.detail

        if "ownership transfered" in item.detail:
            continue

        bad = set(field for field in fields if field not in item.detail)
        if bad:
            raise AssertionError(
                f"Detail `{item.detail}` of event `{item.uuid}` should "
                f"contain one of the following: `{bad}`."
            )

    return event


class BaseTestViews:
    T: Type[BaseRequest]

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
