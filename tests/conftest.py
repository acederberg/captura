# =========================================================================== #
from datetime import datetime
from os import path
from typing import Annotated, Any, AsyncGenerator, Dict, Iterable, List, Self, Set

import httpx
import pytest
import pytest_asyncio
import yaml
from fastapi import Depends, FastAPI
from pydantic import BaseModel
from sqlalchemy import delete, select, text, true
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker as _sessionmaker
from yaml_settings_pydantic import BaseYamlSettings, YamlFileConfigDict

# --------------------------------------------------------------------------- #
from app import depends, util
from app.auth import Auth
from app.config import AppConfig
from app.models import Base, User
from app.schemas import mwargs
from app.views import AppView
from dummy import DummyHandler, DummyProvider, DummyProviderYAML
from tests.config import PytestClientConfig, PytestConfig
from tests.flakey import FLAKEY_PATH, FLAKEY_STASHKEY, Flake, Flakey

logger = util.get_logger(__name__)

COUNT = 5


# --------------------------------------------------------------------------- #
# Hooks
#
# NOTE: I've never used them before but they are extremely helpful. See docs
#       here:
#
#       .. code:: txt
#
#          https://docs.pytest.org/en/7.1.x/reference/reference.html
#


def pytest_exception_interact(
    node: pytest.Collector | pytest.Item,
    call: pytest.CallInfo,
    report: pytest.CollectReport | pytest.TestReport,
):
    if report.passed:
        return
    elif call.excinfo is None:
        return

    match (node, report):
        case (pytest.Collector(), _) | (_, pytest.CollectReport):
            logger.debug("Not handling for exception raise via collection.")
            return

    err = call.excinfo.value
    if not isinstance(err, AssertionError):
        return

    node.keywords
    flakey = node.config.stash[FLAKEY_STASHKEY]
    if flakey.register(node, call) is None:  # type: ignore
        return


def pytest_sessionfinish(session: pytest.Session, exitstatus: pytest.ExitCode):

    flakey = session.config.stash[FLAKEY_STASHKEY]

    with open(FLAKEY_PATH, "w") as file:
        yaml.dump(flakey.model_dump(mode="json"), file)


def pytest_addoption(parser: pytest.Parser, pluginmanager: pytest.PytestPluginManager):
    # NOTE: Because count will be necessary to configure for CI and it is
    #       easier to update configuration as opposed to updating pipeline
    #       scripts.
    parser.addini(
        name="count",
        help="Rerun count for tests.",
        type="string",
    )

    # NOTE: Because high count can take a long time when one might only want
    #       to have a general idea if tests pass or not.
    parser.addoption(
        "--count",
        help=(
            "Rerun count for tests. Tests are repeated due to inherit "
            "flakeyness resulting from the randomness of the cases provided "
            "dummy provider."
        ),
    )

    # NOTE: Used to populate ``pytest.Config.stash[FLAKEY_STASHKEY]``.
    msg_see_flakey = "See `tests.flakey:Flakey.ignore`."
    parser.addini(
        name="flakey_ignore",
        help=msg_see_flakey,
        type="linelist",
    )
    parser.addini(
        name="flakey_ignore_err",
        help=msg_see_flakey,
        type="linelist",
    )
    # parser.addoption(
    #     name="flakey_rerun",
    #     help=f"Run all recently flakey from ``flakey.yaml``. {msg_see_flakey}",
    # )


def pytest_configure(config: pytest.Config):
    # NOTE: To see the effect of this hook run with the ``--collect-only``
    #       flag, set ``count`` in an ini configuration source or via the
    #       command line. If no source is found the default value is used.
    #       The command line option overwrites the ini option, which overwrites
    #       the default value.
    count_ini = config.getini("count")
    count_opt = config.getoption("--count")

    msg = "option `count` must be numeric string"
    assert count_ini is None or isinstance(count_ini, str)
    if count_ini:
        assert count_ini.isnumeric(), f"`ini` configuration {msg}."

    assert count_opt is None or isinstance(count_opt, str)
    if count_opt:
        assert count_opt.isnumeric(), f"Command {msg}."

    count = count_opt or count_ini or "5"
    global COUNT
    COUNT = int(count)

    # NOTE: Add ``flakey.yaml`` to the stash so that dependency injection is
    #       maintained. This cannot be done with count as it is not in an
    #       injectable context.
    Flakey.yaml_ensure()

    ignore_ini = config.getini("flakey_ignore") or list()
    ignore_ini_err = config.getini("flakey_ignore_err") or list()
    # assert isinstance(ignore_ini, list)
    # assert all(isinstance(item, str) for item in ignore_ini)

    # Flakey()
    flakey = mwargs(Flakey, ignore=ignore_ini, ignore_err=ignore_ini_err)
    config.stash[FLAKEY_STASHKEY] = flakey


# =========================================================================== #
# Test configuration and configuration fixture


# NOTE: Session scoping works like fastapi dependency caching, so these will
#       only ever be called once in a test session.
@pytest.fixture(scope="session")
def config() -> PytestConfig:
    logger.debug("Loading application configuration.")
    app = AppConfig.model_validate(
        {
            "logging_configuration_path": util.Path.base("logging.test.yaml"),
        }
    )
    if (config := mwargs(PytestConfig, app=app)).auth0.use:
        raise AssertionError(
            "Refusing to perform tests with `config.auth0.use=True`. "
            "Please set this setting to `False` to use the test token "
            "provider (see `app.config` and `app.auth::Auth.forPyTest`)."
        )

    return config


@pytest.fixture(scope="session")
def client_config() -> PytestClientConfig:
    logger.debug("Loading client configuration.")
    # raw: Dict[str, Any] = dict(
    #     hosts=dict(
    #         docker=dict(host="http://localhost:8080", remote=True),
    #         app=dict(host="http://localhost:8080", remote=False),
    #     ),
    #     profiles=dict(me=dict(token=None, uuid_user="000-000-000")),
    #     use=dict(host="app", profile="me"),
    # )
    return PytestClientConfig.model_validate({})


class PytestContext(BaseModel):
    reloaded: bool = False
    config: PytestConfig
    config_client: PytestClientConfig


@pytest.fixture(scope="session")
def context(
    config: PytestConfig,
    client_config: PytestClientConfig,
) -> PytestContext:
    logger.debug("Creating client context.")
    return PytestContext(config=config, config_client=client_config)


# --------------------------------------------------------------------------- #
# Application fixtures.


@pytest_asyncio.fixture(scope="session")
async def app(
    client_config: PytestClientConfig, config: PytestConfig
) -> FastAPI | None:
    if (host := client_config.host) is None or not host.remote:
        logger.info("Using httpx client with app instance.")

        # NOTE: Ensure that the pytest config is used. This step cannot be per-
        #       formed for remote hosts.
        app: FastAPI
        app = AppView.view_router  # type: ignore

        def config_callback():
            return config

        app.dependency_overrides[depends.config] = config_callback
        return app
    else:
        logger.warning("Using remote host for testing. Not recommended in CI!")


@pytest.fixture(scope="session")
def auth(config: PytestConfig) -> Auth:
    return Auth.forPyTest(config)


# =========================================================================== #
# Database fixtures


@pytest.fixture(scope="session")
def engine(config: PytestConfig) -> Engine:
    logger.debug("Creating engine from application configuration.")
    return config.engine()


@pytest.fixture(scope="session")
def sessionmaker(engine: Engine) -> _sessionmaker[Session]:
    logger.debug("Creating sessionmaker from application configuration.")
    return _sessionmaker(engine)


@pytest.fixture(scope="function")
def session(sessionmaker):
    logger.debug("Session opened.")
    with sessionmaker() as session:
        yield session
    logger.debug("Session closed.")


# TODO: Try out module scoping.
@pytest.fixture(scope="module")
def dummy_handler(
    request, sessionmaker: _sessionmaker, config: PytestConfig, auth: Auth
):
    user_uuids: List[str] = list()
    handler = DummyHandler(
        sessionmaker,
        config,
        user_uuids,
        auth=auth,
    )

    logger.info("Cleaning an restoring database.")
    name_module = f"(`module={request.node.name}`) "
    if generate_reports := config.tests.generate_reports:
        handler.create_report(f"Before disposal {name_module}.")

    handler.dispose()
    if generate_reports:
        handler.create_report(f"After disposal {name_module}.")

    handler.restore()
    if generate_reports:
        handler.create_report(f"After restoration {name_module}.")
    return handler


@pytest.fixture
def dummy(request, dummy_handler: DummyHandler):
    logger.info("Providing random dummy.")
    with dummy_handler.sessionmaker() as session:
        dummy = DummyProvider(
            dummy_handler.config,
            session,
            use_existing=dummy_handler.user_uuids,
            auth=dummy_handler.auth,
            client_config_cls=PytestClientConfig,
        )
        dummy.info_mark_used(request.node.name)
        session.add(dummy.user)
        session.commit()
        session.expire(dummy.user)

        yield dummy


@pytest.fixture
def dummy_new(request, dummy_handler: DummyHandler):
    logger.info("Providing new dummy.")
    with dummy_handler.sessionmaker() as session:
        dummy = DummyProvider(
            dummy_handler.config,
            session,
            auth=dummy_handler.auth,
            use_existing=None,
            client_config_cls=PytestClientConfig,
        )
        dummy.info_mark_used(request.node.name)
        session.add(dummy.user)
        session.commit()
        session.expire(dummy.user)

        yield dummy


@pytest.fixture
def dummy_disposable(request, dummy_handler: DummyHandler):
    logger.info("Providing disposable dummy.")
    with dummy_handler.sessionmaker() as session:
        dummy = DummyProvider(
            dummy_handler.config,
            session,
            auth=dummy_handler.auth,
            use_existing=dummy_handler.user_uuids,
            client_config_cls=PytestClientConfig,
        )
        dummy.info_mark_used(request.node.name).info_mark_tainted()
        session.add(dummy.user)
        session.commit()
        session.expire(dummy.user)

        yield dummy


@pytest.fixture(scope="function")
def yaml_dummy(request, dummy_handler: DummyHandler):
    logger.debug("Providing dummy for user uuid `000-000-000`.")
    with dummy_handler.sessionmaker() as session:
        user = session.get(User, 2)
        assert user is not None

        dd = DummyProviderYAML(
            dummy_handler.config,
            session,
            auth=dummy_handler.auth,
            user=user,
            client_config_cls=PytestClientConfig,
        )
        dd.merge(session)
        dd.session.refresh(dd.user)

        yield dd


# --------------------------------------------------------------------------- #
# Loading fixtures


@pytest.fixture(scope="session", autouse=True)
def setup_logging(config: PytestConfig) -> None:
    util.setup_logging(config.app.logging_configuration_path)
    return


@pytest.fixture(scope="session")
def setup_cleanup(engine: Engine, config: PytestConfig):
    logger.info("Setting up.")
    logger.debug("Verifying tables.")
    metadata = Base.metadata
    exists: bool
    with engine.begin() as connection:
        result = list(connection.execute(text("SHOW TABLES;")).scalars())
        exists = len(result) > 0

    if not exists:
        logger.debug("Recreating tables.")
        metadata.create_all(engine)
    # elif not exists:
    #     logger.debug("Creating tables.")
    #     metadata.create_all(engine)
    else:
        logger.debug("Doing nothing to tables.")

    yield


@pytest.fixture(scope="session", autouse=True)
def load_tables(
    setup_cleanup, config: PytestConfig, auth: Auth, sessionmaker: _sessionmaker
):
    with sessionmaker() as session:
        logger.info("Loading tables with dummy data from `YAML`.")
        DummyProviderYAML.merge(session)
        logger.info("Generating dummy data.")
