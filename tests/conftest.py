# =========================================================================== #
import argparse
from datetime import datetime
from os import path
from typing import Annotated, Any, AsyncGenerator, Dict, Iterable, List, Self, Set

import httpx
import pytest
import pytest_asyncio
import yaml
from _pytest.stash import StashKey
from fastapi import Depends, FastAPI
from pydantic import BaseModel
from sqlalchemy import delete, select, text, true
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker as _sessionmaker
from yaml_settings_pydantic import BaseYamlSettings, YamlFileConfigDict

# --------------------------------------------------------------------------- #
from captura import depends, util
from captura.auth import Auth
from captura.config import AppConfig
from captura.models import Base, User
from captura.schemas import mwargs
from captura.views import AppView
from simulatus import DummyHandler, DummyProvider, DummyProviderYAML
from tests.config import PytestClientConfig, PytestConfig
from tests.flakey import FLAKEY_PATH, Flake, Flakey

logger = util.get_logger(__name__)

COUNT = 5
FLAKEY = True


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
STASHKEY_CONFIG_FLAKEY = StashKey[Flakey]()
STASHKEY_CONFIG_CAPTRUA = StashKey[PytestConfig]()
STASHKEY_CONFIG_LEGERE = StashKey[PytestClientConfig]()


def pytest_exception_interact(
    node: pytest.Collector | pytest.Item,
    call: pytest.CallInfo,
    report: pytest.CollectReport | pytest.TestReport,
):
    if FLAKEY:
        return

    logger.debug("Check exception from `%s` for flakeyness.", node.name)
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

    logger.debug("Recording flakey test in `flakey.yaml`.")
    flakey = node.config.stash[STASHKEY_CONFIG_FLAKEY]
    if flakey.register(node, call) is None:  # type: ignore
        return


def pytest_sessionfinish(session: pytest.Session, exitstatus: pytest.ExitCode):
    logger.info("Recording flakey tests in `flakey.yaml`.")
    flakey = session.config.stash[STASHKEY_CONFIG_FLAKEY]

    with open(FLAKEY_PATH, "w") as file:
        yaml.dump(flakey.model_dump(mode="json"), file)


# NOTE: Do not add settings that belong directly in ``tests.config.PytestConfig``
#       or ``test.config.PytestClientConfig``. This should include global
#       tests settings only and preference should be given to the
#       afforementioned classes.
def pytest_addoption(parser: pytest.Parser, pluginmanager: pytest.PytestPluginManager):
    logger.debug("Configuring additional `pytest` flags and `ini` options.")

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
    parser.addoption(
        "--generate-dummies",
        help="Overwrites `PytestConfig.tests.generate_reports`.",
        action=argparse.BooleanOptionalAction,
    )

    # NOTE: Configuration flags.
    parser.addoption("--config-captura", help="Overwrite the app config path.")
    parser.addoption("--config-legere", help="Overwrite the client config path.")

    # NOTE: Used to populate ``pytest.Config.stash[STASHKEY_CONFIG_FLAKEY]``.
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
    parser.addoption(
        "--flakey-clear",
        action=argparse.BooleanOptionalAction,
        help="Clear `flakey.yaml` before tests.",
    )
    parser.addoption(
        "--flakey",
        action=argparse.BooleanOptionalAction,
        help="Collection flakey tests in `flakey.yaml`.",
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

    # ----------------------------------------------------------------------- #
    # NOTE: Add ``flakey.yaml`` to the stash so that dependency injection is
    #       maintained. This cannot be done with count as it is not in an
    #       injectable context.
    # NOTE: Add other configurations to the stash. These will be served using
    #       the ``config`` and ``config_client`` fixtures.

    logger.debug("Loading and stashing configurations.")

    flakey = config.getoption("--flakey")
    flakey_clear = config.getoption("--flakey-clear")
    flakey_ignore_ini = config.getini("flakey_ignore") or list()
    flakey_ignore_ini_err = config.getini("flakey_ignore_err") or list()
    Flakey.yaml_ensure(bool(flakey_clear))
    global FLAKEY
    FLAKEY = flakey

    flakey = mwargs(Flakey, ignore=flakey_ignore_ini, ignore_err=flakey_ignore_ini_err)
    config.stash[STASHKEY_CONFIG_FLAKEY] = flakey

    config_captura = resolve_config_captura(config)
    if generate_dummies := config.getoption("--generate-dummies"):
        assert isinstance(generate_dummies, bool), "Should be `bool`."
        config_captura.tests.generate_dummies = generate_dummies

    config.stash[STASHKEY_CONFIG_CAPTRUA] = config_captura
    config.stash[STASHKEY_CONFIG_LEGERE] = resolve_config_legere(config)


def resolve_config_captura(pytestconfig: pytest.Config) -> PytestConfig:
    PytestConfig.pytestconfig = pytestconfig
    if config_captura_path := pytestconfig.getoption("--config-captura"):
        logger.warning(
            "Loading app configuration from alternative path `%s`.",
            config_captura_path,
        )
        PytestConfig.model_config["yaml_files"] = config_captura_path

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


def resolve_config_legere(pytestconfig: pytest.Config):
    PytestClientConfig.pytestconfig = pytestconfig
    if config_legere_path := pytestconfig.getoption("--config-legere"):
        logger.warning(
            "Loading client configuration from alternative path `%s`.",
            config_legere_path,
        )
        PytestConfig.model_config["yaml_files"] = config_legere_path

    logger.debug("Loading client configuration.")
    return PytestClientConfig.model_validate({})


# =========================================================================== #
# NOTE: Configuration fixtures.


# NOTE: Session scoping works like fastapi dependency caching, so these will
#       only ever be called once in a test session. This should be specified
#       in ``config/app.test.yaml``.
@pytest.fixture(scope="session")
def config(pytestconfig: pytest.Config) -> PytestConfig:
    return pytestconfig.stash[STASHKEY_CONFIG_CAPTRUA].model_copy()


# NOTE: Should be specified in config/client.test.yaml or overwritten using
#       ``--config-legere``. Returning copies of models will help preventing
#       overwrites being maintained from any test.
@pytest.fixture(scope="session")
def client_config(pytestconfig: pytest.Config) -> PytestClientConfig:
    return pytestconfig.stash[STASHKEY_CONFIG_LEGERE].model_copy()


# NOTE: Was this necessary? Currently impartial.
class PytestContext(BaseModel):
    reloaded: bool = False
    config: PytestConfig
    config_client: PytestClientConfig


@pytest.fixture(scope="function")
def context(
    config: PytestConfig,
    client_config: PytestClientConfig,
) -> PytestContext:
    logger.debug("Creating client context.")
    return PytestContext(config=config, config_client=client_config)


# --------------------------------------------------------------------------- #
# Application fixtures.


@pytest.fixture(scope="session")
def app(client_config: PytestClientConfig, config: PytestConfig) -> FastAPI | None:
    print(client_config.model_dump())
    if (host := client_config.host) is None or not host.remote:
        logger.info("Using httpx client with app instance.")

        # NOTE: Ensure that the pytest config is used. This step cannot be per-
        #       formed for remote hosts.
        app: FastAPI
        app = AppView.view_router  # type: ignore

        # NOTE: Dependency overwrites.
        app.dependency_overrides[depends.config] = lambda: config
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
    logger.debug("Creating engine from capturalication configuration.")
    return config.engine()


@pytest.fixture(scope="session")
def sessionmaker(engine: Engine) -> _sessionmaker[Session]:
    logger.debug("Creating sessionmaker from capturalication configuration.")
    return _sessionmaker(engine)


@pytest.fixture(scope="function")
def session(sessionmaker):
    logger.debug("Session opened.")
    with sessionmaker() as session:
        yield session
    logger.debug("Session closed.")


@pytest.fixture(scope="module")
def dummy_handler(
    request,
    sessionmaker: _sessionmaker,
    config: PytestConfig,
    auth: Auth,
    worker_id: str,
):
    name_module = f"(`module={request.node.name}`) "
    handler = DummyHandler(sessionmaker, config, auth=auth)
    if worker_id != "master":
        return handler

    if generate_reports := config.tests.generate_reports:
        handler.create_report(f"For {name_module}.")

    if config.tests.generate_dummies:
        logger.info("Cleaning and restoring database.")
        handler.dispose()
        if generate_reports:
            note = f"Post ``DummyHandler.restore`` {name_module}."
            handler.create_report(note)

        handler.restore()
        if generate_reports:
            note = f"Post ``DummyHandle.dispose`` restoration {name_module}."
            handler.create_report(note)

    return handler


@pytest.fixture
def dummy(request, dummy_handler: DummyHandler):
    logger.info("Providing random dummy.")
    with dummy_handler.sessionmaker() as session:
        dummy = DummyProvider(
            dummy_handler.config,
            session,
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
            use_existing=False,
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
            client_config_cls=PytestClientConfig,
        )
        dummy.info_mark_used(request.node.name).info_mark_tainted()
        session.add(dummy.user)
        session.commit()
        session.expire(dummy.user)

        yield dummy


# --------------------------------------------------------------------------- #
# Loading fixtures


@pytest.fixture(scope="session", autouse=True)
def setup_cleanup(
    engine: Engine,
    sessionmaker: _sessionmaker,
    config: PytestConfig,
    worker_id: str,
):
    util.setup_logging(config.app.logging_configuration_path)

    if worker_id != "master":
        yield
        return

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

    with sessionmaker() as session:
        logger.info("Loading tables with dummy data from `YAML`.")
        DummyProviderYAML.merge(session)
        logger.info("Generating dummy data.")

    yield
