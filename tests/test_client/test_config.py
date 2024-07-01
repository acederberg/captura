# =========================================================================== #
import json
import os
import pathlib
import secrets
from os import path
from typing import Dict, Generic, Tuple, Type, TypeAlias, TypeVar
from unittest import mock

import pytest
import typer
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import false, func, select
from typer.testing import CliRunner

# --------------------------------------------------------------------------- #
from app.auth import Auth
from app.models import User
from app.schemas import mwargs
from client import ConfigCommands, ProfilesCommand
from client.config import Config, HostConfig, Output, OutputConfig, ProfileConfig
from client.requests.base import BaseTyperizable, typerize
from dummy import DummyHandler, DummyProvider
from tests.config import PytestClientConfig


@pytest.fixture
def cc(sessionmaker, auth: Auth) -> Config:

    with sessionmaker() as session:
        q = (
            select(User)
            .where(User.deleted == false(), User.admin == false())
            .order_by(func.random())
            .limit(2)
        )
        res = tuple(session.scalars(q))
        if len(res) != 2:
            raise AssertionError("Expected exactly two users.")

        default, other = res

    return mwargs(
        Config,
        profiles=dict(
            default=mwargs(
                ProfileConfig,
                uuid_user=default.uuid,
                token=auth.encode({"sub": default.uuid, "permissions": []}),
            ),
            other=mwargs(
                ProfileConfig,
                uuid_user=other.uuid,
                token=auth.encode({"sub": other.uuid, "permissions": []}),
            ),
        ),
        hosts=dict(
            first=HostConfig(host="localhost:8080", remote=True),
            second=HostConfig(host="localhost:8080", remote=False),
        ),
        # NOTE: Raw output is required!
        output=mwargs(OutputConfig, output=Output.raw, output_fallback=Output.json),
        use=dict(host="first", profile="default"),
    )


class TestConfig:
    def test_basic(self, cc: Config):
        assert cc.use.profile == "default"
        assert cc.use.host == "first"

        profile_initial, host_initial = cc.profile, cc.host
        assert profile_initial is not None
        assert host_initial is not None
        assert cc.token == profile_initial.token

        cc.use.profile = "other"
        cc.use.host = "second"

        assert cc.host is not None
        assert cc.host != host_initial

        assert cc.profile is not None
        assert cc.profile != profile_initial
        assert cc.token == cc.profile.token

        sensor = "**********"
        dumped = cc.model_dump_minimal()
        assert set(dumped.keys()) == {"profile", "host", "output"}
        assert dumped["profile"]["token"] == sensor, "Should be sensored."

        dumped = cc.model_dump_config()
        assert set(dumped.keys()) == {"profiles", "hosts", "output", "use"}
        assert all(
            pp.get("token") != sensor for pp in dumped["profiles"].values()
        ), "Should not be sensored"

    def test_invalid_use(self, cc: Config):

        content = cc.model_dump_config()
        content["use"]["profile"] = (new := secrets.token_urlsafe(8))

        with pytest.raises(ValidationError) as err:
            Config.model_validate(content)

        fmt = "Invalid %s config `%s`, should be any of"
        assert (fmt % ("profile", new)) in str(err.value)

        # ------------------------------------------------------------------- #

        content["use"]["host"] = (new := secrets.token_urlsafe(8))

        with pytest.raises(ValidationError) as err:
            Config.model_validate(content)
        assert (fmt % ("host", new)) in str(err.value)

    def test_load_dump(self, cc: Config, tmp_path):
        Config()

        tmp_config = tmp_path / "client.yaml"
        for _ in range(5):
            cc.dump(tmp_config)
            dd = Config.load(tmp_config)

            assert cc == dd


Stuff: TypeAlias = Tuple[CliRunner, typer.Typer, pathlib.Path]


class BaseTestCommand:

    typerizable: Type[BaseTyperizable]

    @pytest.fixture
    def stuff(self, cc: Config, tmp_path: pathlib.Path):

        config_path = str(tmp_path / "client.yaml")
        cc.dump(config_path)

        env = {"CAPTURA_CONFIG_CLIENT": config_path}
        with mock.patch.dict(os.environ, env):
            yield (
                CliRunner(env=env),
                typerize(self.typerizable),
                tmp_path,
            )


class TestConfigCommand(BaseTestCommand):
    typerizable = ConfigCommands

    def test_origin(self, stuff: Stuff):
        runner, tt, tmp_path = stuff

        # NOTE: Default output is ``--all``
        result = runner.invoke(tt, ["origin"])
        assert result.stdout.strip() == str(tmp_path / "client.yaml")

    @pytest.mark.skip
    def test_show(self, stuff: Stuff):
        runner, tt, tmp_path = stuff

        config_path = str(tmp_path / "client.yaml")
        config_expected = Config.load(config_path)
        assert config_expected.output.output == Output.raw
        assert config_expected.output.output_fallback == Output.json

        result = runner.invoke(tt, ["origin"])
        assert result.stdout.strip() == str(config_path)

        # NOTE: Default output is not ``--all``
        result = runner.invoke(tt, ["show"])
        result_all = runner.invoke(tt, ["show", "--all"])

        assert result.exit_code == result_all.exit_code == 0
        assert result_all.stdout != result.stdout
        assert len(result_all.stdout) > len(result.stdout)

        # NOTE: Cannot use ``model_validate`` on result since it does not contain
        #       all fields.
        config = Config.model_validate_json(result_all.stdout)

        assert config.output == config_expected.output
        assert config.use == config_expected.use
        assert config.hosts == config_expected.hosts
        assert config.profiles == config_expected.profiles


@pytest.mark.skip
class TestProfilesCommand(BaseTestCommand):
    typerizable = ProfilesCommand

    def test_list(self, stuff: Stuff):
        runner, tt, tmp_path = stuff
        config_path = str(tmp_path / "client.yaml")
        config = Config.load(config_path)

        # NOTE: Default output is ``--all``
        result_default = runner.invoke(tt, ["list"])
        result = runner.invoke(tt, ["list", "--all"])

        assert result.exit_code == result_default.exit_code == 0
        assert result.stdout == result_default.stdout

        adptr = TypeAdapter(Dict[str, ProfileConfig])
        profiles = adptr.validate_json(result.stdout_bytes)

        assert profiles == config.profiles
