# =========================================================================== #
import os
import secrets
from unittest import mock

# --------------------------------------------------------------------------- #
from captura import util
from legere.config import Config


class TestEnv:
    def test_from_env(self):
        """Ensure that ``mock`` works on the ``util`` module as expected."""

        config_path_fmt = "~/.captura/config-{}.yaml"
        config_path = config_path_fmt.format(secrets.token_urlsafe())
        config_path_default = config_path_fmt.format(secrets.token_urlsafe())

        # NOTE: Changing environment of util should go back to OS. Doing so
        #       should then change the location in which ``Config`` expects
        #       to find ``YAML`` configuration.
        VAR = "CONFIG_APP_CLIENT"
        with mock.patch.dict(util.environ, {VAR: config_path}, clear=True):
            assert os.environ.get(VAR) == config_path
            assert util.environ.get(VAR) == config_path

            CONFIG_APP_CLIENT = util.from_env(
                VAR,
                default=config_path_default,
                prefix=False,
            )
            assert CONFIG_APP_CLIENT == config_path

            # NOTE: Proof that updating the config does not update as expected.
            # yaml_files = Config.model_config["yaml_files"]
            # assert isinstance(yaml_files, str)
            # assert yaml_files == config_path

        with mock.patch.dict(os.environ, {"CONFIG_APP_CLIENT": ""}, clear=True):
            CONFIG_APP_CLIENT = util.from_env(
                "CONFIG_APP_CLIENT", default=config_path_default, prefix=False
            )
            assert CONFIG_APP_CLIENT != config_path_default
            assert CONFIG_APP_CLIENT != config_path
