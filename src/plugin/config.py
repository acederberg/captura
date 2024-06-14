# =========================================================================== #
import re
from typing import Annotated, Dict

import git
from pydantic import Field, model_validator
from yaml_settings_pydantic import BaseYamlSettings, YamlSettingsConfigDict

# --------------------------------------------------------------------------- #
from app import util
from app.config import BaseHashable

PATTERN_GITHUB = re.compile(
    "(?P<scheme>https|ssh)://(?P<auth>(?P<auth_username>[a-zA-Z0-9]+):?(?P<auth_password>.+)?@)?github.com/(?P<slug>(?P<username>[a-zA-Z0-9_-]+)/(?P<repository>[a-zA-Z0-9_-]+))(?P<dotgit>\\.git)?(?P<path>/.*)?"
)


class RepoConfig(BaseHashable):
    """From ``captura_pipelines``."""

    tag: Annotated[
        str | None,
        Field(description="Git tag.", default=None),
    ]
    branch: Annotated[
        str,
        Field(description="Git branch.", default="master"),
    ]
    repository: Annotated[
        str,
        Field(description="Git repository", default="master"),
    ]
    path: Annotated[str, Field()]
    pull: Annotated[bool, Field(default=True)]
    commit: Annotated[
        str | None,
        Field(
            default=None,
            description="Hash to checkout and build. Populated when ``configure`` is called.",
        ),
    ]

    @model_validator(mode="before")
    def check_repository(cls, values):

        if (repository := values.get("repository")) is None or "path" in values:
            return values

        matched = PATTERN_GITHUB.match(repository)
        if matched is None:
            msg = f"`{repository}` must match pattern `{PATTERN_GITHUB}`."
            raise ValueError(msg)

        values["path"] = util.Path.plugins(matched.group("repository"))
        return values

    @classmethod
    def ensure(cls, repository: str, path: str) -> git.Repo:
        repo = (
            git.Repo.clone_from(repository, to_path=path)
            if path is None or not util.Path.exists(path)
            else git.Repo(path)
        )
        return repo

    def configure(self):
        path = self.path
        if util.p.exists(path) and not util.p.isdir(path):
            raise ValueError(f"Clone path `{path}` must be a directory.")

        repo = self.ensure(self.repository, path)

        branch: git.Head | None
        if (branch := getattr(repo.heads, self.branch, None)) is None:
            msg = f"No such branch `{self.branch}` of `{self.repository}`."
            raise ValueError(msg)

        if self.pull:
            repo.remotes["origin"].pull()

        if self.commit is not None:
            branch.set_commit(self.commit)
        else:
            self.commit = branch.object.hexsha

        return


# --------------------------------------------------------------------------- #


class PluginsItemConfig(RepoConfig):
    # script: Annotated[
    #     str,
    #     Field(default="plugin.py", description="Plugin script."),
    # ]
    exclude: Annotated[
        bool,
        Field(default=False, description="Exclude this plugin."),
    ]


class PluginsConfig(BaseHashable, BaseYamlSettings):
    """This data is used to install plugins."""

    model_config = YamlSettingsConfigDict(yaml_files=util.Path.base("plugins.yaml"))

    plugins: Dict[str, PluginsItemConfig]

    def ensure(self):
        util.Path.ensure("plugins")
        for plugin in self.plugins.values():
            if plugin.exclude:
                continue

            plugin.configure()
