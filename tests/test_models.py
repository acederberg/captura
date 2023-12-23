from typing import Any, ClassVar, Dict, List, Type

import pytest
import yaml
from app import util
from app.models import (
    AssocCollectionDocument,
    AssocUserDocument,
    Base,
    Collection,
    Document,
    DocumentHistory,
    User,
)
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

logger = util.get_logger(__name__)


class ModelTestMeta(type):
    def __new__(cls, name, bases, namespace):
        if name == "BaseModelTest":
            return super().__new__(cls, name, bases, namespace)

        # M, since it is needed to determine the default dummies file name.
        if (M := namespace.get("M")) is None:
            raise ValueError("`M` must be defined.")
        elif not issubclass(M, Base):
            raise ValueError(f"`{name}.M={M}` must be a subclass of `{Base}`.")

        if (dummies_file := namespace.get("dummies_file")) is None:
            dummies_file = util.Path.test_assets(f"{M.__tablename__}.yaml")
            namespace["dummies_file"] = dummies_file

        # Dummies. Cannot declare dummies directly.
        if namespace.get("dummies") is not None:
            raise ValueError("Cannot specify dummies explicitly.")

        with open(dummies_file, "r") as file:
            namespace["dummies"] = (dummies := yaml.safe_load(file))

        _msg = f"`{name}.dummies_file={dummies_file}`"
        if not isinstance(dummies, list):
            raise ValueError(f"{_msg} must deserialize to a list.")
        elif len(
            bad := tuple(
                index
                for index, item in enumerate(dummies)
                if not isinstance(item, dict)
            )
        ):
            raise ValueError(f"{_msg} has bad entries in positions `{bad}`.")

        return super().__new__(cls, name, bases, namespace)


class BaseModelTest(metaclass=ModelTestMeta):
    # NOTE: This will matter less when the dummy data project is copmlete.
    M: ClassVar[Type[Base]]
    dummies_file: ClassVar[str]
    dummies: ClassVar[List[Dict[str, Any]]]

    # NOTE: Session soped fixtures should occur in the order in which they are
    #       defined.
    @pytest.fixture(scope="session", autouse=True)
    def load(self, sessionmaker: sessionmaker[Session]) -> None:
        with sessionmaker() as session:
            query = select(func.count()).select_from(self.M)
            count = session.execute(query).scalar()
            if not count:
                preload = getattr(self, "preload", lambda item: item)

                logger.debug(
                    "Adding dummies from `%s.dummies_file` to database.",
                    self.__class__.__name__,
                )
                session.add_all(list(preload(self.M(**item)) for item in self.dummies))
                session.commit()
                return

            logger.debug(
                "Dummies already exist for `%s`.",
                self.__class__.__name__,
            )


# NOTE: Test suites must be defined in appropraite order to ensure that
#       integrity constraints allow data to be inserted successfully.
class TestUser(BaseModelTest):
    M = User

    def test_whatever(self, sessionmaker: sessionmaker[Session]):
        ...


class TestCollection(BaseModelTest):
    M = Collection

    # def test_user_optional(self, sessionmaker: sessionmaker[Session]):
    #     assert print(id(sessionmaker))
    #     ...
    #
    # def test_relationships(self, sessionmaker: sessionmaker[Session]):
    #     assert print(id(sessionmaker))
    #     ...


class TestDocument(BaseModelTest):
    M = Document

    def preload(self, item: Document) -> Document:
        item.content = bytes(item.content, "utf-8")
        return item

    def test_whatever(self, sessionmaker: sessionmaker[Session]):
        ...


class TestDocumentHistory(BaseModelTest):
    M = DocumentHistory
