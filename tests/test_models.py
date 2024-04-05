# =========================================================================== #
from typing import Any, ClassVar, Dict, List, Type

import pytest
import yaml
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session, make_transient, sessionmaker

# --------------------------------------------------------------------------- #
from app import __version__, util
from app.models import (
    AssocCollectionDocument,
    AssocUserDocument,
    Base,
    Collection,
    Document,
    Edit,
    Event,
    Grant,
    KindEvent,
    KindObject,
    User,
)

logger = util.get_logger(__name__)


class ModelTestMeta(type):
    __children__: ClassVar[Dict[str, "BaseModelTest"]] = dict()

    @classmethod
    def load(cls, sessionmaker: sessionmaker[Session]):
        assert False, "User merge dummyProviderYaml.merge."

    def __new__(cls, name, bases, namespace):
        if name == "BaseModelTest":
            return super().__new__(cls, name, bases, namespace)

        # M, since it is needed to determine the default dummies file name.
        if (M := namespace.get("M")) is None:
            raise ValueError("`M` must be defined.")
        elif not issubclass(M, Base):
            raise ValueError(f"`{name}.M={M}` must be a subclass of `{Base}`.")

        if (dummies_file := namespace.get("dummies_file")) is None:
            kind = KindObject._value2member_map_[M.__tablename__]
            dummies_file = util.Path.test_assets(f"{kind.name}.yaml")
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

        T = super().__new__(cls, name, bases, namespace)
        cls.__children__[T.M.__tablename__] = T  # type: ignore
        return T


class BaseModelTest(metaclass=ModelTestMeta):
    # NOTE: This will matter less when the dummy data project is copmlete.
    M: ClassVar[Type[Base]]
    dummies_file: ClassVar[str]
    dummies: ClassVar[List[Dict[str, Any]]]

    @classmethod
    def preload(cls, item):
        return item

    @classmethod
    def clean(cls, session: Session) -> None:
        assert False
        logger.debug("Cleaning %s.", cls.M.__tablename__)
        session.execute(delete(cls.M))
        session.commit()

    @classmethod
    def load(cls, session: Session, start: int = 0, stop: int | None = None) -> None:
        assert False
        logger.debug("Adding %s dummies from `%s`.", cls.M, cls.dummies_file)
        session.add_all(
            list(cls.preload(cls.M(**item)) for item in cls.dummies[start:stop])
        )
        session.commit()

    @classmethod
    def merge(cls, session: Session):
        loaded = (cls.preload(cls.M(**item)) for item in cls.dummies)
        for item in loaded:
            session.merge(item)
        session.commit()

    @pytest.fixture(scope="session", autouse=True)
    def invoke_loader(self, load_tables, setup_cleanup):
        ...


# NOTE: Test suites must be defined in appropraite order to ensure that
#       integrity constraints allow data to be inserted successfully.
class TestUser(BaseModelTest):
    M = User

    ...


class TestCollection(BaseModelTest):
    M = Collection


class TestDocument(BaseModelTest):
    M = Document

    @classmethod
    def preload(cls, item: Document) -> Document:
        item.content = bytes(item.content, "utf-8")
        return item


class TestEdit(BaseModelTest):
    M = Edit

    @classmethod
    def preload(cls, item: Edit) -> Edit:
        item.content = bytes(
            item.content,
            "utf-8",
        )  # type: ignore
        return item


class TestAssocUserDocument(BaseModelTest):
    M = AssocUserDocument

    @classmethod
    def load(cls, session: Session, start: int = 0, stop: int | None = None) -> None:
        logger.debug("Adding %s dummies from `%s`.", cls.M, cls.dummies_file)
        items: Dict[str, Grant] = {
            item["uuid"]: cls.preload(Grant(**item)) for item in cls.dummies[start:stop]
        }
        roots = (item for item in items.values() if item.uuid_parent is None)
        others = (item for item in items.values() if item.uuid_parent is not None)
        for root in roots:
            session.merge(root)
        session.commit()

        for leaf in others:
            session.merge(leaf)
            session.commit()


class TestAssocCollectionDocument(BaseModelTest):
    M = AssocCollectionDocument


class TestEvent(BaseModelTest):
    M = Event

    @classmethod
    def clean(cls, session: Session) -> None:
        logger.debug("Cleaning %s.", cls.M.__tablename__)
        session.execute(update(cls.M).values(uuid_parent=None))
        session.execute(delete(cls.M))
        session.commit()

    def test_flattened(self):
        def make_uuid(char: str) -> str:
            return "-".join(char * 3 for _ in range(3))

        def make(char: str, children: List[Event] = list()) -> Event:
            uuid = make_uuid(char)
            return Event(uuid=uuid, **common, children=children)

        common = dict(
            kind=KindEvent.create,
            kind_obj=KindObject.event,
            uuid_obj="666-666-666",
            uuid_user="test-flattened",
            detail="TEST FLATTENED",
            api_version=__version__,
            api_origin="TestEvent",
        )

        # Traversing the below tree depth first should reorder the letters
        B = make("B", [make("C"), make("D"), make("E", [make("F"), make("G")])])
        H = make(
            "H",
            [make("I", [make("J"), make("K", [make("L"), make("M", [make("N")])])])],
        )
        A = make("A", [B, H])

        nodechars = "ABCDEFGHIJKLMN"
        uuids = {
            node.uuid: make_uuid(nodechars[index])
            for index, node in enumerate(A.flattened())
        }

        # assert rich.print_json(json.dumps(uuids, indent=2))
        assert list(uuids) == list(uuids.values())
