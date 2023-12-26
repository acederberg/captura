from typing import Any, ClassVar, Dict, List, Self, Type

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
from sqlalchemy import delete, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, make_transient, sessionmaker

logger = util.get_logger(__name__)


class ModelTestMeta(type):
    __children__: ClassVar[Dict[str, "BaseModelTest"]] = dict()

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
        logger.debug("Cleaning %s.", cls.M.__tablename__)
        for item in session.execute(select(cls.M)).scalars():
            session.delete(item)
        session.commit()

    @classmethod
    def load(cls, session: Session) -> None:
        logger.debug("Adding %s dummies from `%s`.", cls.M, cls.dummies_file)
        session.add_all(
            list(print(m := cls.M(**item)) or cls.preload(m) for item in cls.dummies)
        )
        session.commit()


@pytest.fixture(scope="session", autouse=True)
def load_tables(sessionmaker: sessionmaker[Session]):
    logger.info("Reloading tables (fixture `load_tables`).")
    with sessionmaker() as session:
        for table in Base.metadata.sorted_tables:
            cls = ModelTestMeta.__children__.get(table.name)
            if cls is None:
                logger.debug("No dummies for `%s`.", table.name)
                continue
            cls.clean(session)
            cls.load(session)


@pytest.fixture(scope="function")
def user(sessionmaker: sessionmaker[Session], id: int = 1) -> User | None:
    """Because this is frustrating to do all the time."""

    logger.debug("Calling `user` fixture.")
    with sessionmaker() as session:
        # Get user
        user = session.execute(select(User).where(User.id == id)).scalar()
        assert user is not None
        return user


# NOTE: Test suites must be defined in appropraite order to ensure that
#       integrity constraints allow data to be inserted successfully.
class TestUser(BaseModelTest):
    M = User

    def test_collections_relationship(
        self, user: User, sessionmaker: sessionmaker[Session]
    ):
        M: Type[User]
        m, M = user, self.M  # type: ignore
        assert isinstance(m, M)

        logger.debug("Initializing collections.")
        with sessionmaker() as session:
            q_collections = select(Collection)
            collections: List[Collection] = list(
                session.execute(q_collections).scalars()
            )
            assert len(collections), "Collections not found."

            for collection in collections:
                collection.id_user = None  # type: ignore

            session.add_all(collections)
            session.commit()

        logger.debug("Verifying that collections have no owner.")
        with sessionmaker() as session:
            # Check that collections were properly initialized.
            collections = list(session.execute(q_collections).scalars())
            assert len(collections), "Collections not found."
            assert not len(
                list(
                    dict(id=cc.id, id_user=cc.id_user)
                    for cc in collections
                    if cc.id_user is not None
                )
            ), "Collections should not have an owner at this point."

            # Check that user corresponds correctly.
            m = session.execute(select(M).where(M.id == 1)).scalar()
            assert m is not None, "User with id `1` should exist."
            assert not len(m.collections), "User should have no collections."

            # Assign collections
            logger.debug("Assigning collections to user with id `1`.")
            m.collections = {cc.name: cc for cc in collections}
            session.commit()

        logger.debug("Verifying reassignment.")
        with sessionmaker() as session:
            # Check that the ids were reassigned.
            _ = select(Collection)
            collections = list(session.execute(_).scalars())
            assert len(collections), "Collections not found."
            assert not len(
                list(
                    dict(id=cc.id, id_user=cc.id_user)
                    for cc in collections
                    if cc.id_user != 1
                )
            )

        logger.debug("Verifiying deletion cascading.")
        with sessionmaker() as session:
            session.delete(m)
            session.commit()

            count = session.execute(
                select(func.count()).select_from(Collection)
            ).scalar()
            assert count == 0

            # Make transient is necessary as the objects
            logger.debug("Regenerating.")
            make_transient(m)
            for collection in m.collections.values():
                make_transient(collection)
            for edit in m.edits:
                make_transient(edit)
            session.add(m)
            session.commit()

        logger.debug("Verifying regeneration.")
        with sessionmaker() as session:
            count = session.execute(select(func.count()).where(User.id == 1)).scalar()
            assert count is not None
            assert count > 0, "User with id `1` not regenerated."

            count = session.execute(
                select(func.count()).select_from(Collection)
            ).scalar()
            assert count is not None
            assert count > 0, f"{collections = }"  # type: ignore

    def test_documents_relationship(
        self,
        sessionmaker: sessionmaker[Session],
    ):
        with sessionmaker() as session:
            # Initially there should be no documents for the user.
            # Clear out directly through the association table.
            logger.debug("Clearing existing associations for user 1.")
            assocs: List[AssocUserDocument] = list(
                session.execute(
                    select(AssocUserDocument).where(AssocUserDocument.id_user == 1)
                ).scalars()
            )
            for assoc in assocs:
                session.delete(assoc)
            session.commit()

            # Verify that the user has no associations.
            logger.debug("Verifying that associations were cleared.")
            user: User | None = session.execute(
                select(User).where(User.id == 1)
            ).scalar()
            assert user is not None
            assert not user.documents, "Expected no documents for users."

            # Reassign these documents using the orm
            logger.debug("Reassigning documents to user 1.")
            documents: List[Document] = list(
                session.execute(
                    q_docs := select(Document).where(Document.id.between(1, 3))
                ).scalars()
            )
            assert len(documents), "Expected to find some documents."
            user.documents = {dd.name: dd for dd in documents}
            session.commit()

        # New session just to be safe
        with sessionmaker() as session:
            logger.debug("Verifying that documents were reassigned.")
            user = session.execute(select(User).where(User.id == 1)).scalar()
            session.refresh(user)
            assert user is not None
            assert user.documents, "Expected documents to be assigned to user."

            logger.debug("Deleting user 1.")
            session.delete(user)
            session.commit()

            # NOTE: Deletion cannot cascade as it would require adding the
            #       access level to the join condition.
            logger.debug("Checking that documents were not deleted.")
            documents = list(session.execute(q_docs).scalars())
            assert documents

            make_transient(user)
            for collection in user.collections.values():
                make_transient(collection)
            for edit in user.edits:
                make_transient(edit)
            session.add(user)
            session.commit()


class TestCollection(BaseModelTest):
    M = Collection

    # def test_user_optional(self, sessionmaker: sessionmaker[Session]):
    #     assert print(id(sessionmaker))
    #     ...

    def test_relationships(self, sessionmaker: sessionmaker[Session]):
        ...


class TestDocument(BaseModelTest):
    M = Document

    @classmethod
    def preload(cls, item: Document) -> Document:
        item.content = bytes(item.content, "utf-8")
        return item

    # def test_whatever(self, sessionmaker: sessionmaker[Session]):
    #     ...


class TestDocumentHistory(BaseModelTest):
    M = DocumentHistory

    @classmethod
    def preload(cls, item: Document) -> Document:
        item.content_previous = bytes(item.content_previous, "utf-8")
        return item
