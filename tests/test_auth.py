import pytest
from app.auth import PATTERN_BEARER, Auth


@pytest.fixture(scope="session")
def auth(config) -> Auth:
    return Auth.forPyTest(config)


class TestAuth:
    def pattern_tester(self, encoded: str) -> None:
        encoded_split = encoded.split(".")
        encoded_header = f"BeArEr {encoded}"
        assert len(encoded_split) == 3, "JWT should contain two '.'s."

        m = PATTERN_BEARER.match(encoded_header)
        assert m is not None
        assert m.group("header") == encoded_split[0]
        assert m.group("payload") == encoded_split[1]
        assert m.group("signature") == encoded_split[2]
        assert m.group("token") == encoded

    def test_pattern_bearer(self, auth: Auth):
        payload = {"you're": "mom", "its funny": "because it is mispelled."}
        encoded = auth.encode(payload)
        self.pattern_tester(encoded)

        p = PATTERN_BEARER
        assert p.match("spam.eggs.bea?ns.fo%o") is None
        assert p.match("Bearer ...") is None
        assert p.match("Bearer") is None

    def test_pytestauth(self, auth):
        payload = dict(foo="bar", aud=auth.audience, iss=auth.issuer)

        encoded = f"Bearer {auth.encode(payload)}"
        decoded = auth.decode(encoded)

        assert decoded == payload
