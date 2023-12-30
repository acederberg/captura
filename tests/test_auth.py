import pytest
from app.auth import PATTERN_BEARER, Auth


@pytest.fixture(scope="session")
def auth() -> Auth:
    return Auth.forPyTest()


class TestAuth:
    def pattern_tester(self, encoded: str) -> None:
        encoded_split = encoded.split(".")
        encoded_header = f"BeArEr {encoded}"
        assert len(encoded_split) == 3, "JWT should contain two '.'s."

        p = PATTERN_BEARER
        m = p.match(encoded_header)
        assert m is not None
        print(str(m.groups()))
        assert m.group("header") == encoded_split[0]
        assert m.group("payload") == encoded_split[1]
        assert m.group("signature") == encoded_split[2]
        assert m.group("token") == encoded

    def test_pattern_bearer(self, config, auth: Auth):
        payload = {"you're": "mom", "its funny": "because it is mispelled."}
        encoded = auth.encode(config, payload)
        self.pattern_tester(encoded)

        p = PATTERN_BEARER
        assert p.match("spam.eggs.bea?ns.fo%o") is None
        assert p.match("Bearer ...") is None
        assert p.match("Bearer") is None

    def test_pytestauth(self, config, auth):
        payload = dict(
            foo="bar",
            aud=config.auth0.api.audience,
            iss=config.auth0.issuer,
        )

        encoded = auth.encode(config, payload)
        decoded = auth.decode(config, encoded)

        assert decoded == payload
