from app.auth import Auth


class TestAuth:
    def test_pytestauth(self, config):
        auth = Auth.forPyTest()
        payload = dict(
            foo="bar",
            audience=config.auth0.api.audience,
            issuer=config.auth0.issuer,
        )

        encoded = auth.encode(config, payload)
        decoded = auth.decode(config, encoded)

        assert decoded == payload
