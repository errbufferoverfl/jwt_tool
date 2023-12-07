import copy

import pytest

from jwt_tool.JWT import Payload, Header, JWT, SigningConfig


class TestJWT:
    def test_encoding_and_decoding(self):
        """
        Scenario: Encoding and Decoding

        Given a JWT instance with a valid header, payload, and signature.
        When encoding the JWT.
        Then the encoded token should be a non-empty string.
        And When decoding the encoded token.
        Then the decoded payload should match the original payload.
        """
        expected_header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        header = Header("HS256", "JWT")
        given_header = header.encode()
        assert given_header == expected_header, f"Expected header: {expected_header}, but got: {given_header}"

        expected_payload = "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        payload = Payload({"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True})
        given_payload = payload.encode()
        assert given_payload == expected_payload, f"Expected payload: {expected_payload}, but got: {given_payload}"

        expected_signature = "Lk7xNLJ8ReSNz0O-cufFhk6CTJBVkR-0fY57B8LR62U"
        signature = SigningConfig("password", "HS256")
        expected_jwt = f"{expected_header}.{expected_payload}.{expected_signature}"
        given_jwt = JWT(header, payload, signature)
        given_signature = given_jwt.sign()
        assert given_signature == expected_signature, f"Expected signature: {expected_signature}, but got: {given_signature}"
        assert given_jwt.encode() == expected_jwt, f"Expected JWT: {expected_jwt}, but got: {given_jwt.encode()}"

    def test_jwt_header_update(self):
        """
        Scenario: JWT Header Claim Update

        Given a JWT instance with a valid header, payload, and signature.
        When updating a claim in the header.
        Then the updated header claim should reflect the new value.
        """
        expected_header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        header = Header("HS256", "JWT")
        assert header.encode() == expected_header, f"Expected header: {expected_header}, but got: {header.encode()}"

        expected_json_header = b'{"alg":"HS256","typ":"JWT"}'
        assert header.to_json() == expected_json_header, f"Expected JSON header: {expected_json_header}, but got: {header.to_json()}"

        header.add_claim("kid", "https://1password.invalid")

        expected_new_header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imh0dHBzOi8vMXBhc3N3b3JkLmludmFsaWQifQ"
        expected_new_json_header = b'{"alg":"HS256","typ":"JWT","kid":"https://1password.invalid"}'

        assert header.encode() == expected_new_header, f"Expected new header: {expected_new_header}, but got: {header.encode()}"
        assert header.to_json() == expected_new_json_header, f"Expected new JSON header: {expected_new_json_header}, but got: {header.to_json()}"

    def test_update_payload(self):
        """
        Scenario: Update Payload

        Given a JWT instance with a valid header, initial payload, and a secret key.
        When updating the payload.
        Then the updated payload should reflect the new values.
        """
        initial_payload_data = {"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True}
        jwt_instance = JWT(
            header=Header(alg="HS256", typ="JWT"),
            payload=Payload(data=initial_payload_data),
            signing_config=SigningConfig(key="secret_key", algorithm="HS256")
        )

        jwt_instance.payload.add_claim("iat", 1516239022)

        expected_updated_payload = "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9"
        expected_updated_json_payload = b'{"iss":"joe","exp":1300819380,"http://example.com/is_root":true,"iat":1516239022}'

        assert jwt_instance.payload.encode() == expected_updated_payload, f"Expected updated payload: {expected_updated_payload}, but got: {jwt_instance.payload.encode()}"
        assert jwt_instance.payload.to_json() == expected_updated_json_payload, f"Expected updated JSON payload: {expected_updated_json_payload}, but got: {jwt_instance.payload.to_json()}"

    @pytest.mark.usefixtures('valid_jwt_object')
    def test_none_signature(self, valid_jwt_object):
        """
        Scenario: None Signature

        Given a JWT instance with a valid header, payload, and an alg of none, None, NoNe or NONE.
        When encoding the JWT.
        Then the encoded token should have no signature.
        """
        pass

    @pytest.mark.usefixtures('valid_jwt_object')
    def test_update_payload_without_changing_signature(self, valid_jwt_object):
        """
        Scenario: Update Payload Without Changing Signature

        Given a JWT instance with a valid header, initial payload, and a secret key.
        When updating the contents of the payload.
        Then the signature should not change.
        """
        # Create a deep copy of the original JWT object
        original_jwt_object = copy.deepcopy(valid_jwt_object)

        valid_jwt_object.payload.add_claim("iat", 1516239022)

        assert valid_jwt_object._signature == original_jwt_object._signature, f"Signature should not change when updating payload. Expected: {original_jwt_object._signature}, but got: {valid_jwt_object._signature}"

    def test_update_payload_and_change_signature(self):
        """
        Scenario: Update Payload and Change Signature

        Given a JWT instance with a valid header, initial payload, and a secret key.
        When updating the payload and changing the signature.
        Then the encoded token should be updated with a new signature.
        """
        pass

    @pytest.mark.usefixtures('valid_jwt_string')
    @pytest.mark.usefixtures('valid_jwt_no_sig_string')
    @pytest.mark.usefixtures('invalid_jwt_no_header')
    @pytest.mark.usefixtures('invalid_jwt_no_payload')
    def test_create_jwt_from_string(self, valid_jwt_string, valid_jwt_no_sig_string, invalid_jwt_no_header, invalid_jwt_no_payload):
        """
        Scenario: Parsing a valid JWT string

        Given a valid JWT string
        When parsing the JWT string
        Then the resulting JWT object should have the correct header, payload, and signature
        """
        jwt_object = JWT.from_jwt_string(valid_jwt_string)

        assert isinstance(jwt_object, JWT)
        assert isinstance(jwt_object.header, Header)
        assert isinstance(jwt_object.payload, Payload)

        # assert that all the header options are present
        assert (jwt_object.header.alg == "HS256")
        assert (jwt_object.header.typ == "JWT")

        # assert that all the payload properties are present
        assert (jwt_object.payload.get_claim("iss") == "joe")
        assert (jwt_object.payload.get_claim("exp") == 1300819380)
        assert (jwt_object.payload.get_claim("http://example.com/is_root") is True)

        assert jwt_object._signature is not None

        jwt_object = JWT.from_jwt_string(valid_jwt_no_sig_string)
        assert isinstance(jwt_object, JWT)
        assert isinstance(jwt_object.header, Header)
        assert isinstance(jwt_object.payload, Payload)
        assert jwt_object._signature is None

        jwt_object = JWT.from_jwt_string(invalid_jwt_no_header)
        assert jwt_object is None

        jwt_object = JWT.from_jwt_string(invalid_jwt_no_payload)
        assert jwt_object is None
