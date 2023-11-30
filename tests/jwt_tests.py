import pytest

from jwt_tool.JWT import Payload, Header, JWT, Signature


class TestJWT:
    def test_encoding_and_decoding(self):
        """
        Scenario: JWT Encoding and Decoding

        Given a JWT instance with a valid header, payload, and signature.
        When encoding the JWT.
        Then the encoded token should be a non-empty string.
        And When decoding the encoded token.
        Then the decoded payload should match the original payload.
        """
        expected_header = b"eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"

        header = Header("HS256", "JWT")
        given_header = header.urlsafe_b64encode()

        assert given_header == expected_header

        expected_payload = b"eyJpc3MiOiAiam9lIiwgImV4cCI6IDEzMDA4MTkzODAsICJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6IHRydWV9"
        payload = Payload({"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True})

        given_payload = payload.urlsafe_b64encode()

        assert given_payload == expected_payload

        expected_signature = b"bPq2_UTJCTJy5jikbBQWU4AgIZaFG9lIgtBhXFuFQ3I"
        signature = Signature("dWGgphQgrorLKwpJFteFZUDHG4m8b6HDkKnrZT8BbZH3m6X66VbWJVezzzBhHRQMn83wnWoBP7trq8mAKkEnK6Bumk47zDfxbteb", "HS256")
        given_signature = signature.sign(header.urlsafe_b64encode(), payload.urlsafe_b64encode())

        assert given_signature == expected_signature

    def test_jwt_verification(self):
        """
        Scenario: JWT Verification

        Given a JWT instance with a valid header, payload, and signature.
        When verifying the JWT.
        Then the result should be True, indicating that the JWT is valid.
        """
        pass

    def test_jwt_header_update(self):
        """
        Scenario: JWT Header Claim Update

        Given a JWT instance with a valid header, payload, and signature.
        When updating a claim in the header.
        Then the updated header claim should reflect the new value.
        """
        pass

    def test_update_payload(self):
        """
        Scenario: Update Payload

        Given a JWT instance with a valid header, initial payload, and a secret key.
        When updating the payload.
        Then the updated payload should reflect the new values.
        """
        pass

    def test_none_signature(self):
        """
        Scenario: None Signature

        Given a JWT instance with a valid header, payload, and no signature.
        When encoding the JWT.
        Then the encoded token should have no signature.
        """
        pass

    def test_update_payload_without_changing_signature(self):
        """
        Scenario: Update Payload Without Changing Signature

        Given a JWT instance with a valid header, initial payload, and a secret key.
        When updating the payload without changing the signature.
        Then the encoded token should still be valid.
        """
        pass

    def test_update_payload_and_change_signature(self):
        """
        Scenario: Update Payload and Change Signature

        Given a JWT instance with a valid header, initial payload, and a secret key.
        When updating the payload and changing the signature.
        Then the encoded token should be updated with a new signature.
        """
        pass
