from exitlane.core import hash_password, verify_password


def test_hash():
    digest, salt = hash_password("a sufficiently long password")
    assert len(digest) == 128 and len(salt) == 32
    assert verify_password("a sufficiently long password", digest, salt)
    assert not verify_password("a different long password", digest, salt)
