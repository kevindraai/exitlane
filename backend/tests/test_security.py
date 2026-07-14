from exitlane.core import hash_password


def test_hash():
    digest, salt = hash_password("a sufficiently long password")
    assert len(digest) == 128 and len(salt) == 32
