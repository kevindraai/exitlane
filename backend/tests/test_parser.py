from exitlane.providers.nordvpn import parse


def test_parser():
    p = parse("Status: Connected\nCountry: Netherlands")
    assert p["Status"] == "Connected" and p["Country"] == "Netherlands"
