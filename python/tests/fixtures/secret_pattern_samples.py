"""Synthetic regression samples built ONLY from publicly documented pattern
shapes / placeholder forms. None are real credentials; none were fetched from
any repository. Values are assembled at import time from obvious filler.
"""
_F = "EXAMPLE"  # filler marker

POSITIVE = [  # (expected_type, line)
    ("aws_access_key_id", "aws_key = AKIA" + "IOSFODNN7" + _F),  # AWS docs placeholder shape
    ("github_pat", "token: ghp_" + "x" * 36),
    ("github_fine_grained", "GH=github_pat_" + "X1" * 15),
    ("slack_token", "SLACK=xoxb-" + "0" * 12 + "-" + _F.lower()),
    ("google_api_key", "key=AIza" + "S" * 30),
    ("stripe_key", "STRIPE=sk_live_" + "0" * 24),
    ("private_key_block", "-----BEGIN RSA PRIVATE KEY-----"),
    ("generic_api_key_assignment", "api_key = '" + "a" * 24 + "'"),
    ("generic_api_key_assignment", "ACCESS_TOKEN=" + "Z" * 20),
    ("password_assignment", "password = 'changeme" + _F + "'"),
]

NEGATIVE = [
    "def get_api_key(): return os.environ['API_KEY']",
    "# set your api_key in the dashboard",
    "AKIA is the prefix used by AWS access keys",
    "token = None",
    "url = 'https://example.com/docs'",
]
