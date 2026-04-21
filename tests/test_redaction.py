from sniffer import mask_ip, redact_text

def test_mask_ip():
    assert mask_ip("192.168.1.25") == "192.168.1.xxx"

def test_redact_email():
    text = "contact me at test@example.com"
    assert "[REDACTED_EMAIL]" in redact_text(text)

def test_redact_token():
    text = "token=abc123"
    assert "token=[REDACTED]" in redact_text(text)

def test_redact_auth_header():
    text = "Authorization: Bearer secretvalue"
    assert "Authorization: [REDACTED_AUTH]" in redact_text(text)

def test_redact_cookie():
    text = "Cookie: sessionid=abc123"
    assert "Cookie: [REDACTED_COOKIE]" in redact_text(text)
