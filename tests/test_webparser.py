import pytest

from socanalyzer.webparser import parse_line

FAILED_LINE = '203.0.113.5 - admin [08/Oct/2026:03:14:07 +0000] "POST /login HTTP/1.1" 401 512'
SUCCESS_LINE = '203.0.113.5 - admin [08/Oct/2026:03:14:40 +0000] "POST /login HTTP/1.1" 302 0'
PAGE_VIEW = '198.51.100.7 - - [08/Oct/2026:03:15:00 +0000] "GET /index.html HTTP/1.1" 200 2048'
SIGNIN_LINE = '203.0.113.9 - bob [08/Oct/2026:03:16:00 +0000] "POST /signin HTTP/1.1" 401 512'


def test_401_on_login_is_a_failure():
    event = parse_line(FAILED_LINE, 1)

    assert event.kind == "failed"
    assert event.user == "admin"
    assert event.ip == "203.0.113.5"


def test_redirect_after_login_is_a_success():
    assert parse_line(SUCCESS_LINE, 6).kind == "success"


def test_normal_page_view_is_ignored():
    assert parse_line(PAGE_VIEW, 7) is None


def test_garbage_line_raises():
    with pytest.raises(ValueError):
        parse_line("this is not an access log line", 8)

def test_signin_path_is_treated_as_a_login():
    event = parse_line(SIGNIN_LINE, 1)

    assert event.kind == "failed"
    assert event.user == "bob"