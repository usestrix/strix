from strix.skills import get_available_skills, load_skills, validate_requested_skills


WEBSOCKET_SKILL_CATEGORY = "protocols"
WEBSOCKET_SKILL_NAME = "websocket"
WEBSOCKET_SKILL_PATH = f"{WEBSOCKET_SKILL_CATEGORY}/{WEBSOCKET_SKILL_NAME}"
VALID_BASELINE_SEC_WEBSOCKET_KEY = "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
WEBSOCKET_COVERAGE_MARKERS = (
    "Upgrade: websocket",
    VALID_BASELINE_SEC_WEBSOCKET_KEY,
    "Sec-WebSocket-Protocol",
    "CSWSH",
    "Origin",
    "message injection",
    "handshake auth bypass",
)


def test_websocket_skill_is_discoverable() -> None:
    assert WEBSOCKET_SKILL_NAME in get_available_skills()[WEBSOCKET_SKILL_CATEGORY]
    assert validate_requested_skills([WEBSOCKET_SKILL_PATH]) is None


def test_websocket_skill_covers_realtime_attack_surface() -> None:
    skill_content = load_skills([WEBSOCKET_SKILL_PATH])[WEBSOCKET_SKILL_NAME]

    for marker in WEBSOCKET_COVERAGE_MARKERS:
        assert marker in skill_content
