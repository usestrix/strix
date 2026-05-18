from strix.runtime.docker_runtime import _as_bool, _host_reachable_proxy_url


def test_host_reachable_proxy_url_rewrites_loopback_hosts() -> None:
    assert (
        _host_reachable_proxy_url("socks5h://127.0.0.1:9050")
        == "socks5h://host.docker.internal:9050"
    )
    assert (
        _host_reachable_proxy_url("socks5h://localhost:9050")
        == "socks5h://host.docker.internal:9050"
    )
    assert (
        _host_reachable_proxy_url("socks5h://user:localhost@127.0.0.1:9050")
        == "socks5h://user:localhost@host.docker.internal:9050"
    )


def test_as_bool_accepts_common_truthy_values() -> None:
    assert _as_bool("true") is True
    assert _as_bool("1") is True
    assert _as_bool("yes") is True
    assert _as_bool("false") is False
    assert _as_bool(None) is False
