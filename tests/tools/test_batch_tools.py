"""batch_view_files / batch_terminal_execute — sandbox-side concurrency tools.

Exercised with a fake session (no sandbox) covering: order preservation,
per-item error isolation, the batch-size cap, missing-session guard, and that
the reads/execs actually fan out concurrently (bounded).
"""
from __future__ import annotations

import asyncio

from strix.tools.batch import tools as bt


class _Result:
    def __init__(self, stdout="", exit_code=0, stderr=""):
        self.stdout = stdout
        self.exit_code = exit_code
        self.stderr = stderr


class _FakeSession:
    def __init__(self, handler):
        self._handler = handler
        self.max_in_flight = 0
        self._in_flight = 0

    async def exec(self, *args, timeout=60):  # noqa: ARG002 — matches session.exec signature
        self._in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self._in_flight)
        await asyncio.sleep(0.01)  # force overlap so concurrency is observable
        try:
            return self._handler(args)
        finally:
            self._in_flight -= 1


def _view(session, paths):
    return asyncio.run(bt._view_files_impl(session, paths))


def _exec(session, commands):
    return asyncio.run(bt._exec_impl(session, commands))


# ---- batch_view_files -----------------------------------------------------

def test_view_files_reads_all_in_order():
    sess = _FakeSession(lambda args: _Result(stdout=f"content of {args[-1]}"))
    res = _view(sess, ["a.py", "b.py", "c.py"])
    assert res["success"] is True
    assert [r["path"] for r in res["results"]] == ["a.py", "b.py", "c.py"]
    assert "content of /workspace/a.py" in res["results"][0]["content"]


def test_view_files_error_isolated():
    def handler(args):
        if "bad" in args[-1]:
            return _Result(exit_code=1, stderr="No such file")
        return _Result(stdout="ok")
    res = _view(_FakeSession(handler), ["good.py", "bad.py"])
    assert "content" in res["results"][0]           # good read succeeded
    assert "error" in res["results"][1]              # bad read isolated
    assert res["success"] is True                    # batch didn't abort


def test_view_files_runs_concurrently():
    sess = _FakeSession(lambda _a: _Result(stdout="x"))
    _view(sess, [f"f{i}.py" for i in range(6)])
    assert sess.max_in_flight > 1                    # actually overlapped


def test_view_files_cap_enforced():
    res = _view(_FakeSession(lambda _a: _Result()), [f"f{i}" for i in range(51)])
    assert res["success"] is False and "too large" in res["error"]


def test_view_files_no_session():
    res = _view(None, ["a"])
    assert res["success"] is False and "no sandbox session" in res["error"]


def test_view_files_empty_is_ok():
    res = _view(_FakeSession(lambda _a: _Result()), [])
    assert res["success"] is True and res["results"] == []


# ---- batch_terminal_execute -----------------------------------------------

def test_exec_runs_all_in_order():
    sess = _FakeSession(lambda args: _Result(stdout=f"ran: {args[-1]}", exit_code=0))
    res = _exec(sess, ["echo a", "echo b"])
    assert res["success"] is True
    assert [r["command"] for r in res["results"]] == ["echo a", "echo b"]
    assert res["results"][0]["exit_code"] == 0
    assert "ran: echo a" in res["results"][0]["stdout"]


def test_exec_error_isolated():
    def handler(args):
        cmd = args[-1]
        if "fail" in cmd:
            return _Result(exit_code=1, stderr="boom")
        return _Result(stdout="fine", exit_code=0)
    res = _exec(_FakeSession(handler), ["true", "fail-cmd"])
    assert res["results"][0]["exit_code"] == 0
    assert res["results"][1]["exit_code"] == 1 and res["results"][1]["stderr"] == "boom"


def test_exec_cap_enforced():
    res = _exec(_FakeSession(lambda _a: _Result()), [f"echo {i}" for i in range(51)])
    assert res["success"] is False and "too large" in res["error"]
