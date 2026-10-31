"""Output rendering for `strix cloud` commands."""

from __future__ import annotations

import json
import re
import sys
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, TypeGuard

from rich.markup import escape
from rich.table import Table

from strix.interface.terminal_text import sanitize_terminal_text


if TYPE_CHECKING:
    from collections.abc import Iterable

    from rich.console import Console


_MAX_TABLE_COLUMNS = 8
_MAX_CELL_LENGTH = 60
_MAX_DETAIL_CELL_LENGTH = 2000
_MAX_DETAIL_FIELDS = 36
_MAX_NESTED_PREVIEW = 5
_NARROW_TABLE_WIDTH = 120
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_COPYABLE_SELECTOR_COLUMNS = frozenset(
    {
        "event_id",
        "id",
        "installation_id",
        "parent_id",
        "path",
        "policy_key",
        "repo_key",
        "retest_scan_id",
        "scan_id",
        "test_user_id",
        "vulnerability_id",
    }
)
_SELECTOR_NO_WRAP_MAX = 40
_INTERNAL_COLUMNS = frozenset(
    {
        "organization_id",
        "user_id",
        "userId",
        "installation_id",
        "added_by",
        "created_by",
        "connected_by",
        "invited_by",
        "uploaded_by",
        "avatarUrl",
    }
)
_LOSSLESS_DETAIL_KEYS = frozenset(
    {
        "api_token",
        "command",
        "docker_command",
        "enrollment_command",
        "secret",
        "signing_secret",
        "token",
        "webhook_secret",
    }
)

_PREFERRED_KEYS = (
    "name",
    "title",
    "repository_full_name",
    "pr_number",
    "pr_title",
    "head_branch",
    "base_branch",
    "verdict",
    "domain",
    "target",
    "default_branch",
    "branch",
    "display_number",
    "status",
    "state",
    "workspace_state",
    "severity",
    "cve",
    "cvss",
    "finding_type",
    "findings_count",
    "open_findings_count",
    "role",
    "email",
    "firstName",
    "lastName",
    "url",
    "provider",
    "secret_prefix",
    "events",
    "action",
    "resource_type",
    "response_status",
    "attempts",
    "scan_type",
    "engagement_type",
    "estimated_credits",
    "cron_expression",
    "timezone",
    "next_run_at",
    "is_active",
    "created_at",
    "updated_at",
    "expires_at",
    "last_used_at",
    "id",
)

_DETAIL_PRIORITY_KEYS = (
    "id",
    "display_number",
    "title",
    "name",
    "status",
    "state",
    "severity",
    "finding_type",
    "cve",
    "cwe",
    "cvss",
    "filed_at",
    "target",
    "location_meta",
    "urls",
    "repositories",
    "internal_targets",
    "endpoint",
    "method",
    "url",
    "events",
    "business_unit",
    "is_active",
    "secret_prefix",
    "last_success_at",
    "last_failure_at",
    "run_id",
    "sandbox_attached",
    "description",
    "impact",
    "technical_analysis",
    "evidence",
    "assumptions",
    "remediation_steps",
    "fix_pr_eligible",
    "fix_pr_reason",
    "fix_pr_url",
    "poc_description",
    "poc_script_code",
    "code_file",
    "code_locations",
    "code_diff",
    "code_before",
    "code_after",
    "dependency_metadata",
    "fix_effort",
    "executive_summary",
    "methodology",
    "recommendations",
    "auth_status",
    "auth_failure_code",
    "auth_detail",
    "scan_scope",
    "findings",
    "duration",
    "created_at",
    "updated_at",
)

_LIST_ENVELOPE_KEYS = frozenset(
    {
        "items",
        "data",
        "scans",
        "agents",
        "chats",
        "vulnerabilities",
        "findings",
        "files",
        "messages",
        "runs",
        "steps",
        "components",
        "domains",
        "repositories",
        "repos",
        "schedules",
        "reviews",
        "pr_reviews",
        "workspaces",
        "members",
        "invitations",
        "integrations",
        "connectors",
        "webhooks",
        "deliveries",
        "entries",
        "documents",
        "docs",
        "policies",
        "tokens",
        "uploads",
        "events",
        "audit_logs",
        "logs",
    }
)
_ENVELOPE_METADATA_KEYS = frozenset(
    {
        "total",
        "total_count",
        "totalCount",
        "count",
        "page",
        "limit",
        "page_size",
        "pageSize",
        "has_more",
        "hasMore",
        "next_cursor",
        "nextCursor",
        "meta",
        "pagination",
        "summary",
        "stats",
        "scansThisMonth",
        "organization_id",
    }
)

_VIEW_COLUMNS: dict[str, tuple[str, ...]] = {
    "GET /scans": (
        "title",
        "target",
        "engagement_type",
        "scan_type",
        "status",
        "findings_count",
        "created_at",
        "id",
    ),
    "GET /vulnerabilities": (
        "display_number",
        "title",
        "severity",
        "status",
        "location",
        "cvss",
        "finding_type",
        "id",
    ),
    "GET /pr-reviews": (
        "repository",
        "pull_request",
        "branches",
        "status",
        "verdict",
        "findings",
        "updated_at",
        "id",
    ),
    "GET /integrations": (
        "provider",
        "account_login",
        "installation_id",
        "instance_url",
        "status",
        "repository_selection",
        "default_collection_name",
        "connected_at",
    ),
    "GET /domains": (
        "domain",
        "asset_type",
        "verified",
        "last_scan_at",
        "context",
        "tags",
        "business_unit",
        "id",
    ),
    "GET /repositories": (
        "full_name",
        "provider",
        "pr_review_enabled",
        "last_scan_at",
        "business_unit",
        "tags",
        "id",
    ),
    "GET /knowledge": (
        "title",
        "source_type",
        "source_id",
        "tags",
        "severity",
        "status",
        "updated_at",
        "id",
    ),
    "GET /knowledge/repos/{repo}/entries": (
        "title",
        "source_type",
        "source_id",
        "tags",
        "severity",
        "status",
        "updated_at",
        "id",
    ),
    "GET /knowledge/repos": ("repo_key", "docs_count", "last_updated_at"),
    "GET /knowledge/policies": (
        "policy_key",
        "policy_type",
        "is_active",
        "policy_value",
        "updated_at",
        "created_at",
        "id",
    ),
    "GET /domains/{domainId}/test-users": (
        "label",
        "username",
        "password",
        "mfa",
        "verification",
        "login_url",
        "updated_at",
        "id",
    ),
    "GET /tokens": (
        "name",
        "type",
        "status",
        "scopes",
        "access",
        "expires_at",
        "last_used_at",
        "id",
    ),
    "GET /chat": ("title", "status", "last_message_at", "created_at", "id"),
    "GET /chat/{chatId}/files": ("path", "size"),
    "GET /chat/{chatId}/findings": (
        "title",
        "severity",
        "status",
        "location",
        "cvss",
        "filed_at",
        "created_at",
        "id",
    ),
    "GET /domains/{domainId}/test-users/{userId}/inbox": (
        "from",
        "subject",
        "detected_code",
        "timestamp",
        "preview",
        "id",
    ),
    "GET /scans/{scanId}/agents": (
        "name",
        "status",
        "task",
        "finding_count",
        "parent_id",
        "created_at",
        "id",
    ),
    "GET /scans/{scanId}/trace": (
        "timestamp",
        "kind",
        "tool_name",
        "status",
        "summary",
        "event_id",
    ),
    "GET /scans/{scanId}/retests": (
        "title",
        "severity",
        "issue_status",
        "retest_status",
        "created_at",
        "vulnerability_id",
        "retest_scan_id",
    ),
    "GET /pr-reviews/findings": (
        "repository",
        "pull_request",
        "pr_state",
        "title",
        "severity",
        "status",
        "created_at",
        "id",
    ),
    "GET /vulnerabilities/{vulnerabilityId}/history": (
        "created_at",
        "previous_status",
        "new_status",
        "snooze",
        "previous_severity",
        "new_severity",
        "note",
        "reason",
    ),
    "GET /repositories/{repositoryId}/supply-chain/findings": (
        "title",
        "package",
        "severity",
        "status",
        "fixed_version",
        "manifest_path",
        "direct",
        "id",
    ),
    "GET /repositories/{repositoryId}/supply-chain/components": (
        "name",
        "version",
        "ecosystem",
        "relationship",
        "status",
        "highest_open_severity",
        "manifest_path",
        "id",
    ),
    "GET /schedules": (
        "name",
        "target",
        "cron_expression",
        "timezone",
        "state",
        "last_run_status",
        "next_run_at",
        "id",
    ),
    "GET /connectors": ("name", "last_status", "last_status_checked_at", "created_at", "id"),
    "GET /organization/members": (
        "email",
        "firstName",
        "lastName",
        "role",
        "access",
        "status",
        "joinedAt",
        "id",
    ),
    "GET /organization/invitations": (
        "email",
        "role",
        "access",
        "state",
        "expiresAt",
        "createdAt",
        "id",
    ),
    "GET /webhooks": (
        "url",
        "events",
        "is_active",
        "business_unit",
        "last_success_at",
        "last_failure_at",
        "created_at",
        "id",
    ),
    "GET /webhooks/{webhookId}/deliveries": (
        "event_type",
        "status",
        "response_status",
        "last_error",
        "attempts",
        "sent_at",
        "next_attempt_at",
        "id",
    ),
    "GET /audit": (
        "action",
        "resource_type",
        "resource_id",
        "actor_email",
        "ip_address",
        "created_at",
    ),
    "supply_chain_totals": (
        "repositories",
        "components",
        "findings",
        "open_issues",
        "malicious",
        "suspicious",
        "vulnerable",
    ),
    "supply_chain_repositories": (
        "repository",
        "components",
        "findings",
        "severity",
        "risks",
        "latest_scan",
        "policy",
        "id",
    ),
    "chat_credentials_attached": (
        "label",
        "username",
        "login_url",
        "mfa_method",
        "password",
        "totp",
        "test_user_id",
    ),
    "chat_credentials_test_users": (
        "label",
        "username",
        "domain",
        "login_url",
        "mfa_method",
        "password",
        "totp",
        "id",
    ),
    "chat_credentials_scans": (
        "scan_title",
        "username",
        "login_url",
        "mfa_method",
        "password",
        "totp",
        "scan_id",
    ),
}

_VIEW_LIST_KEYS: dict[str, str] = {
    "GET /chat": "chats",
    "GET /chat/{chatId}/files": "files",
    "GET /chat/{chatId}/findings": "findings",
    "GET /domains/{domainId}/test-users/{userId}/inbox": "messages",
    "GET /scans/{scanId}/agents": "agents",
    "GET /scans/{scanId}/trace": "steps",
    "GET /scans/{scanId}/retests": "runs",
    "GET /pr-reviews/findings": "items",
    "GET /vulnerabilities/{vulnerabilityId}/history": "items",
    "GET /knowledge/repos/{repo}/entries": "docs",
    "GET /repositories/{repositoryId}/supply-chain/findings": "findings",
    "GET /repositories/{repositoryId}/supply-chain/components": "components",
    "GET /schedules": "schedules",
    "GET /organization/members": "members",
    "GET /organization/invitations": "invitations",
}

_DETAIL_ENVELOPE_KEYS: dict[str, str] = {
    "GET /chat/{chatId}": "chat",
    "GET /webhooks/{webhookId}": "webhook",
}


def _is_record(value: object) -> TypeGuard[dict[str, Any]]:
    return isinstance(value, dict)


def _is_list(value: object) -> TypeGuard[list[Any]]:
    return isinstance(value, list)


def json_mode(*, flag: bool) -> bool:
    """JSON output is on when the flag is set or when stdout is not a terminal."""
    return flag or not sys.stdout.isatty()


def emit(  # noqa: PLR0911, PLR0912, PLR0915
    console: Console,
    data: Any,
    *,
    as_json: bool,
    row_numbers: bool = False,
    omit_columns: frozenset[str] = frozenset(),
    hint: str | None = None,
    view: str | None = None,
    warning: str | None = None,
) -> None:
    if as_json:
        sys.stdout.write(json.dumps(data, indent=2, default=str) + "\n")
        return
    if warning:
        console.print(f"[bold yellow]Save this now:[/] {escape(sanitize_terminal_text(warning))}")
    hint = _combine_hints(hint, _pagination_hint(data))
    if view == "source_manifest" and _is_record(data):
        _print_source_manifest(console, data)
        return
    if view == "GET /analytics/scan-frequency":
        _print_scan_frequency(console, data)
        return
    if view in {"GET /analytics/overview", "GET /analytics/stats"} and _is_record(data):
        _print_analytics(console, data)
        return
    if view == "GET /supply-chain/summary" and _is_record(data):
        _print_supply_chain_summary(console, data)
        return
    if view == "GET /chat/{chatId}/credentials" and _is_record(data):
        _print_chat_credentials(console, data)
        return
    detail_key = _DETAIL_ENVELOPE_KEYS.get(view or "")
    if detail_key and _is_record(data):
        detail = data.get(detail_key)
        if _is_record(detail):
            _print_detail(console, _detail_envelope_record(detail, view))
            return
    if view == "GET /integrations":
        integration_rows = _integration_rows(data)
        if integration_rows is not None:
            _print_table(
                console,
                integration_rows,
                row_numbers=row_numbers,
                omit_columns=omit_columns,
                hint=hint,
                view=view,
            )
            return
    if view == "GET /tokens":
        token_rows = _token_rows(data)
        if token_rows is not None:
            _print_table(
                console,
                token_rows,
                row_numbers=row_numbers,
                omit_columns=omit_columns,
                hint=hint,
                view=view,
            )
            return
    if view == "GET /scans":
        scan_rows = _scan_rows(data)
        if scan_rows is not None:
            _print_table(
                console,
                scan_rows,
                row_numbers=False,
                omit_columns=omit_columns,
                hint=_combine_hints("Inspect one scan with `strix cloud scans get ID`.", hint),
                view=view,
            )
            return
    if view == "GET /vulnerabilities":
        vulnerability_rows = _finding_location_rows(data)
        if vulnerability_rows is not None:
            _print_table(
                console,
                vulnerability_rows,
                row_numbers=False,
                omit_columns=omit_columns | frozenset({"scan_id"}),
                hint=_combine_hints("Inspect one finding with `strix cloud vulns get ID`.", hint),
                view=view,
            )
            return
    if view == "GET /pr-reviews":
        review_rows = _pr_review_rows(data)
        if review_rows is not None:
            _print_table(
                console,
                review_rows,
                row_numbers=False,
                omit_columns=omit_columns,
                hint=_combine_hints(
                    "Use `strix cloud pr-reviews get ID` for one review.",
                    _view_hint(data, view),
                    hint,
                ),
                view=view,
            )
            return
    view_rows = _rows_for_view(data, view)
    if view_rows is not None:
        _print_table(
            console,
            view_rows,
            row_numbers=row_numbers,
            omit_columns=omit_columns,
            hint=_combine_hints(_view_hint(data, view), hint),
            view=view,
        )
        return
    rows = _list_of_dicts(data)
    if rows is not None:
        _print_table(
            console,
            rows,
            row_numbers=row_numbers,
            omit_columns=omit_columns,
            hint=hint,
            view=view,
        )
        return
    if isinstance(data, str):
        console.print(sanitize_terminal_text(data), markup=False)
        return
    if _is_record(data):
        _print_detail(console, data)
        return
    console.print_json(json.dumps(data, default=str))


def _list_of_dicts(data: Any) -> list[dict[str, Any]] | None:
    """Extract a record list from a raw list or a common paginated envelope."""
    if _is_record(data):
        # Some endpoints wrap the actual envelope in a top-level ``data`` or
        # ``result`` object. Only recurse through an object wrapper; a list in
        # ``data`` is handled with the other named envelope keys below.
        for wrapper in ("data", "result"):
            nested = data.get(wrapper)
            if _is_record(nested):
                nested_rows = _list_of_dicts(nested)
                if nested_rows is not None:
                    return nested_rows
        candidates = [
            (key, value)
            for key, value in data.items()
            if key in _LIST_ENVELOPE_KEYS
            and _is_list(value)
            and all(_is_record(item) for item in value)
        ]
        if len(candidates) == 1:
            list_key, records = candidates[0]
            other_keys = set(data) - {list_key}
            if list_key in {"items", "data"} or other_keys <= _ENVELOPE_METADATA_KEYS:
                data = records
    if not _is_list(data):
        return None
    if not data:
        return []
    records = [item for item in data if _is_record(item)]
    if len(records) != len(data):
        return None
    return records


def _records_at_key(data: Any, key: str) -> list[dict[str, Any]] | None:
    """Extract one deliberate collection even when an envelope has other lists."""
    if _is_list(data):
        return _list_of_dicts(data)
    if not _is_record(data):
        return None
    value = data.get(key)
    if not _is_list(value) or not all(_is_record(item) for item in value):
        return None
    return list(value)


def _detail_envelope_record(data: dict[str, Any], view: str | None) -> dict[str, Any]:
    record = dict(data)
    if view == "GET /webhooks/{webhookId}" and not record.get("business_unit"):
        record["business_unit"] = "all organization"
    if view == "GET /chat/{chatId}":
        record["sandbox_attached"] = bool(record.pop("sandbox_api_url", False))
    return record


def _rows_for_view(data: Any, view: str | None) -> list[dict[str, Any]] | None:
    """Shape non-standard list envelopes into compact, actionable rows."""
    if view == "GET /domains/{domainId}/test-users":
        return _test_user_rows(data)
    key = _VIEW_LIST_KEYS.get(view or "")
    if key is None:
        return None
    records = _records_at_key(data, key)
    if records is None:
        return None
    transforms = {
        "GET /scans/{scanId}/trace": _trace_rows,
        "GET /chat/{chatId}/findings": _finding_location_rows,
        "GET /pr-reviews/findings": _pr_finding_rows,
        "GET /vulnerabilities/{vulnerabilityId}/history": _vulnerability_history_rows,
        "GET /repositories/{repositoryId}/supply-chain/findings": (_supply_chain_finding_rows),
        "GET /schedules": _schedule_rows,
        "GET /organization/members": _access_rows,
        "GET /organization/invitations": _access_rows,
    }
    transform = transforms.get(view or "")
    return transform(records) if transform else records


def _view_hint(data: Any, view: str | None) -> str | None:
    hint: str | None = None
    if view == "GET /scans/{scanId}/trace" and _is_record(data):
        hint = _trace_view_hint(data)
    elif view == "GET /scans/{scanId}/retests" and _is_record(data):
        total = data.get("total")
        completed = data.get("completed")
        running = data.get("running")
        if all(isinstance(value, int) for value in (total, completed, running)):
            hint = f"{completed}/{total} retest(s) complete; {running} running."
    elif view == "GET /knowledge/repos/{repo}/entries" and _is_record(data):
        hint = _knowledge_repo_hint(data)
    elif view == "GET /pr-reviews" and _is_record(data):
        hint = _metric_hint(
            "Review counts",
            data.get("counts"),
            ("all", "open", "attention", "merged_open", "passed", "running"),
        )
    elif view == "GET /pr-reviews/findings" and _is_record(data):
        hint = _metric_hint(
            "Impact",
            data.get("stats"),
            ("prs_reviewed", "issues_found", "critical_high_found", "merges_blocked"),
        )
    elif view == "GET /domains/{domainId}/test-users/{userId}/inbox" and _is_record(data):
        address = data.get("address")
        if isinstance(address, str) and address.strip():
            hint = f"Inbox: {sanitize_terminal_text(address.strip())}."
    elif view == "GET /schedules":
        hint = "Inspect one schedule with `strix cloud schedules get ID`."
    return hint


def _trace_view_hint(data: dict[str, Any]) -> str | None:
    scan_id = data.get("scan_id")
    suffix = f" {scan_id}" if scan_id else " SCAN_ID"
    parts = [
        f"Inspect a complete event with `strix cloud scans trace-event{suffix} EVENT_ID`; "
        "use --json for full tool arguments and results."
    ]
    cursor = data.get("cursor")
    if data.get("has_more") and isinstance(cursor, str) and cursor:
        parts.append(
            f"Continue the same trace command with `--cursor {cursor}`; keep its "
            "--agent-id, --tool-name, and --limit options."
        )
    note = data.get("note")
    if isinstance(note, str) and note.strip():
        parts.append(note.strip())
    return _combine_hints(*parts)


def _knowledge_repo_hint(data: dict[str, Any]) -> str | None:
    parts: list[str] = []
    profile = data.get("profile")
    if _is_record(profile):
        title = sanitize_terminal_text(str(profile.get("title") or "present"))
        parts.append(f"Repository profile: {title}.")
    policies = data.get("policies")
    if _is_list(policies):
        noun = "policy" if len(policies) == 1 else "policies"
        parts.append(f"{len(policies)} {noun} apply.")
    if parts:
        parts.append("Use --json to view the profile and policy metadata.")
    return _combine_hints(*parts)


def _metric_hint(label: str, value: Any, keys: tuple[str, ...]) -> str | None:
    if not _is_record(value):
        return None
    metrics = [
        f"{_human_label(key)} {value[key]}" for key in keys if isinstance(value.get(key), int)
    ]
    return f"{label}: {', '.join(metrics)}." if metrics else None


def _combine_hints(*hints: str | None) -> str | None:
    combined = " ".join(hint.strip() for hint in hints if hint and hint.strip())
    return combined or None


def _pagination_hint(data: Any) -> str | None:
    """Explain how to continue a paginated human list without hiding API metadata."""
    if not _is_record(data):
        return None
    candidates = [data.get(key) for key in ("meta", "pagination")]
    for pagination in candidates:
        if not _is_record(pagination):
            continue
        message = _pagination_message(pagination)
        if message:
            return message
    for wrapper in ("data", "result"):
        nested = data.get(wrapper)
        if _is_record(nested):
            hint = _pagination_hint(nested)
            if hint:
                return hint
    return None


def _pagination_message(pagination: dict[str, Any]) -> str | None:
    page = pagination.get("page")
    total_pages = pagination.get("total_pages")
    total = pagination.get("total_items", pagination.get("total"))
    has_next = pagination.get("has_next")
    if isinstance(page, int) and isinstance(total_pages, int):
        return _page_pagination_message(page, total_pages, total, has_next=has_next)

    offset = pagination.get("offset")
    limit = pagination.get("limit")
    if not isinstance(offset, int) or not isinstance(limit, int) or not isinstance(total, int):
        return None
    if total <= 0:
        return "0 total."
    if offset >= total:
        last_offset = max(0, ((total - 1) // max(1, limit)) * max(1, limit))
        return f"No items at offset {offset}; {total} total. Retry with `--offset {last_offset}`."
    shown_through = min(offset + limit, total)
    message = f"Showing {offset + 1}-{shown_through} of {total}."
    if offset + limit < total:
        message += f" Continue with `--offset {offset + limit}`."
    return message


def _page_pagination_message(page: int, total_pages: int, total: Any, *, has_next: Any) -> str:
    if total == 0:
        return "0 total."
    last_page = max(1, total_pages)
    if page > last_page:
        total_note = f"; {total} total" if isinstance(total, int) else ""
        return f"No items on page {page}{total_note}. Retry with `--page {last_page}`."
    parts = [f"Page {page}/{last_page}"]
    if isinstance(total, int):
        parts.append(f"{total} total")
    message = " · ".join(parts) + "."
    if (has_next is True or page < total_pages) and page >= 0:
        message += f" Continue with `--page {page + 1}`."
    return message


def _test_user_rows(data: Any) -> list[dict[str, Any]] | None:
    records = _records_at_key(data, "items")
    if records is None:
        return None
    checks = data.get("auth_checks") if _is_record(data) else None
    rows: list[dict[str, Any]] = []
    for record in records:
        row = dict(record)
        row["password"] = "set" if record.get("has_password") else "not set"
        method = str(record.get("mfa_method") or "none")
        if method == "totp":
            row["mfa"] = "totp (secret set)" if record.get("has_totp_secret") else "totp (missing)"
        elif method in {"email_otp", "magic_link"}:
            address = str(record.get("mfa_email") or "address missing")
            row["mfa"] = f"{method}: {address}"
        elif record.get("has_totp_secret"):
            row["mfa"] = "none (TOTP secret stored)"
        else:
            row["mfa"] = "none"

        check: Any = None
        if _is_record(checks):
            check = checks.get(str(record.get("id") or ""))
        elif _is_list(checks):
            check = next(
                (
                    candidate
                    for candidate in checks
                    if _is_record(candidate) and candidate.get("test_user_id") == record.get("id")
                ),
                None,
            )
        if _is_record(check):
            status = str(check.get("status") or "unknown")
            failure = str(check.get("failure_code") or "").strip()
            row["verification"] = f"{status}: {failure}" if failure else status
        else:
            row["verification"] = "not checked"
        rows.append(row)
    return rows


def _trace_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        row = dict(record)
        finding = record.get("finding")
        if _is_record(finding):
            title = str(finding.get("title") or "finding")
            severity = str(finding.get("severity") or "").strip()
            row["summary"] = f"{severity}: {title}" if severity else title
        elif record.get("result") is not None:
            row["summary"] = _trace_payload_shape("result", record["result"])
        elif record.get("args") is not None:
            row["summary"] = _trace_payload_shape("arguments", record["args"])
        elif record.get("content") is not None:
            row["summary"] = _trace_payload_shape("message", record["content"])
        rows.append(row)
    return rows


def _trace_payload_shape(label: str, value: Any) -> str:
    """Describe trace payload structure without leaking credentials or response bodies."""
    if _is_record(value):
        return f"{label}: {len(value)} field(s)"
    if _is_list(value):
        return f"{label}: {len(value)} item(s)"
    if value is None:
        return f"{label}: empty"
    text = str(value)
    kind = "text" if isinstance(value, str) else type(value).__name__
    return f"{label}: {kind} ({len(text)} character(s))"


def _pr_finding_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        row = dict(record)
        row["repository"] = record.get("repository_full_name")
        number = record.get("pr_number")
        title = str(record.get("pr_title") or "").strip()
        row["pull_request"] = " ".join(
            part for part in (f"#{number}" if number is not None else "", title) if part
        )
        rows.append(row)
    return rows


def _finding_location_rows(data: Any) -> list[dict[str, Any]] | None:
    records = _list_of_dicts(data)
    if records is None:
        return None
    rows: list[dict[str, Any]] = []
    for record in records:
        row = dict(record)
        endpoint = str(record.get("endpoint") or "").strip()
        method = str(record.get("method") or "").strip().upper()
        target = str(record.get("target") or "").strip()
        row["location"] = f"{method} {endpoint}".strip() if endpoint else target
        rows.append(row)
    return rows


def _supply_chain_finding_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        row = dict(record)
        name = str(record.get("package_name") or "").strip()
        version = str(record.get("package_version") or "").strip()
        row["package"] = f"{name}@{version}" if name and version else name or version
        rows.append(row)
    return rows


def _schedule_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        row = dict(record)
        row["cron_expression"] = record.get("cron") or record.get("cron_expression")
        row["state"] = "paused" if record.get("isPaused") else "active"
        targets: list[str] = []
        if record.get("supply_chain") is True:
            targets.append("supply chain")
        for key, singular in (("domain_ids", "domain"), ("repository_ids", "repo")):
            values = record.get(key)
            if _is_list(values) and values:
                noun = singular if len(values) == 1 else f"{singular}s"
                targets.append(f"{len(values)} {noun}")
        internal_targets = record.get("internal_targets")
        if _is_list(internal_targets) and internal_targets:
            first = sanitize_terminal_text(str(internal_targets[0]))
            suffix = f" (+{len(internal_targets) - 1} more)" if len(internal_targets) > 1 else ""
            targets.append(f"{first}{suffix}")
        if record.get("connector_id"):
            targets.append("network connector")
        row["target"] = " · ".join(targets) if targets else "no targets"
        rows.append(row)
    return rows


def _access_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        row = dict(record)
        row["access"] = _scope_summary(record.get("scopes"))
        rows.append(row)
    return rows


def _scope_summary(scopes: Any) -> str:
    if not _is_list(scopes) or not scopes:
        return "all assets"
    labels: list[str] = []
    for scope in scopes[:2]:
        if _is_record(scope):
            scope_type = str(scope.get("type") or "scope").strip()
            value = str(scope.get("value") or "").strip()
            labels.append(f"{scope_type}:{value}" if value else scope_type)
        else:
            labels.append(str(scope))
    suffix = f" (+{len(scopes) - len(labels)} more)" if len(scopes) > len(labels) else ""
    return ", ".join(labels) + suffix


def _credential_summary_rows(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    records = _records_at_key(data, key) or []
    rows: list[dict[str, Any]] = []
    for record in records:
        row = dict(record)
        row["password"] = "set" if record.get("has_password") else "not set"
        row["totp"] = "set" if record.get("has_totp_secret") else "not set"
        rows.append(row)
    return rows


def _print_chat_credentials(console: Console, data: dict[str, Any]) -> None:
    """Render attached and attachable credential metadata without exposing secrets."""
    sections = (
        (
            "Attached credentials",
            _credential_summary_rows(data, "credentials"),
            "chat_credentials_attached",
            None,
        ),
        (
            "Available saved test users",
            _credential_summary_rows(data, "available_test_users"),
            "chat_credentials_test_users",
            "Attach one with `strix cloud chat credentials set CHAT_ID --test-user-ids ID`.",
        ),
        (
            "Credentials from requested scans",
            _credential_summary_rows(data, "available_scan_credentials"),
            "chat_credentials_scans",
            (
                "Discover these with `strix cloud chat credentials CHAT_ID --scan-ids SCAN_ID`; "
                "attach them with `strix cloud chat credentials set CHAT_ID --scan-ids SCAN_ID`."
            ),
        ),
    )
    for title, rows, section_view, section_hint in sections:
        console.print(f"[bold]{title}[/]")
        _print_table(
            console,
            rows,
            view=section_view,
            hint=section_hint,
            show_json_hint=False,
        )
    console.print("[dim]Use --json for the complete credential metadata.[/]")


def _integration_rows(data: Any) -> list[dict[str, Any]] | None:
    """Flatten the two integration collections into one compact human view."""
    if not _is_record(data):
        return _list_of_dicts(data)
    rows: list[dict[str, Any]] = []
    found_collection = False
    for key in ("integrations", "merge_accounts"):
        collection = data.get(key)
        if not _is_list(collection):
            continue
        found_collection = True
        for item in collection:
            if not _is_record(item):
                continue
            row = dict(item)
            if not row.get("account_login") and row.get("account_email"):
                row["account_login"] = row["account_email"]
            rows.append(row)
    return rows if found_collection else None


def _token_rows(data: Any) -> list[dict[str, Any]] | None:
    """Add an explicit lifecycle state to token rows for the human view."""
    records = _list_of_dicts(data)
    if records is None:
        return None
    rows: list[dict[str, Any]] = []
    for record in records:
        row = dict(record)
        row["access"] = _scope_summary(record.get("rbac_scopes"))
        if record.get("revoked_at"):
            row["status"] = "revoked"
        elif _timestamp_has_passed(record.get("expires_at")):
            row["status"] = "expired"
        else:
            row["status"] = "active"
        rows.append(row)
    return rows


def _timestamp_has_passed(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed <= datetime.now(UTC)


def _scan_rows(data: Any) -> list[dict[str, Any]] | None:
    """Flatten the nested target and finding summaries returned by scan lists."""
    records = _list_of_dicts(data)
    if records is None:
        return None
    rows: list[dict[str, Any]] = []
    for record in records:
        row = dict(record)
        if not row.get("title") and row.get("name"):
            row["title"] = row["name"]
        if not row.get("id") and isinstance(row.get("scan_id"), str):
            row["id"] = row["scan_id"]

        targets = _scan_targets(record)
        if targets:
            visible_targets = targets[:2]
            summary = " | ".join(visible_targets)
            if len(targets) > len(visible_targets):
                summary += f" (+{len(targets) - len(visible_targets)} more)"
            row["target"] = summary

        findings = record.get("findings")
        if _is_record(findings) and findings.get("total") is not None:
            row["findings_count"] = findings["total"]
        rows.append(row)
    return rows


def _scan_targets(record: dict[str, Any]) -> list[str]:
    targets: list[str] = []
    urls = record.get("urls")
    if _is_list(urls):
        targets.extend(url.strip() for url in urls if isinstance(url, str) and url.strip())
    repositories = record.get("repositories")
    if _is_list(repositories):
        for repository in repositories:
            if not _is_record(repository):
                continue
            identifier = str(
                repository.get("full_name") or repository.get("name") or repository.get("url") or ""
            ).strip()
            branch = str(repository.get("branch") or "").strip()
            if identifier:
                targets.append(f"{identifier} @ {branch}" if branch else identifier)
    internal_targets = record.get("internal_targets")
    if _is_list(internal_targets):
        targets.extend(
            target.strip()
            for target in internal_targets
            if isinstance(target, str) and target.strip()
        )
    if record.get("has_code_upload") is True:
        targets.append("uploaded source")
    return targets


def _pr_review_rows(data: Any) -> list[dict[str, Any]] | None:
    """Collapse related PR fields into an eight-column, action-oriented human view."""
    records = _list_of_dicts(data)
    if records is None:
        return None
    rows: list[dict[str, Any]] = []
    for record in records:
        row = dict(record)
        number = record.get("pr_number")
        title = str(record.get("pr_title") or "").strip()
        row["repository"] = record.get("repository_full_name") or record.get("repository")
        pull_request = " ".join(
            part for part in (f"#{number}" if number is not None else "", title) if part
        )
        pr_state = str(record.get("pr_state") or "").strip()
        row["pull_request"] = f"{pull_request} [{pr_state}]" if pr_state else pull_request
        head = str(record.get("head_branch") or "").strip()
        base = str(record.get("base_branch") or "").strip()
        row["branches"] = f"{head} → {base}" if head and base else head or base
        findings = record.get("findings")
        total = findings.get("total") if _is_record(findings) else None
        unresolved = findings.get("unresolved") if _is_record(findings) else None
        opened = unresolved.get("total") if _is_record(unresolved) else None
        if not isinstance(total, int):
            total = record.get("findings_count")
        if not isinstance(opened, int):
            opened = record.get("open_findings_count")
        if isinstance(total, int) and isinstance(opened, int):
            row["findings"] = f"{opened} open / {total} total"
        elif isinstance(total, int):
            row["findings"] = total
        rows.append(row)
    return rows


def _vulnerability_history_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        row = dict(record)
        previous = record.get("previous_snoozed_until")
        current = record.get("new_snoozed_until")
        if previous != current:
            if previous and current:
                row["snooze"] = f"{previous} → {current}"
            elif current:
                row["snooze"] = f"set until {current}"
            else:
                row["snooze"] = f"cleared (was {previous})"
        rows.append(row)
    return rows


def _print_table(
    console: Console,
    rows: list[dict[str, Any]],
    *,
    row_numbers: bool = False,
    omit_columns: frozenset[str] = frozenset(),
    hint: str | None = None,
    view: str | None = None,
    show_json_hint: bool = True,
) -> None:
    if not rows:
        console.print("[dim]No items.[/]")
        if hint:
            console.print(f"[dim]{escape(sanitize_terminal_text(hint))}[/]")
        return
    integration_view = view == "GET /integrations"
    visible_internal: set[str] = {"installation_id"} if integration_view else set()
    view_omissions: set[str] = {"id"} if integration_view else set()
    omit_columns = omit_columns | (_INTERNAL_COLUMNS - visible_internal) | view_omissions
    preferred = _VIEW_COLUMNS.get(view or "", _PREFERRED_KEYS)
    columns: list[str] = [
        key
        for key in preferred
        if key not in omit_columns and any(_meaningful(row.get(key)) for row in rows)
    ]
    if view not in _VIEW_COLUMNS:
        _append_fallback_columns(rows, columns, omit_columns)
    columns = columns[:_MAX_TABLE_COLUMNS]
    if console.width < _NARROW_TABLE_WIDTH:
        _print_cards(console, rows, columns, row_numbers=row_numbers)
        _print_copyable_selectors(console, rows, columns)
        footer = f"{len(rows)} item(s)."
        if show_json_hint:
            footer += " Use --json for the full records."
        console.print(f"[dim]{footer}[/]")
        if hint:
            console.print(f"[dim]{escape(sanitize_terminal_text(hint))}[/]")
        return
    table = Table(show_lines=False)
    if row_numbers:
        table.add_column("#", justify="right", style="cyan", no_wrap=True)
    for column in columns:
        table.add_column(
            escape(_human_label(column)),
            no_wrap=_selector_can_no_wrap(column, rows),
        )
    for index, row in enumerate(rows, start=1):
        cells = [escape(_cell(row.get(column))) for column in columns]
        if row_numbers:
            cells.insert(0, str(index))
        table.add_row(*cells)
    console.print(table)
    _print_copyable_selectors(console, rows, columns)
    footer = f"{len(rows)} item(s)."
    if show_json_hint:
        footer += " Use --json for the full records."
    console.print(f"[dim]{footer}[/]")
    if hint:
        console.print(f"[dim]{escape(sanitize_terminal_text(hint))}[/]")


def _print_cards(
    console: Console,
    rows: list[dict[str, Any]],
    columns: list[str],
    *,
    row_numbers: bool,
) -> None:
    """Render list rows legibly when a terminal is too narrow for a table."""
    for index, row in enumerate(rows, start=1):
        parts = [
            f"[bold]{escape(_human_label(column))}:[/] {escape(_cell(row.get(column)))}"
            for column in columns
            if row.get(column) is not None
        ]
        prefix = f"[cyan]{index}.[/] " if row_numbers else "[cyan]•[/] "
        if not parts:
            console.print(prefix.rstrip())
            continue
        console.print(prefix + parts[0], soft_wrap=True)
        continuation = "   " if row_numbers else "  "
        for part in parts[1:]:
            console.print(continuation + part, soft_wrap=True)


def _append_fallback_columns(
    rows: list[dict[str, Any]],
    columns: list[str],
    omit_columns: frozenset[str],
) -> None:
    for row in rows:
        for key in row:
            if (
                key not in columns
                and key not in omit_columns
                and len(columns) < _MAX_TABLE_COLUMNS
                and not isinstance(row[key], dict | list)
            ):
                columns.append(key)


def _meaningful(value: Any) -> bool:
    return value is not None and value not in ("", [], {})


def _is_selector_column(column: str) -> bool:
    return column in _COPYABLE_SELECTOR_COLUMNS


def _selector_can_no_wrap(column: str, rows: list[dict[str, Any]]) -> bool:
    return _is_selector_column(column) and all(
        len(str(row[column])) <= _SELECTOR_NO_WRAP_MAX
        for row in rows
        if row.get(column) is not None
    )


def _print_copyable_selectors(
    console: Console,
    rows: list[dict[str, Any]],
    columns: list[str],
) -> None:
    """Print command selectors losslessly when their compact cell is shortened."""
    selector_columns = [column for column in columns if _is_selector_column(column)]
    selectors = [
        (index, row, column, str(row[column]))
        for index, row in enumerate(rows, start=1)
        for column in selector_columns
        if row.get(column) is not None and len(str(row[column])) > _SELECTOR_NO_WRAP_MAX
    ]
    if not selectors:
        return
    console.print("[dim]Copyable selectors:[/]")
    for index, row, column, value in selectors:
        label = next(
            (
                str(row[key])
                for key in ("title", "name", "label", "domain", "full_name")
                if row.get(key)
            ),
            f"item {index}",
        )
        console.print(
            f"  {index}. {sanitize_terminal_text(label)} ({_human_label(column)}): "
            f"{sanitize_terminal_text(value)}",
            markup=False,
            soft_wrap=True,
        )


def _print_detail(console: Console, data: dict[str, Any]) -> None:
    """Render one API record as a readable field/value view."""
    keys = [key for key in _DETAIL_PRIORITY_KEYS if key in data and key not in _INTERNAL_COLUMNS]
    keys.extend(
        key
        for key in _PREFERRED_KEYS
        if key in data and key not in keys and key not in _INTERNAL_COLUMNS
    )
    keys.extend(key for key in data if key not in keys and key not in _INTERNAL_COLUMNS)
    table = Table(show_header=False, show_edge=False, box=None, padding=(0, 2))
    table.add_column("field", style="bold cyan", no_wrap=True)
    table.add_column("value", overflow="fold")
    populated_keys = [key for key in keys if data.get(key) is not None]
    visible_keys = populated_keys[:_MAX_DETAIL_FIELDS]
    lossless_fields: list[tuple[str, Any]] = []
    for key in visible_keys:
        value = data.get(key)
        if _is_lossless_detail(key, value):
            lossless_fields.append((key, value))
            continue
        rendered = (
            _nested_summary(value) if _is_record(value) or _is_list(value) else _detail_cell(value)
        )
        table.add_row(escape(_human_label(key)), escape(rendered))
    if table.row_count:
        console.print(table)
    for key, value in lossless_fields:
        console.print(f"{_human_label(key)}:", style="bold cyan", markup=False)
        console.print(_lossless_detail_value(value), markup=False, soft_wrap=True)
    if len(populated_keys) > len(visible_keys):
        console.print(
            f"[dim]{len(populated_keys) - len(visible_keys)} additional field(s) omitted from "
            "this view.[/]"
        )
    console.print("[dim]Use --json for the lossless machine-readable record.[/]")


def _is_lossless_detail(key: str, value: Any) -> bool:
    """Keep one-time credentials and enrollment commands complete and copyable."""
    sensitive_key = key in _LOSSLESS_DETAIL_KEYS or key.endswith(("_token", "_secret"))
    return sensitive_key and not _is_record(value) and not _is_list(value)


def _lossless_detail_value(value: Any) -> str:
    """Preserve structural newlines while making every other control byte visible."""
    return "\n".join(sanitize_terminal_text(line) for line in str(value).split("\n"))


def _nested_summary(value: dict[str, Any] | list[Any]) -> str:
    """Bound nested records so one detail response cannot flood a terminal."""
    if _is_record(value):
        scalar_items = [
            (nested_key, nested_value)
            for nested_key, nested_value in value.items()
            if not isinstance(nested_value, dict | list) and nested_value is not None
        ]
        lines = [
            f"{_human_label(str(nested_key))}: {_cell(nested_value)}"
            for nested_key, nested_value in scalar_items[:_MAX_NESTED_PREVIEW]
        ]
        omitted = len(value) - len(lines)
        if omitted > 0:
            lines.append(f"… {omitted} more field(s)")
        return "\n".join(lines) if lines else f"{len(value)} nested field(s)"
    if not _is_list(value):
        return "none"
    if not value:
        return "none"
    if all(not isinstance(item, dict | list) for item in value):
        preview = ", ".join(_cell(item) for item in value[:12])
        if len(value) > 12:
            preview += f", … {len(value) - 12} more"
        return preview
    records = [item for item in value if _is_record(item)]
    lines = [f"{len(value)} item(s)"]
    for record in records[:_MAX_NESTED_PREVIEW]:
        label = record.get("title") or record.get("name") or record.get("message")
        severity = record.get("severity")
        status = record.get("status") or record.get("state")
        prefix = " / ".join(_cell(part) for part in (severity, status) if part)
        summary = str(label or record.get("id") or "record")
        lines.append(f"- {prefix + ': ' if prefix else ''}{_cell(summary)}")
    if len(value) > len(records[:_MAX_NESTED_PREVIEW]):
        lines.append(f"… {len(value) - len(records[:_MAX_NESTED_PREVIEW])} more; use --json")
    return "\n".join(lines)


def _print_source_manifest(console: Console, data: dict[str, Any]) -> None:
    source = data.get("source")
    manifest = source if _is_record(source) else data
    files = manifest.get("files")
    summary = {key: value for key, value in manifest.items() if key != "files"}
    _print_detail(console, summary)
    if _is_list(files):
        console.print(f"\n[bold]Selected files ({len(files):,})[/]")
        for path in files:
            console.print(f"  {escape(sanitize_terminal_text(path))}", soft_wrap=True)


def _print_supply_chain_summary(console: Console, data: dict[str, Any]) -> None:
    """Render organization totals and one actionable row per repository."""
    totals = data.get("totals")
    console.print("[bold]Supply-chain totals[/]")
    _print_table(
        console,
        [dict(totals)] if _is_record(totals) else [],
        view="supply_chain_totals",
        show_json_hint=False,
    )

    console.print("[bold]Repositories[/]")
    _print_table(
        console,
        _supply_chain_repository_rows(data),
        view="supply_chain_repositories",
        hint="Inspect one repository with `strix cloud repos supply-chain summary ID`.",
        show_json_hint=False,
    )
    console.print("[dim]Use --json for complete totals and repository records.[/]")


def _supply_chain_repository_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    entries = data.get("repositories")
    if not _is_list(entries):
        return []
    rows: list[dict[str, Any]] = []
    for entry in entries:
        if not _is_record(entry):
            continue
        repository = entry.get("repository")
        summary = entry.get("summary")
        if not _is_record(repository) or not _is_record(summary):
            continue
        row: dict[str, Any] = {
            "repository": repository.get("full_name") or repository.get("name"),
            "components": summary.get("component_count", 0),
            "findings": summary.get("finding_count", 0),
            "severity": _supply_chain_severity_summary(summary.get("severity_counts")),
            "risks": _supply_chain_risk_summary(summary),
            "latest_scan": _supply_chain_scan_summary(entry.get("latest_supply_chain_scan")),
            "policy": _supply_chain_policy_summary(summary.get("policy")),
            "id": repository.get("id"),
        }
        rows.append(row)
    return rows


def _supply_chain_risk_summary(summary: dict[str, Any]) -> str:
    return " · ".join(
        (
            f"{summary.get('malicious_count', 0)} malicious",
            f"{summary.get('suspicious_count', 0)} suspicious",
            f"{summary.get('vulnerable_count', 0)} vulnerable",
        )
    )


def _supply_chain_severity_summary(value: Any) -> str:
    if not _is_record(value):
        return "none"
    ordered = ("critical", "high", "medium", "low", "info", "unknown")
    counts = [f"{key} {value[key]}" for key in ordered if isinstance(value.get(key), int)]
    return " · ".join(counts) if counts else "none"


def _supply_chain_scan_summary(value: Any) -> str:
    if not _is_record(value):
        return "not run"
    status = str(value.get("status") or "unknown")
    created_at = str(value.get("created_at") or "").strip()
    return f"{status} · {created_at}" if created_at else status


def _supply_chain_policy_summary(value: Any) -> str:
    if not _is_record(value):
        return "unknown"
    if value.get("enabled") is False:
        return "disabled"
    mode = str(value.get("mode") or "monitor")
    if value.get("pr_checks_enabled") is False:
        return f"{mode} · PR checks off"
    return mode


def _print_analytics(console: Console, data: dict[str, Any]) -> None:
    rows = list(_flatten_summary(data))
    table = Table(show_header=False, show_edge=False, box=None, padding=(0, 2))
    table.add_column("metric", style="bold cyan")
    table.add_column("value", overflow="fold")
    for label, value in rows[:_MAX_DETAIL_FIELDS]:
        table.add_row(escape(label), escape(value))
    console.print(table)
    if len(rows) > _MAX_DETAIL_FIELDS:
        console.print(
            f"[dim]Showing {_MAX_DETAIL_FIELDS} of {len(rows)} summary metrics. "
            "Use --json for all data.[/]"
        )
    else:
        console.print("[dim]Use --json for the complete analytics record.[/]")


def _flatten_summary(value: Any, prefix: str = "", depth: int = 0) -> Iterable[tuple[str, str]]:
    if _is_record(value) and depth < 4:
        for key, nested in value.items():
            label = f"{prefix} / {_human_label(key)}" if prefix else _human_label(key)
            yield from _flatten_summary(nested, label, depth + 1)
        return
    if _is_list(value):
        if all(not isinstance(item, dict | list) for item in value):
            yield prefix, _nested_summary(value)
        else:
            yield prefix, f"{len(value)} data point(s)"
        return
    yield prefix or "value", _cell(value)


def _print_scan_frequency(console: Console, data: Any) -> None:
    rows = _find_record_series(data)
    if rows is None:
        if _is_record(data):
            _print_analytics(console, data)
        else:
            console.print_json(json.dumps(data, default=str))
        return
    nonzero = [row for row in rows if _row_has_activity(row)]
    selected = (nonzero[-30:] if nonzero else rows[-14:]) if rows else []
    _print_table(console, selected, view="GET /analytics/scan-frequency")
    if rows:
        qualifier = "non-zero" if nonzero else "most recent"
        console.print(
            f"[dim]Showing {len(selected)} {qualifier} point(s) from {len(rows)} total. "
            "Use --json for the full series.[/]"
        )


def _find_record_series(data: Any) -> list[dict[str, Any]] | None:
    direct = _list_of_dicts(data)
    if direct is not None:
        return direct
    if _is_record(data):
        candidates = [
            series for value in data.values() if (series := _find_record_series(value)) is not None
        ]
        if candidates:
            return max(candidates, key=len)
    return None


def _row_has_activity(row: dict[str, Any]) -> bool:
    count_keys = ("count", "scans", "scan_count", "total", "value")
    return any(isinstance(row.get(key), int | float) and row[key] > 0 for key in count_keys)


def _human_label(column: str) -> str:
    column = sanitize_terminal_text(column)
    if column == "secret_prefix":
        return "prefix"
    labels = {
        "repository_full_name": "repo",
        "pr_number": "PR",
        "pr_title": "title",
        "head_branch": "head",
        "base_branch": "base",
        "findings_count": "findings",
        "open_findings_count": "open",
        "display_number": "finding",
        "created_at": "created",
        "updated_at": "updated",
        "expires_at": "expires",
        "last_used_at": "last used",
    }
    return labels.get(column, _CAMEL_BOUNDARY.sub(" ", column).replace("_", " ").lower())


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if _is_list(value) and all(not _is_record(item) and not _is_list(item) for item in value):
        text = ", ".join(str(item) for item in value)
    elif _is_record(value) or _is_list(value):
        text = f"{len(value)} item(s)"
    else:
        text = str(value)
    text = sanitize_terminal_text(text)
    if len(text) > _MAX_CELL_LENGTH:
        return text[: _MAX_CELL_LENGTH - 1] + "…"
    return text


def _detail_cell(value: Any) -> str:
    """Keep prose useful in a detail view while bounding hostile responses."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = "\n".join(sanitize_terminal_text(line) for line in str(value).split("\n"))
    if len(text) > _MAX_DETAIL_CELL_LENGTH:
        suffix = "… [truncated; use --json]"
        return text[: _MAX_DETAIL_CELL_LENGTH - len(suffix)] + suffix
    return text
