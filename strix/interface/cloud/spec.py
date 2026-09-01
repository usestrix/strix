"""Declarative command table for `strix cloud`.

Each command maps one CLI verb to one managed API operation. The runner
builds the argument parser and the HTTP request from this table, so the
CLI surface stays aligned with the OpenAPI specification.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class P:
    """One command parameter.

    ``kind`` is one of ``str``, ``int``, ``float``, ``bool``, ``list``, ``json``,
    or ``json-list``.
    """

    name: str
    kind: str = "str"
    required: bool = False
    help: str = ""
    # Command-line name when the field name collides with a common option.
    flag: str | None = None


@dataclass(frozen=True)
class Cmd:
    method: str
    path: str
    help: str
    query: tuple[P, ...] = ()
    body: tuple[P, ...] = ()
    binary: bool = False
    wait_path: str | None = None
    # When true, `--wait` polls GET on this same path until the status is final.
    wait_self: bool = False
    # Response field that holds a URL a person must open, for example a hosted
    # checkout page. The runner opens the browser for an interactive terminal
    # and always prints the URL.
    link: str | None = None
    # Caller retries for this mutation must carry one stable opaque key. The
    # platform binds it to the authenticated actor and exact request body.
    idempotent: bool = False


def _q(*names: str) -> tuple[P, ...]:
    return tuple(P(name) for name in names)


_SCAN_START_BODY = (
    P(
        "engagement_type",
        help=("Test category: code_review, live_test, internal_infra, or compliance_pentest."),
    ),
    P("domain_ids", "list", help="Domain asset IDs to test."),
    P("domain_paths", "json", help="JSON map of domain ID to start paths."),
    P("repository_ids", "list", help="Repository asset IDs to test."),
    P("repository_branches", "json", help="JSON map of repository ID to branch."),
    P("credentials", "json", help="JSON list of credential objects."),
    P(
        "headers",
        "json",
        help='JSON array of target header objects: [{"name":"...","value":"...","notes":"..."}].',
    ),
    P("concerns", help="Free-form security concerns to investigate."),
    P("focus", help="Free-form focus instructions for the agents."),
    P("context", help="Extra context about the target."),
    P("upload_ids", "list", help="Upload IDs to attach to the scan."),
    P("connector_id", help="Network connector ID for internal targets."),
    P("internal_targets", "list", help="Internal IP addresses or ranges."),
    P("org_knowledge_enabled", "bool", help="Use the organization knowledge base."),
    P("notify_on_completion", "bool", help="Send an email when the scan completes."),
    P("notification_emails", "list", help="Extra notification email addresses."),
    P(
        "scan_tier",
        help=(
            "Scan tier: lite, standard, or ultra (default). "
            "Not used for Enterprise or self-hosted scans."
        ),
    ),
    P("model_config_id", help="Self-hosted only: model configuration ID to run with."),
    P("max_budget_usd", "float", help="Self-hosted only: budget limit for the scan in USD."),
)

_TEST_USER_ADD_BODY = (
    P("label", required=True, help="Display label for the test user."),
    P("username", required=True, help="Sign-in username or email address."),
    P("password", help="Sign-in password."),
    P("notes", help="Free-form notes for the agents."),
    P("login_url", help="URL of the sign-in page."),
    P("mfa_method", help="MFA method: none, totp, email_otp, or magic_link."),
    P("totp_secret", help="TOTP secret for MFA sign-in."),
    P("mfa_email", help="Email address that receives MFA codes."),
    P("scope_domain_ids", "list", help="Domain IDs where this user applies."),
)

_TEST_USER_BODY = (
    P("label", help="Display label for the test user."),
    P("username", help="Sign-in username or email address."),
    P("password", help="Sign-in password."),
    P("notes", help="Free-form notes for the agents."),
    P("login_url", help="URL of the sign-in page."),
    P("mfa_method", help="MFA method: none, totp, email_otp, or magic_link."),
    P("totp_secret", help="TOTP secret for MFA sign-in."),
    P("mfa_email", help="Email address that receives MFA codes."),
    P("scope_domain_ids", "list", help="Domain IDs where this user applies."),
)

_GIT_TOKEN_BODY = (
    P("access_token", required=True, help="Provider access token.", flag="provider-token"),
    P("instance_url", help="GitLab base URL, for example https://gitlab.com."),
    P("account_email", help="Bitbucket account email address."),
    P("installation_id", "int", help="Existing installation ID to update."),
)


SPEC: dict[str, dict[str, Cmd]] = {
    "scans": {
        "list": Cmd(
            "GET",
            "/scans",
            "List scans.",
            query=(
                P("page", "int", help="Results page (starts at 1)."),
                P("limit", "int", help="Results per page (1-100)."),
                *_q(
                    "status",
                    "scan_type",
                    "date_from",
                    "date_to",
                    "domain_id",
                    "repository_id",
                    "search",
                ),
                P("include_retests", "bool", help="Include per-finding retest scans."),
                P("sort_by", help="Sort key; currently created_at."),
                P("sort_order", help="Sort order: asc or desc."),
            ),
        ),
        "start": Cmd(
            "POST",
            "/scans",
            "Start a scan.",
            body=_SCAN_START_BODY,
            wait_path="/scans/{id}",
            idempotent=True,
        ),
        "get": Cmd("GET", "/scans/{scanId}", "Get one scan."),
        "delete": Cmd("DELETE", "/scans/{scanId}", "Delete a scan."),
        "agents": Cmd("GET", "/scans/{scanId}/agents", "List the agents of a scan."),
        "cancel": Cmd("POST", "/scans/{scanId}/cancel", "Cancel a running scan."),
        "message": Cmd(
            "POST",
            "/scans/{scanId}/message",
            "Send a message to the scan agents.",
            body=(
                P(
                    "message",
                    help="Message text for the agents. Required unless --cancel-current is used.",
                ),
                P("cancel_current", "bool", help="Cancel the current task before delivery."),
                P("agent_id", help="Target one agent instead of the root agent."),
            ),
        ),
        "report": Cmd(
            "GET",
            "/scans/{scanId}/report",
            "Download the scan report.",
            query=(
                P(
                    "format",
                    help=(
                        "Report content: technical (default), retest, attestation, or "
                        "executive_summary. Advanced formats require Enterprise."
                    ),
                ),
                P(
                    "type",
                    help="Rendered file type: pdf (default) or docx. DOCX requires Enterprise.",
                ),
                P(
                    "providerName",
                    flag="provider-name",
                    help="Enterprise report-cover provider name (up to 80 characters).",
                ),
                P(
                    "memberName0",
                    flag="member-name-0",
                    help="First Enterprise report preparer's name (up to 120 characters).",
                ),
                P(
                    "memberEmail0",
                    flag="member-email-0",
                    help="First Enterprise report preparer's email address.",
                ),
                P(
                    "memberName1",
                    flag="member-name-1",
                    help="Second Enterprise report preparer's name (up to 120 characters).",
                ),
                P(
                    "memberEmail1",
                    flag="member-email-1",
                    help="Second Enterprise report preparer's email address.",
                ),
            ),
            binary=True,
        ),
        "rerun": Cmd(
            "POST",
            "/scans/{scanId}/rerun",
            "Run the scan again.",
            wait_path="/scans/{id}",
            idempotent=True,
        ),
        "retest-all": Cmd(
            "POST",
            "/scans/{scanId}/retest-all",
            "Retest all open findings of a scan.",
            body=(
                P("scope", help="Retest scope."),
                P("upload_ids", "list", help="Upload IDs with updated code."),
            ),
        ),
        "retests": Cmd("GET", "/scans/{scanId}/retests", "List the retests of a scan."),
        "sarif": Cmd(
            "GET",
            "/scans/{scanId}/sarif",
            "Download the scan findings as SARIF.",
            query=_q("repository"),
            binary=True,
        ),
        "sarif-upload": Cmd(
            "POST",
            "/scans/{scanId}/sarif",
            "Upload the scan findings to GitHub code scanning.",
            body=(
                P("repository", help="Repository full name."),
                P("ref", help="Git ref for the upload."),
                P("commit_sha", help="Commit SHA for the upload."),
                P("checkout_uri", help="Checkout URI for the upload."),
                P("github_api_base_url", help="GitHub API base URL."),
            ),
        ),
        "template": Cmd("GET", "/scans/{scanId}/template", "Get the scan configuration template."),
        "trace": Cmd(
            "GET",
            "/scans/{scanId}/trace",
            "List trace events for one agent of a scan.",
            query=(
                P("agent_id", required=True, help="Agent ID to read the trace for."),
                P("cursor"),
                P("limit", "int"),
                P("tool_name"),
            ),
        ),
        "trace-event": Cmd(
            "GET", "/scans/{scanId}/trace/{eventId}", "Get one trace event of a scan."
        ),
    },
    "vulns": {
        "list": Cmd(
            "GET",
            "/vulnerabilities",
            "List vulnerabilities.",
            query=(
                P("page", "int", help="Results page (starts at 1)."),
                P("limit", "int", help="Results per page (1-100)."),
                *_q(
                    "scan_id",
                    "severity",
                    "status",
                    "search",
                    "from",
                    "to",
                    "domain_id",
                    "repository_id",
                    "finding_type",
                    "dependency_relation",
                    "reachability",
                    "sort_by",
                ),
                P("sort_order", help="Sort order: asc or desc."),
            ),
        ),
        "get": Cmd("GET", "/vulnerabilities/{vulnerabilityId}", "Get one vulnerability."),
        "history": Cmd(
            "GET",
            "/vulnerabilities/{vulnerabilityId}/history",
            "Get the change history of a vulnerability.",
        ),
        "update": Cmd(
            "PATCH",
            "/vulnerabilities/{vulnerabilityId}",
            "Update the status or severity of a vulnerability.",
            body=(
                P(
                    "status",
                    help=(
                        "New status: open, in_progress, snoozed, fixed, ignored, or not_affected."
                    ),
                ),
                P("note", help="Note that explains the change."),
                P("severity", help="New severity."),
                P("severity_reason", help="Reason for the severity change."),
            ),
        ),
        "retest": Cmd(
            "POST",
            "/vulnerabilities/{vulnerabilityId}/retest",
            "Retest one vulnerability.",
            body=(P("upload_ids", "list", help="Upload IDs with updated code."),),
            wait_path="/scans/{id}",
        ),
        "fix-pr": Cmd(
            "POST",
            "/vulnerabilities/{vulnerabilityId}/create-fix-pr",
            "Create a fix pull request for a vulnerability.",
        ),
        "push": Cmd(
            "POST",
            "/vulnerabilities/{vulnerabilityId}/push",
            "Push one vulnerability to an issue tracker.",
            body=(
                P("provider", required=True, help="Tracker provider, for example jira or linear."),
                P("collection_id", help="Tracker project or collection ID."),
            ),
        ),
        "push-bulk": Cmd(
            "POST",
            "/vulnerabilities/bulk-push",
            "Push many vulnerabilities to an issue tracker.",
            body=(
                P("provider", required=True, help="Tracker provider, for example jira or linear."),
                P("vulnerability_ids", "list", required=True, help="Vulnerability IDs to push."),
                P("collection_id", help="Tracker project or collection ID."),
            ),
        ),
    },
    "domains": {
        "list": Cmd(
            "GET",
            "/domains",
            "List domain assets.",
            query=(
                P("page", "int", help="Results page (starts at 1)."),
                P("limit", "int", help="Results per page (1-100)."),
                *_q("search", "verified", "business_unit", "tags", "sort_by"),
                P("sort_order", help="Sort order: asc or desc."),
            ),
        ),
        "add": Cmd(
            "POST",
            "/domains",
            "Add a domain asset.",
            body=(
                P("domain", required=True, help="Domain name or URL."),
                P("asset_type", required=True, help="Asset type, for example web_app or api."),
                P("context", help="Extra context about the asset."),
                P("tags", "list", help="Tags for the asset."),
                P("business_unit", help="Business unit for the asset."),
            ),
        ),
        "update": Cmd(
            "PATCH",
            "/domains/{domainId}",
            "Update a domain asset.",
            body=(
                P("context", help="Extra context about the asset."),
                P("tags", "list", help="Tags for the asset."),
                P("business_unit", help="Business unit for the asset."),
            ),
        ),
        "remove": Cmd("DELETE", "/domains/{domainId}", "Remove a domain asset."),
        "verify": Cmd("POST", "/domains/{domainId}/verify", "Verify domain ownership."),
        "auto-verify": Cmd(
            "POST",
            "/domains/{domainId}/auto-verify",
            "Verify domain ownership through a DNS provider.",
            body=(P("provider", required=True, help="DNS provider name."),),
        ),
        "test-users list": Cmd(
            "GET", "/domains/{domainId}/test-users", "List the test users of a domain."
        ),
        "test-users add": Cmd(
            "POST",
            "/domains/{domainId}/test-users",
            "Add a test user to a domain.",
            body=_TEST_USER_ADD_BODY,
        ),
        "test-users update": Cmd(
            "PATCH",
            "/domains/{domainId}/test-users/{userId}",
            "Update a test user.",
            body=_TEST_USER_BODY,
        ),
        "test-users remove": Cmd(
            "DELETE", "/domains/{domainId}/test-users/{userId}", "Remove a test user."
        ),
        "test-users provision-inbox": Cmd(
            "POST",
            "/domains/{domainId}/test-users/provision-inbox",
            (
                "Provision a Strix-managed inbox for email OTP or magic-link MFA. "
                "Returns an address; it does not create a test user."
            ),
            body=(P("label", help="Optional display label for the managed inbox."),),
        ),
        "test-users inbox": Cmd(
            "GET",
            "/domains/{domainId}/test-users/{userId}/inbox",
            "List the inbox messages of a test user.",
            query=(P("limit", "int"),),
        ),
        "test-users inbox-message": Cmd(
            "GET",
            "/domains/{domainId}/test-users/{userId}/inbox/{messageId}",
            "Get one inbox message of a test user.",
        ),
        "test-users verify": Cmd(
            "POST",
            "/domains/{domainId}/test-users/{userId}/verify",
            "Verify that the test user credentials work.",
            query=(P("force"),),
            wait_self=True,
        ),
        "test-users verify-status": Cmd(
            "GET",
            "/domains/{domainId}/test-users/{userId}/verify",
            "Get the verification status of a test user.",
        ),
    },
    "repos": {
        "list": Cmd(
            "GET",
            "/repositories",
            "List repository assets.",
            query=(
                P("page", "int", help="Results page (starts at 1)."),
                P("limit", "int", help="Results per page (1-100)."),
                *_q("search", "business_unit", "tags", "sort_by"),
                P("sort_order", help="Sort order: asc or desc."),
            ),
        ),
        "add": Cmd("POST", "/repositories", "Add a repository asset. Use --data for the fields."),
        "update": Cmd(
            "PATCH",
            "/repositories/{repositoryId}",
            "Update a repository asset.",
            body=(
                P("pr_review_enabled", "bool", help="Turn PR reviews on or off."),
                P("pr_review_approvals_enabled", "bool", help="Let reviews approve clean PRs."),
                P("pr_review_non_blocking", "bool", help="Make review verdicts non-blocking."),
                P("pr_review_on_push", "bool", help="Review new pushes to open PRs."),
                P("tags", "list", help="Tags for the asset."),
                P("business_unit", help="Business unit for the asset."),
            ),
        ),
        "remove": Cmd("DELETE", "/repositories/{repositoryId}", "Remove a repository asset."),
        "supply-chain scan": Cmd(
            "POST",
            "/repositories/{repositoryId}/supply-chain/scan",
            "Start a supply-chain scan for a repository.",
        ),
        "supply-chain summary": Cmd(
            "GET",
            "/repositories/{repositoryId}/supply-chain/summary",
            "Get the supply-chain summary of a repository.",
            query=_q("job_id", "snapshot_id"),
        ),
        "supply-chain findings": Cmd(
            "GET",
            "/repositories/{repositoryId}/supply-chain/findings",
            "List the supply-chain findings of a repository.",
            query=_q("job_id", "snapshot_id", "component_id"),
        ),
        "supply-chain components": Cmd(
            "GET",
            "/repositories/{repositoryId}/supply-chain/components",
            "List the dependency components of a repository.",
            query=(
                *_q(
                    "job_id",
                    "snapshot_id",
                    "component_id",
                    "ecosystem",
                    "status",
                    "relationship",
                    "source_file",
                    "q",
                    "changed",
                ),
                P("limit", "int", help="Maximum components to return."),
                P("offset", "int", help="Number of components to skip."),
            ),
        ),
        "supply-chain sbom": Cmd(
            "GET",
            "/repositories/{repositoryId}/supply-chain/sbom",
            "Download the SBOM of a repository.",
            query=_q("job_id", "snapshot_id", "format"),
            binary=True,
        ),
        "supply-chain policy": Cmd(
            "PATCH",
            "/repositories/{repositoryId}/supply-chain/policy",
            "Update the supply-chain policy of a repository.",
            body=(
                P("supply_chain_enabled", "bool", help="Turn supply-chain scans on or off."),
                P("supply_chain_pr_checks_enabled", "bool", help="Run checks on pull requests."),
                P("supply_chain_policy_mode", help="Policy mode for new findings."),
            ),
        ),
    },
    "supply-chain": {
        "summary": Cmd(
            "GET", "/supply-chain/summary", "Get the organization supply-chain summary."
        ),
    },
    "schedules": {
        "list": Cmd("GET", "/schedules", "List scan schedules."),
        "create": Cmd(
            "POST",
            "/schedules",
            "Create a scan schedule. Use --data for the fields.",
            idempotent=True,
        ),
        "get": Cmd("GET", "/schedules/{scheduleId}", "Get one schedule."),
        "update": Cmd(
            "PATCH",
            "/schedules/{scheduleId}",
            "Update a schedule. Use --data for fields that have no option.",
            body=(
                P("action", help="Lifecycle action, for example pause or resume."),
                P("cron_expression", help="Cron expression for the schedule."),
                P("timezone", help="Time zone for the cron expression."),
                P("name", help="Display name of the schedule."),
                P(
                    "max_budget_usd",
                    "float",
                    help=(
                        "Self-hosted only: budget limit per run in USD. "
                        "Use --data to set null and clear it."
                    ),
                ),
                P("scan_tier", help="Scan tier: lite, standard, or ultra."),
            ),
        ),
        "delete": Cmd("DELETE", "/schedules/{scheduleId}", "Delete a schedule."),
        "template": Cmd(
            "GET", "/schedules/{scheduleId}/template", "Get the schedule configuration template."
        ),
        "trigger": Cmd(
            "POST",
            "/schedules/{scheduleId}/trigger",
            "Run a schedule now.",
            idempotent=True,
        ),
    },
    "pr-reviews": {
        "list": Cmd(
            "GET",
            "/pr-reviews",
            "List PR reviews.",
            query=(
                P("page", "int", help="Results page (starts at 1)."),
                P("limit", "int", help="Results per page (1-100)."),
                *_q(
                    "search",
                    "status",
                    "group",
                    "pr_state",
                    "repository_full_name",
                    "date_from",
                    "date_to",
                    "sort_by",
                    "sort_order",
                ),
                P("include_counts", "bool", help="Include exact disposition counts."),
            ),
        ),
        "get": Cmd("GET", "/pr-reviews/{prReviewId}", "Get one PR review."),
        "findings": Cmd(
            "GET",
            "/pr-reviews/findings",
            "List PR review findings.",
            query=(
                P("page", "int", help="Results page (starts at 1)."),
                P("limit", "int", help="Results per page (1-100)."),
                *_q("severity", "pr_state", "search", "repository_full_name"),
                P("include_stats", "bool", help="Include all-time impact statistics."),
            ),
        ),
        "start": Cmd(
            "POST",
            "/pr-reviews/start",
            "Start a PR review.",
            body=(
                P("provider", required=True, help="Git provider: github, gitlab, or bitbucket."),
                P("installation_id", "int", required=True, help="Provider installation ID."),
                P("repository_full_name", required=True, help="Repository full name."),
                P("pr_number", "int", required=True, help="Pull request number."),
            ),
        ),
        "settings": Cmd("GET", "/pr-reviews/settings", "Get the PR review settings."),
        "settings update": Cmd(
            "PATCH",
            "/pr-reviews/settings",
            "Update the PR review settings. Use --data for fields that have no option.",
            body=(
                P("review_on_push", "bool", help="Review new pushes to open PRs."),
                P("block_on_findings", "bool", help="Block PRs that have findings."),
                P("blocking_severities", "list", help="Severities that block a PR."),
                P("approve_clean_prs", "bool", help="Approve PRs without findings."),
                P("target_branches", "list", help="Branches that get reviews."),
            ),
        ),
    },
    "billing": {
        "credits": Cmd("GET", "/billing/credits", "Get the credit balance of the workspace."),
        "topup": Cmd(
            "POST",
            "/billing/topup",
            "Buy credits with an agent payment (HTTP 402 flow).",
            body=(P("credits", "int", required=True, help="Number of credits to buy."),),
        ),
        "subscribe": Cmd(
            "POST",
            "/billing/checkout",
            "Create a checkout link for a plan or a credit pack. A person completes the payment.",
            body=(
                P(
                    "product",
                    required=True,
                    flag="plan",
                    help="Product to buy: strix_cloud, strix_startup, or strix_top_up.",
                ),
                P("success_url", help="Page to open after the payment."),
            ),
            link="checkout_url",
        ),
        "portal": Cmd(
            "POST",
            "/billing/portal",
            "Create a billing portal link. A person manages the card and the plan there.",
            link="portal_url",
        ),
        "auto-topup": Cmd("GET", "/billing/auto-topup", "Get the automatic top-up settings."),
        "auto-topup update": Cmd(
            "PUT",
            "/billing/auto-topup",
            "Update the automatic top-up settings.",
            body=(
                P("enabled", "bool", required=True, help="Turn automatic top-up on or off."),
                P("topup_credits", "int", required=True, help="Credits to buy on each top-up."),
                P("monthly_cap_credits", "int", help="Monthly credit cap for automatic top-ups."),
            ),
        ),
    },
    "chat": {
        "list": Cmd("GET", "/chat", "List chat sessions."),
        "start": Cmd(
            "POST",
            "/chat",
            "Start a chat session.",
            body=(
                P("message", required=True, help="First message of the session."),
                P(
                    "repos",
                    "json",
                    help='JSON array of repository refs: [{"repoId":"...","branch":"main"}].',
                ),
                P("domain_ids", "list", help="Domain asset IDs for context."),
            ),
        ),
        "get": Cmd("GET", "/chat/{chatId}", "Get one chat session."),
        "send": Cmd(
            "POST",
            "/chat/{chatId}/message",
            "Send a message in a chat session.",
            body=(
                P(
                    "message",
                    help="Message text. Required unless --cancel-current or --stop-agent is used.",
                ),
                P("cancel_current", "bool", help="Cancel the in-flight agent turn first."),
                P("stop_agent", "bool", help="Park the target agent and its descendants."),
                P(
                    "repos",
                    "json",
                    help='JSON array of repository refs: [{"repoId":"...","branch":"main"}].',
                ),
                P("agent_id", help="Target one subagent instead of the root agent."),
            ),
        ),
        "findings": Cmd("GET", "/chat/{chatId}/findings", "List the findings of a chat session."),
        "finding": Cmd(
            "GET", "/chat/{chatId}/findings/{findingId}", "Get one finding of a chat session."
        ),
        "finding file": Cmd(
            "POST",
            "/chat/{chatId}/findings/{findingId}/file",
            "File a chat finding into the organization issue list.",
        ),
        "files": Cmd("GET", "/chat/{chatId}/files", "List the files of a chat session."),
        "files download": Cmd(
            "GET",
            "/chat/{chatId}/files/download",
            "Download one file of a chat session.",
            query=(
                P(
                    "path",
                    required=True,
                    help="Relative path in the session, or an absolute path under /workspace.",
                ),
            ),
            binary=True,
        ),
        "files archive": Cmd(
            "GET",
            "/chat/{chatId}/files/archive",
            "Download all files of a chat session as an archive.",
            binary=True,
        ),
        "credentials": Cmd(
            "GET",
            "/chat/{chatId}/credentials",
            "Get the credentials of a chat session.",
            query=_q("scan_ids"),
        ),
        "credentials set": Cmd(
            "POST",
            "/chat/{chatId}/credentials",
            "Set the credentials of a chat session.",
            body=(
                P("test_user_ids", "list", help="Test user IDs to attach."),
                P("credentials", "json", help="JSON list of credential objects."),
                P("scan_ids", "list", help="Scan IDs that use the credentials."),
            ),
        ),
        "credentials clear": Cmd(
            "DELETE", "/chat/{chatId}/credentials", "Remove the credentials of a chat session."
        ),
        "domains set": Cmd(
            "PUT",
            "/chat/{chatId}/domains",
            "Set the domains of a chat session.",
            body=(P("domain_ids", "list", help="Domain asset IDs."),),
        ),
        "terminal": Cmd(
            "POST",
            "/chat/{chatId}/terminal",
            "Run a command in the chat session sandbox.",
            body=(
                P("command", required=True, help="Shell command to run."),
                P("cwd", help="Working directory for the command."),
            ),
        ),
        "share": Cmd("POST", "/chat/{chatId}/share", "Create a share link for a chat session."),
    },
    "knowledge": {
        "list": Cmd(
            "GET",
            "/knowledge",
            "List knowledge documents.",
            query=(
                *_q("source_type", "search"),
                P("limit", "int", help="Maximum documents to return."),
            ),
        ),
        "add": Cmd(
            "POST",
            "/knowledge",
            "Add a knowledge document.",
            body=(
                P("title", required=True, help="Document title."),
                P("content", required=True, help="Document content."),
                P("tags", "list", help="Tags for the document."),
                P("metadata", "json", help="JSON metadata for the document."),
            ),
        ),
        "update": Cmd(
            "PATCH",
            "/knowledge/{documentId}",
            "Update a knowledge document.",
            body=(
                P("title", help="Document title."),
                P("content", help="Document content."),
                P("tags", "list", help="Tags for the document."),
                P("metadata", "json", help="JSON metadata for the document."),
            ),
        ),
        "delete": Cmd("DELETE", "/knowledge/{documentId}", "Delete a knowledge document."),
        "policies": Cmd("GET", "/knowledge/policies", "List knowledge policies."),
        "policies add": Cmd(
            "POST",
            "/knowledge/policies",
            "Add a knowledge policy.",
            body=(
                P("policy_key", required=True, flag="key", help="Policy key."),
                P("policy_value", required=True, flag="content", help="Policy content."),
                P("policy_type", help="Policy type. Defaults to constraint."),
                P("is_active", "bool", flag="enabled", help="Turn the policy on or off."),
                P("metadata", "json", help="JSON metadata for the policy."),
            ),
        ),
        "policies delete": Cmd(
            "DELETE", "/knowledge/policies/{policyKey}", "Delete a knowledge policy."
        ),
        "repos": Cmd("GET", "/knowledge/repos", "List repositories with knowledge entries."),
        "repos entries": Cmd(
            "GET", "/knowledge/repos/{repo}/entries", "List the knowledge entries of a repository."
        ),
        "repos profile": Cmd(
            "PATCH",
            "/knowledge/repos/{repo}/profile",
            "Update the knowledge profile of a repository. Use --data for the fields.",
        ),
    },
    "org": {
        "get": Cmd("GET", "/organization", "Get the organization."),
        "update": Cmd(
            "PATCH",
            "/organization",
            "Update the organization.",
            body=(P("name", required=True, help="Organization name."),),
        ),
        "members": Cmd("GET", "/organization/members", "List the organization members."),
        "members invite": Cmd(
            "POST",
            "/organization/members",
            "Invite a member to the organization.",
            body=(
                P("email", required=True, help="Email address of the new member."),
                P("role", help="Member role, for example admin, analyst, or viewer."),
                P("scopes", "list", help="RBAC scopes for the member."),
            ),
        ),
        "members update": Cmd(
            "PATCH",
            "/organization/members/{membershipId}",
            "Update a member of the organization.",
            body=(
                P("role", required=True, help="Member role."),
                P("scopes", "list", help="RBAC scopes for the member."),
            ),
        ),
        "members remove": Cmd("DELETE", "/organization/members/{membershipId}", "Remove a member."),
        "invitations": Cmd("GET", "/organization/invitations", "List open invitations."),
        "invitations revoke": Cmd(
            "DELETE", "/organization/invitations/{invitationId}", "Revoke an invitation."
        ),
    },
    "integrations": {
        "list": Cmd("GET", "/integrations", "List the connected integrations."),
        "connect": Cmd(
            "POST",
            "/integrations/{provider}/connect",
            "Connect a Git provider. The provider is gitlab or bitbucket.",
            body=_GIT_TOKEN_BODY,
        ),
        "validate": Cmd(
            "POST",
            "/integrations/{provider}/validate",
            "Validate a Git provider token. The provider is gitlab or bitbucket.",
            body=_GIT_TOKEN_BODY,
        ),
        "install": Cmd(
            "POST",
            "/integrations/{provider}/install-url",
            "Create an installation link. The provider is github or slack. A person approves it.",
            link="url",
        ),
        "disconnect": Cmd(
            "DELETE",
            "/integrations/{provider}",
            "Disconnect an integration.",
            query=(
                P(
                    "installation_id",
                    "int",
                    help=(
                        "Installation ID. Required for github, gitlab, and bitbucket; "
                        "unsupported for other providers."
                    ),
                ),
            ),
        ),
    },
    "connectors": {
        "list": Cmd("GET", "/connectors", "List network connectors."),
        "create": Cmd(
            "POST",
            "/connectors",
            "Create a network connector.",
            body=(P("name", required=True, help="Connector name."),),
        ),
        "get": Cmd(
            "GET",
            "/connectors/{connectorId}",
            "Get one network connector.",
            query=(
                P(
                    "include_command",
                    "bool",
                    help=(
                        "Include the one-time Docker enrollment command. "
                        "The command contains sensitive connector credentials."
                    ),
                ),
            ),
        ),
        "status": Cmd(
            "GET", "/connectors/{connectorId}/status", "Get the status of a network connector."
        ),
        "delete": Cmd("DELETE", "/connectors/{connectorId}", "Delete a network connector."),
    },
    "webhooks": {
        "list": Cmd("GET", "/webhooks", "List webhooks."),
        "create": Cmd(
            "POST",
            "/webhooks",
            "Create a webhook.",
            body=(
                P("url", required=True, help="Delivery URL."),
                P("events", "list", required=True, help="Event names to deliver."),
                P("business_unit", help="Business unit filter."),
                P("is_active", "bool", help="Turn the webhook on or off."),
            ),
        ),
        "get": Cmd("GET", "/webhooks/{webhookId}", "Get one webhook."),
        "update": Cmd(
            "PATCH",
            "/webhooks/{webhookId}",
            "Update a webhook.",
            body=(
                P("url", help="Delivery URL."),
                P("events", "list", help="Event names to deliver."),
                P("business_unit", help="Business unit filter."),
                P("is_active", "bool", help="Turn the webhook on or off."),
                P("rotate_secret", "bool", help="Create a new signing secret."),
            ),
        ),
        "delete": Cmd("DELETE", "/webhooks/{webhookId}", "Delete a webhook."),
        "deliveries": Cmd(
            "GET",
            "/webhooks/{webhookId}/deliveries",
            "List the deliveries of a webhook.",
            query=(
                P("page", "int", help="Results page (starts at 1)."),
                P("limit", "int", help="Results per page (1-100)."),
            ),
        ),
    },
    "analytics": {
        "overview": Cmd(
            "GET",
            "/analytics/overview",
            "Get the analytics overview.",
            query=_q("range", "from", "to"),
        ),
        "stats": Cmd("GET", "/analytics/stats", "Get the analytics statistics."),
        "scan-frequency": Cmd(
            "GET", "/analytics/scan-frequency", "Get the scan frequency data.", query=_q("tz")
        ),
    },
    "audit": {
        "list": Cmd(
            "GET",
            "/audit",
            "List audit log entries.",
            query=(
                P("page", "int", help="Results page (starts at 1)."),
                P("limit", "int", help="Results per page (1-1000)."),
                *_q("action", "resource_type", "actor_id", "date_from", "date_to"),
                P(
                    "format",
                    help="Output format: json, csv, ndjson, jsonl, snowflake, or splunk.",
                ),
                P("all", "bool", help="Stream all matches when exporting instead of one page."),
            ),
        ),
    },
    "costs": {
        "overview": Cmd(
            "GET",
            "/llm-costs",
            "Self-hosted only: show the LLM cost overview.",
            query=_q("range", "from", "to"),
        ),
        "run": Cmd(
            "GET",
            "/llm-costs/runs/{runType}/{runId}",
            "Self-hosted only: get the LLM costs of one run.",
        ),
    },
    "llm-settings": {
        "get": Cmd("GET", "/llm-settings", "Self-hosted only: get the LLM settings."),
        "update": Cmd(
            "PUT",
            "/llm-settings",
            "Self-hosted only: update the LLM settings.",
            body=(
                P(
                    "modelConfigs",
                    "json",
                    required=True,
                    flag="model-configs",
                    help="JSON list of model configurations.",
                ),
                P("assignments", "json", required=True, help="JSON map of model assignments."),
            ),
        ),
    },
    "settings": {
        "notifications": Cmd("GET", "/settings/notifications", "Get the notification settings."),
        "notifications update": Cmd(
            "PATCH",
            "/settings/notifications",
            "Update the notification settings.",
            body=(
                P("sla_reminders_enabled", "bool", help="Turn SLA reminders on or off."),
                P("sla_reminder_email", "bool", help="Send SLA reminders by email."),
                P("sla_reminder_slack", "bool", help="Send SLA reminders to Slack."),
                P("sla_warning_days", "int", help="Days before an SLA warning."),
            ),
        ),
    },
    "license": {
        "show": Cmd("GET", "/license", "Get the license information."),
    },
    "tokens": {
        "list": Cmd("GET", "/tokens", "List API tokens.", query=_q("type")),
        "create": Cmd(
            "POST",
            "/tokens",
            "Create an API token.",
            body=(
                P("type", required=True, help="Token type, personal or service."),
                P("name", required=True, help="Token name."),
                P("scopes", "list", help="API scopes for the token."),
                P(
                    "rbac_scopes",
                    "json-list",
                    help=(
                        "JSON array of resource restrictions; each item has type "
                        "target, tag, or business_unit and a value."
                    ),
                ),
                P(
                    "expires_at",
                    help=(
                        "Absolute expiration date/time (ISO 8601; mutually exclusive "
                        "with --expires-in-days)."
                    ),
                ),
                P("expires_in_days", "int", help="Days until the token expires."),
            ),
        ),
        "revoke": Cmd("DELETE", "/tokens/{tokenId}", "Revoke an API token."),
    },
    "uploads": {
        "request": Cmd(
            "POST",
            "/uploads/request",
            "Request an upload URL.",
            body=(
                P("file_name", required=True, help="File name."),
                P("file_size", "int", required=True, help="File size in bytes."),
                P("category", help="Upload category."),
            ),
        ),
        "complete": Cmd(
            "POST",
            "/uploads/complete",
            "Mark an upload as complete.",
            body=(P("upload_id", required=True, help="Upload ID."),),
        ),
        "delete": Cmd("DELETE", "/uploads/{uploadId}", "Delete an upload."),
    },
    "workspaces": {
        "list": Cmd("GET", "/workspaces", "List the workspaces of your account."),
        "create": Cmd(
            "POST",
            "/workspaces",
            "Create a workspace and become its admin.",
            body=(P("name", required=True, help="Workspace name."),),
        ),
    },
}


# Default verbs let a bare group name run its most common read command.
DEFAULT_VERBS: dict[str, str] = {
    "scans": "list",
    "vulns": "list",
    "domains": "list",
    "repos": "list",
    "workspaces": "list",
    "schedules": "list",
    "pr-reviews": "list",
    "billing": "credits",
    "chat": "list",
    "knowledge": "list",
    "org": "get",
    "integrations": "list",
    "connectors": "list",
    "webhooks": "list",
    "analytics": "overview",
    "costs": "overview",
    "audit": "list",
    "llm-settings": "get",
    "settings": "notifications",
    "license": "show",
    "tokens": "list",
    "supply-chain": "summary",
}


GROUP_HELP: dict[str, str] = {
    "scans": "Start, watch, and manage scans",
    "vulns": "Triage and remediate vulnerabilities",
    "domains": "Manage domain assets and test users",
    "repos": "Manage repository assets and supply-chain scans",
    "supply-chain": "Organization supply-chain summary",
    "schedules": "Manage scan schedules",
    "pr-reviews": "Manage pull request reviews",
    "billing": "Credits, top-ups, and automatic top-up",
    "chat": "Interactive pentest chat sessions",
    "knowledge": "Manage the knowledge base",
    "org": "Manage the organization and its members",
    "integrations": "Connect Git providers and other integrations",
    "workspaces": "List, create, and switch workspaces",
    "connectors": "Manage network connectors",
    "webhooks": "Manage webhooks",
    "analytics": "Read analytics data",
    "audit": "Read the audit log",
    "costs": "Self-hosted only: read LLM cost data",
    "llm-settings": "Self-hosted only: manage LLM model settings",
    "settings": "Manage notification settings",
    "license": "Read license information",
    "tokens": "Manage API tokens",
    "uploads": "Upload files for scans",
}
