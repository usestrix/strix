"""Asset-type taxonomy: how each target type is recognized and which skill covers it."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import PurePath
from urllib.parse import urlparse


@dataclass(frozen=True)
class AssetType:
    """``kind`` is one of code|file|url|network|identifier|account; ``skill`` is the
    recommended methodology skill stem; ``prefixes``/``exts`` drive detection."""

    key: str
    name: str
    category: str
    kind: str
    skill: str
    brief: str
    prefixes: tuple[str, ...] = ()
    exts: tuple[str, ...] = ()


# Keys whose explicit ``prefix:value`` form resolves to one of the four core
# target types (so they keep clone/mount/proxy handling) instead of ``asset``.
PASSTHROUGH_KEYS = frozenset({"source_code", "url", "domain", "subdomain", "ip_address"})

# URL schemes that auto-classify to an asset type, preserving the full URL.
SCHEME_MAP = {"s3": "s3_bucket", "wss": "websocket", "ws": "websocket", "grpc": "grpc"}


ASSET_TYPES: tuple[AssetType, ...] = (
    # --- Core / mixed ---
    AssetType(
        key="cidr",
        name="CIDR",
        category="Network",
        kind="network",
        skill="cidr",
        prefixes=("cidr",),
        brief="Network range; enumerate live hosts, ports, and services across the block.",
    ),
    AssetType(
        key="domain",
        name="Domain",
        category="Web",
        kind="url",
        skill="domain",
        prefixes=("domain",),
        brief="Map DNS, subdomains, and every web surface under the apex domain.",
    ),
    AssetType(
        key="ios_app_store",
        name="iOS App Store",
        category="Mobile",
        kind="identifier",
        skill="ios_app_store",
        prefixes=("ios-appstore", "appstore"),
        brief="Acquire the IPA from the App Store listing, then assess the iOS app.",
    ),
    AssetType(
        key="ios_testflight",
        name="iOS TestFlight",
        category="Mobile",
        kind="identifier",
        skill="ios_testflight",
        prefixes=("testflight",),
        brief="Install via TestFlight, capture the build, then assess the iOS app.",
    ),
    AssetType(
        key="ios_ipa",
        name="iOS .IPA",
        category="Mobile",
        kind="file",
        skill="ios_ipa",
        prefixes=("ipa",),
        exts=(".ipa",),
        brief="Static and dynamic assessment of the IPA: ATS, keychain, entitlements.",
    ),
    AssetType(
        key="android_play_store",
        name="Android Play Store",
        category="Mobile",
        kind="identifier",
        skill="android_play_store",
        prefixes=("playstore", "googleplay"),
        brief="Pull the APK/AAB from Play, then assess the Android app.",
    ),
    AssetType(
        key="android_apk",
        name="Android .APK",
        category="Mobile",
        kind="file",
        skill="android_apk",
        prefixes=("apk",),
        exts=(".apk", ".aab"),
        brief="Decompile, review manifest and exported components, then test dynamically.",
    ),
    AssetType(
        key="windows_store_app",
        name="Windows Microsoft Store",
        category="Desktop",
        kind="identifier",
        skill="windows_store_app",
        prefixes=("msstore", "windows-store"),
        brief="Acquire the MSIX/APPX package, then assess the Windows app.",
    ),
    AssetType(
        key="source_code",
        name="Source Code",
        category="Code",
        kind="code",
        skill="source_code_review",
        prefixes=("source", "sourcecode"),
        brief="Whitebox SAST plus manual review across the repository.",
    ),
    AssetType(
        key="executable",
        name="Executable",
        category="Desktop",
        kind="file",
        skill="native_executable",
        prefixes=("exe", "executable"),
        exts=(".exe", ".dll"),
        brief="Reverse-engineer the binary: protections, strings, secrets, memory safety.",
    ),
    AssetType(
        key="smart_contract",
        name="Smart Contract",
        category="Web3",
        kind="identifier",
        skill="smart_contracts",
        prefixes=("contract", "smartcontract"),
        exts=(".sol",),
        brief="Audit contract logic for reentrancy, access control, and economic flaws.",
    ),
    AssetType(
        key="wildcard",
        name="Wildcard",
        category="Web",
        kind="network",
        skill="wildcard_scope",
        prefixes=("wildcard",),
        brief="Enumerate every subdomain in scope and triage each surface.",
    ),
    AssetType(
        key="ip_address",
        name="IP Address",
        category="Network",
        kind="network",
        skill="ip_address",
        prefixes=("ip",),
        brief="Port and service scan, then per-service assessment.",
    ),
    AssetType(
        key="hardware_iot",
        name="Hardware / IoT",
        category="Hardware",
        kind="identifier",
        skill="hardware_iot",
        prefixes=("iot", "hardware"),
        brief="Assess firmware, exposed services, debug interfaces, and update flows.",
    ),
    AssetType(
        key="other_asset",
        name="Other Asset",
        category="Other",
        kind="identifier",
        skill="other_asset",
        prefixes=("other", "asset"),
        brief="Generic asset; identify type, map surface, then apply matching methodology.",
    ),
    AssetType(
        key="ai_model",
        name="AI Model",
        category="AI/ML",
        kind="identifier",
        skill="ai_model",
        prefixes=("model", "aimodel"),
        brief="Probe for jailbreaks, prompt injection, data leakage, and unsafe output.",
    ),
    AssetType(
        key="api",
        name="API",
        category="Web",
        kind="url",
        skill="api_security",
        prefixes=("api",),
        brief="Enumerate endpoints and auth, then test authz, injection, and logic.",
    ),
    AssetType(
        key="aws_account",
        name="AWS Account",
        category="Cloud",
        kind="account",
        skill="aws",
        prefixes=("aws", "aws-account"),
        brief="Enumerate IAM, public resources, and misconfigurations across the account.",
    ),
    AssetType(
        key="azure_account",
        name="Azure Account",
        category="Cloud",
        kind="account",
        skill="azure",
        prefixes=("azure", "azure-account"),
        brief="Enumerate Entra ID, RBAC, and exposed resources across the subscription.",
    ),
    AssetType(
        key="blockchain",
        name="Blockchain",
        category="Web3",
        kind="identifier",
        skill="blockchain_rpc",
        prefixes=("blockchain", "chain"),
        brief="Assess the chain, node, and protocol layer per blockchain methodology.",
    ),
    AssetType(
        key="dlt",
        name="DLT",
        category="Web3",
        kind="identifier",
        skill="dlt",
        prefixes=("dlt",),
        brief="Assess permissioned-ledger consensus, membership, and contract layer.",
    ),
    # --- Web / Network ---
    AssetType(
        key="url",
        name="URL",
        category="Web",
        kind="url",
        skill="url",
        prefixes=("url",),
        brief="Crawl and test the web application at this URL.",
    ),
    AssetType(
        key="subdomain",
        name="Subdomain",
        category="Web",
        kind="url",
        skill="subdomain",
        prefixes=("subdomain",),
        brief="Assess this specific host and its services.",
    ),
    AssetType(
        key="graphql_endpoint",
        name="GraphQL Endpoint",
        category="Web",
        kind="url",
        skill="graphql",
        prefixes=("graphql",),
        brief="Introspect the schema, then test resolvers, batching, and authz.",
    ),
    AssetType(
        key="websocket",
        name="WebSocket",
        category="Web",
        kind="url",
        skill="websocket",
        prefixes=("websocket",),
        brief="Test the WS handshake, origin checks, auth, and message tampering.",
    ),
    AssetType(
        key="grpc",
        name="gRPC Service",
        category="Web",
        kind="url",
        skill="grpc",
        prefixes=("grpc",),
        brief="Enumerate services via reflection, then test methods and authz.",
    ),
    AssetType(
        key="rest_api",
        name="REST API Endpoint",
        category="Web",
        kind="url",
        skill="rest_api",
        prefixes=("rest", "restapi"),
        brief="Enumerate routes and verbs, then test authz, injection, and logic.",
    ),
    AssetType(
        key="oauth_sso",
        name="OAuth / SSO Provider",
        category="Identity",
        kind="url",
        skill="oauth_sso",
        prefixes=("oauth", "sso"),
        brief="Test OAuth/OIDC flows: redirect_uri, state, PKCE, token handling.",
    ),
    AssetType(
        key="vpn_gateway",
        name="VPN / Remote Access Gateway",
        category="Network",
        kind="network",
        skill="vpn_gateway",
        prefixes=("vpn",),
        brief="Fingerprint the gateway, check known CVEs, and test auth exposure.",
    ),
    AssetType(
        key="cdn_edge",
        name="CDN / Edge Infrastructure",
        category="Network",
        kind="network",
        skill="cdn_edge",
        prefixes=("cdn", "edge"),
        brief="Test cache poisoning, origin exposure, and edge-rule bypasses.",
    ),
    AssetType(
        key="dns_infrastructure",
        name="DNS Infrastructure",
        category="Network",
        kind="network",
        skill="dns_infrastructure",
        prefixes=("dns",),
        brief="Test zone transfers, takeovers, DNSSEC, and resolver behavior.",
    ),
    # --- Cloud & Infrastructure ---
    AssetType(
        key="gcp_account",
        name="GCP Account / Project",
        category="Cloud",
        kind="account",
        skill="gcp",
        prefixes=("gcp", "gcp-project"),
        brief="Enumerate IAM, public resources, and misconfigurations in the project.",
    ),
    AssetType(
        key="google_workspace",
        name="Google Workspace",
        category="Cloud",
        kind="account",
        skill="google_workspace",
        prefixes=("gworkspace", "googleworkspace"),
        brief="Assess tenant sharing, OAuth apps, and admin/identity exposure.",
    ),
    AssetType(
        key="microsoft_365",
        name="Microsoft 365 Tenant",
        category="Cloud",
        kind="account",
        skill="microsoft_365",
        prefixes=("m365", "o365"),
        brief="Assess Entra ID, tenant sharing, and exposed M365 services.",
    ),
    AssetType(
        key="s3_bucket",
        name="AWS S3 Bucket",
        category="Cloud",
        kind="identifier",
        skill="s3_bucket",
        prefixes=("s3",),
        brief="Check ACLs, policy, listing, and object exposure on the bucket.",
    ),
    AssetType(
        key="azure_blob",
        name="Azure Blob / Storage",
        category="Cloud",
        kind="identifier",
        skill="azure_blob",
        prefixes=("azblob", "azureblob"),
        brief="Check container access level, SAS exposure, and public blobs.",
    ),
    AssetType(
        key="container_image",
        name="Docker Registry / Image",
        category="Cloud",
        kind="identifier",
        skill="container_image",
        prefixes=("image", "container", "registry"),
        brief="Scan layers for secrets, CVEs, and misconfigured entrypoints.",
    ),
    AssetType(
        key="kubernetes_cluster",
        name="Kubernetes Cluster",
        category="Cloud",
        kind="network",
        skill="kubernetes",
        prefixes=("k8s", "kube", "kubernetes"),
        brief="Test API-server exposure, RBAC, workloads, and secret access.",
    ),
    AssetType(
        key="cicd_pipeline",
        name="CI/CD Pipeline",
        category="Cloud",
        kind="identifier",
        skill="cicd_pipeline",
        prefixes=("cicd", "pipeline"),
        brief="Test pipeline injection, secret exposure, and artifact integrity.",
    ),
    AssetType(
        key="serverless_function",
        name="Serverless Function",
        category="Cloud",
        kind="identifier",
        skill="serverless_function",
        prefixes=("serverless", "lambda", "function"),
        brief="Test event injection, IAM scope, and dependency/runtime exposure.",
    ),
    AssetType(
        key="vm_image",
        name="Container / VM Image",
        category="Cloud",
        kind="file",
        skill="vm_image",
        prefixes=("vmimage", "ami"),
        exts=(".ova", ".vmdk", ".qcow2"),
        brief="Mount and scan the image for secrets, CVEs, and misconfigurations.",
    ),
    # --- Desktop & Compiled Software ---
    AssetType(
        key="macos_app",
        name="macOS Application",
        category="Desktop",
        kind="file",
        skill="macos_app",
        prefixes=("macapp", "macos"),
        exts=(".app", ".dmg", ".pkg"),
        brief="Check signing, entitlements, hardened runtime, and IPC exposure.",
    ),
    AssetType(
        key="linux_package",
        name="Linux Binary / Package",
        category="Desktop",
        kind="file",
        skill="linux_package",
        prefixes=("deb", "rpm", "linuxpkg"),
        exts=(".deb", ".rpm"),
        brief="Inspect package scripts, binaries, and bundled dependency CVEs.",
    ),
    AssetType(
        key="electron_app",
        name="Electron Desktop App",
        category="Desktop",
        kind="file",
        skill="electron_app",
        prefixes=("electron",),
        exts=(".asar",),
        brief="Unpack the ASAR; test nodeIntegration, IPC, and protocol handlers.",
    ),
    AssetType(
        key="browser_extension",
        name="Browser Extension",
        category="Desktop",
        kind="file",
        skill="browser_extension",
        prefixes=("extension", "crx"),
        exts=(".crx", ".xpi"),
        brief="Review manifest, permissions, content scripts, and message passing.",
    ),
    AssetType(
        key="firmware",
        name="Firmware",
        category="Hardware",
        kind="file",
        skill="firmware",
        prefixes=("firmware", "fw"),
        exts=(".img", ".hex", ".bin"),
        brief="Extract the filesystem; hunt secrets, services, and backdoors.",
    ),
    # --- Web3 / Blockchain ---
    AssetType(
        key="blockchain_node",
        name="Blockchain Node / Client",
        category="Web3",
        kind="network",
        skill="blockchain_node",
        prefixes=("node", "blockchain-node"),
        brief="Test RPC exposure, admin methods, and peer/consensus interfaces.",
    ),
    AssetType(
        key="defi_dapp",
        name="DeFi Protocol / dApp",
        category="Web3",
        kind="identifier",
        skill="defi_dapp",
        prefixes=("defi", "dapp"),
        brief="Audit on-chain logic and the dApp frontend/wallet integration.",
    ),
    AssetType(
        key="token_contract",
        name="NFT / Token Contract",
        category="Web3",
        kind="identifier",
        skill="token_contract",
        prefixes=("token", "nft"),
        brief="Audit mint/transfer/approval logic and access control.",
    ),
    AssetType(
        key="cross_chain_bridge",
        name="Bridge / Cross-chain",
        category="Web3",
        kind="identifier",
        skill="cross_chain_bridge",
        prefixes=("bridge",),
        brief="Audit message verification, replay protection, and custody logic.",
    ),
    AssetType(
        key="oracle_integration",
        name="Oracle Integration",
        category="Web3",
        kind="identifier",
        skill="oracle_integration",
        prefixes=("oracle",),
        brief="Test price-feed manipulation, staleness, and source trust.",
    ),
    AssetType(
        key="wallet",
        name="Wallet",
        category="Web3",
        kind="identifier",
        skill="wallet",
        prefixes=("wallet",),
        brief="Assess key storage, signing flows, and transaction approval UX.",
    ),
    AssetType(
        key="crypto_library",
        name="Cryptographic Library",
        category="Web3",
        kind="code",
        skill="crypto_library",
        prefixes=("crypto", "cryptolib"),
        brief="Review primitives, randomness, constant-time, and key handling.",
    ),
    # --- AI / ML ---
    AssetType(
        key="llm_safety_classifier",
        name="LLM Safety Classifier",
        category="AI/ML",
        kind="identifier",
        skill="llm_safety_classifier",
        prefixes=("llmsafety", "alignment"),
        brief="Test classifier evasion, false-negative bypasses, and prompt smuggling.",
    ),
    AssetType(
        key="ml_model_weights",
        name="ML Model Weights / Artifact",
        category="AI/ML",
        kind="file",
        skill="ml_model_weights",
        prefixes=("weights", "mlmodel"),
        exts=(".safetensors", ".gguf", ".pt", ".pth", ".onnx", ".h5", ".pkl", ".ckpt"),
        brief="Scan for unsafe deserialization, backdoors, and embedded payloads.",
    ),
    AssetType(
        key="ai_inference_endpoint",
        name="AI Inference Endpoint",
        category="AI/ML",
        kind="url",
        skill="ai_inference_endpoint",
        prefixes=("inference", "ai-endpoint"),
        brief="Test prompt injection, output handling, rate limits, and authz.",
    ),
    AssetType(
        key="training_data_pipeline",
        name="Training Data Pipeline",
        category="AI/ML",
        kind="identifier",
        skill="training_data_pipeline",
        prefixes=("trainingdata", "datapipeline"),
        brief="Test data poisoning, source trust, and pipeline access control.",
    ),
    # --- Identity & Auth ---
    AssetType(
        key="saml_oidc_idp",
        name="SAML / OIDC Identity Provider",
        category="Identity",
        kind="url",
        skill="saml_oidc_idp",
        prefixes=("idp", "saml", "oidc"),
        brief="Test SAML/OIDC signature, audience, replay, and assertion tampering.",
    ),
    AssetType(
        key="ldap_active_directory",
        name="SSO / LDAP / AD",
        category="Identity",
        kind="network",
        skill="ldap_active_directory",
        prefixes=("ldap", "ad", "activedirectory"),
        brief="Test bind/injection, anonymous access, and directory enumeration.",
    ),
    AssetType(
        key="fido2_webauthn",
        name="Hardware Key / FIDO2",
        category="Identity",
        kind="identifier",
        skill="fido2_webauthn",
        prefixes=("fido2", "webauthn"),
        brief="Test WebAuthn ceremony, origin binding, and fallback weaknesses.",
    ),
    AssetType(
        key="pki_ca",
        name="Certificate Authority / PKI",
        category="Identity",
        kind="identifier",
        skill="pki_ca",
        prefixes=("pki", "ca"),
        brief="Test issuance controls, chain validation, and key protection.",
    ),
    # --- Networking / Physical ---
    AssetType(
        key="asn",
        name="ASN",
        category="Network",
        kind="identifier",
        skill="asn",
        prefixes=("asn",),
        brief="Expand the ASN to prefixes, then enumerate hosts and services.",
    ),
    AssetType(
        key="ot_scada_ics",
        name="OT / SCADA / ICS",
        category="Hardware",
        kind="network",
        skill="ot_scada_ics",
        prefixes=("scada", "ics", "ot"),
        brief="Safely fingerprint industrial protocols; never disrupt live process.",
    ),
    AssetType(
        key="physical_access_control",
        name="Physical Facility / Access Control",
        category="Physical",
        kind="identifier",
        skill="physical_access_control",
        prefixes=("physical", "facility"),
        brief="Assess badge, lock, and access-control system exposure.",
    ),
    AssetType(
        key="network_device",
        name="Network Device",
        category="Network",
        kind="network",
        skill="network_device",
        prefixes=("netdevice", "device"),
        brief="Fingerprint the switch/firewall/router; test mgmt exposure and CVEs.",
    ),
    AssetType(
        key="rf_interface",
        name="Satellite / Radio / RF",
        category="Physical",
        kind="identifier",
        skill="rf_interface",
        prefixes=("rf", "radio", "satellite"),
        brief="Assess the RF interface, protocol, and signal-handling exposure.",
    ),
)


_BY_KEY: dict[str, AssetType] = {a.key: a for a in ASSET_TYPES}
_BY_PREFIX: dict[str, AssetType] = {p: a for a in ASSET_TYPES for p in a.prefixes}
_BY_EXT: dict[str, AssetType] = {e: a for a in ASSET_TYPES for e in a.exts}

_ASN_RE = re.compile(r"^AS\d{1,10}$", re.IGNORECASE)
_ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9_-]{1,63}\.)+[a-zA-Z]{2,}$")


def by_key(key: str) -> AssetType | None:
    return _BY_KEY.get(key)


def match_prefix(target: str) -> tuple[AssetType, str] | None:
    """Resolve an explicit ``prefix:value`` form; None if prefix unknown or value is a URL."""
    head, sep, rest = target.partition(":")
    rest = rest.strip()
    if not sep or not rest or rest.startswith("//"):
        return None
    asset = _BY_PREFIX.get(head.strip().lower())
    if asset is None:
        return None
    return asset, rest


def match_scheme(target: str) -> tuple[AssetType, str] | None:
    """Resolve a ``scheme://`` URL whose scheme maps to an asset type."""
    if "://" not in target:
        return None
    key = SCHEME_MAP.get(urlparse(target).scheme.lower())
    if key is None:
        return None
    return _BY_KEY[key], target


def match_pattern(target: str) -> tuple[AssetType, str] | None:
    """Resolve unambiguous string patterns: CIDR, wildcard, ASN, ETH address."""
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            network = None
        if network is not None:
            return _BY_KEY["cidr"], str(network)

    if target.startswith("*.") and _DOMAIN_RE.match(target[2:]):
        return _BY_KEY["wildcard"], target

    if _ASN_RE.match(target):
        return _BY_KEY["asn"], target.upper()

    if _ETH_RE.match(target):
        return _BY_KEY["smart_contract"], target

    return None


def match_extension(name: str) -> AssetType | None:
    """Classify a local artifact by file extension."""
    return _BY_EXT.get(PurePath(name).suffix.lower())
