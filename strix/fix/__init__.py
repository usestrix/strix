"""Verified fix preparation contracts and runtime."""

from strix.fix.contracts import (
    CandidateLocation,
    CheckResult,
    CheckStatus,
    CommandSpec,
    FileManifestEntry,
    FixCandidateV1,
    FixEdit,
    FixPreparationRequestV1,
    FixPreparationResultV1,
    PreparationState,
    ReproductionSpec,
    SourceIdentity,
    SourceIdentityKind,
    VerificationDecision,
    VerifierResult,
    candidate_from_legacy_report,
)
from strix.fix.prepare import (
    PreparationCancelledError,
    PreparationContext,
    PreparationPolicy,
    build_git_manifest,
    prepare_fix,
)


__all__ = [
    "CandidateLocation",
    "CheckResult",
    "CheckStatus",
    "CommandSpec",
    "FileManifestEntry",
    "FixCandidateV1",
    "FixEdit",
    "FixPreparationRequestV1",
    "FixPreparationResultV1",
    "PreparationCancelledError",
    "PreparationContext",
    "PreparationPolicy",
    "PreparationState",
    "ReproductionSpec",
    "SourceIdentity",
    "SourceIdentityKind",
    "VerificationDecision",
    "VerifierResult",
    "build_git_manifest",
    "candidate_from_legacy_report",
    "prepare_fix",
]
