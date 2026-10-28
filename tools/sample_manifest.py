"""Validate local evaluation samples independently of the audit runtime."""

import argparse
import hashlib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EvidenceAnnotation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)

    location: str = Field(min_length=1)
    observation: str = Field(min_length=1)


CASE_EXPECTATIONS = {
    "known_vulnerability": "vulnerable",
    "safe_argument": "not_vulnerable",
    "effective_guard": "not_vulnerable",
    "ineffective_guard": "vulnerable",
    "insufficient_evidence": "unknown",
}


class SampleManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)

    schema_version: Literal["1", "2"]
    sample_id: str = Field(min_length=1)
    artifact: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    split: Literal["development", "evaluation"]
    vulnerability_type: str = Field(min_length=1)
    expected: Literal["vulnerable", "not_vulnerable", "unknown"]
    scope: str = Field(min_length=1)
    references: list[str] = Field(default_factory=list)
    notes: str = ""
    case_kind: Literal[
        "known_vulnerability", "safe_argument", "effective_guard",
        "ineffective_guard", "insufficient_evidence",
    ] | None = None
    origin: Literal["real_world", "synthetic"] | None = None
    evidence: list[EvidenceAnnotation] = Field(default_factory=list)
    rationale: str = ""
    limitations: str = ""

    @model_validator(mode="after")
    def validate_annotation(self):
        if any(not reference.strip() for reference in self.references):
            raise ValueError("references must not be blank")
        if self.expected != "unknown" and not self.references:
            raise ValueError("known expectations require supporting references")
        if self.schema_version == "1":
            if self.case_kind or self.origin or self.evidence or self.rationale or self.limitations:
                raise ValueError("structured annotations require schema_version 2")
            return self
        if self.case_kind is None or self.origin is None:
            raise ValueError("version 2 requires case_kind and origin")
        if self.expected != CASE_EXPECTATIONS[self.case_kind]:
            raise ValueError("case_kind conflicts with expected conclusion")
        if not self.rationale or not self.limitations:
            raise ValueError("version 2 requires rationale and limitations")
        if self.expected != "unknown" and not self.evidence:
            raise ValueError("known expectations require located evidence")
        return self


def validate_sample(manifest_path: Path, artifact_root: Path) -> SampleManifest:
    manifest = SampleManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    root = artifact_root.resolve()
    relative = Path(manifest.artifact)
    if relative.is_absolute():
        raise ValueError("artifact must be relative to the artifact root")
    artifact = (root / relative).resolve()
    if not artifact.is_relative_to(root):
        raise ValueError("artifact escapes the artifact root")
    if not artifact.is_file():
        raise ValueError("artifact is not an existing file")
    digest = hashlib.sha256()
    with artifact.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != manifest.sha256:
        raise ValueError("artifact SHA-256 mismatch")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        manifest = validate_sample(args.manifest, args.artifact_root)
    except (OSError, ValueError) as error:
        parser.exit(1, "Invalid sample: {}\n".format(error))
    print("Validated sample: {}".format(manifest.sample_id))


if __name__ == "__main__":
    main()
