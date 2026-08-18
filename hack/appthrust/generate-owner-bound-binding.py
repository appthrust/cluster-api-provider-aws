#!/usr/bin/env python3
"""Generate an unsealed Platform OwnerBoundCAPAArtifactBinding."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

GIT_OBJECT = re.compile(r"^[0-9a-f]{40}$")
SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ATTESTATION_IDENTITY = re.compile(r"^\S+@sha256:[0-9a-f]{64}$")
NON_EMPTY = re.compile(r".*\S.*")
EMPTY_SHA256_DIGEST = f"sha256:{'0' * 64}"
EMPTY_FILE_SHA256_DIGEST = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

SCHEMA_VERSION = "appthrust-owner-bound-capa-artifact/v1"
UPSTREAM_REPOSITORY = "https://github.com/kubernetes-sigs/cluster-api-provider-aws.git"
UPSTREAM_TAG = "v2.13.0"
UPSTREAM_TAG_OBJECT = "9d3c4c0c07e739cd0a0d616adf76f2a294ec91de"
UPSTREAM_COMMIT = "a84670fca02690c9e644fadcbbbf967a6e6f89d6"
DOWNSTREAM_REPOSITORY = "github.com/appthrust/cluster-api-provider-aws"
IMAGE_REPOSITORY = "ghcr.io/appthrust/platform/cluster-api-provider-aws"
BUILDER_IMAGE_REPOSITORY = "docker.io/library/golang:1.26.6"
BUILDER_IMAGE_DIGEST = "sha256:0d1d3a794be25f809dd2cb3160d8c73276c4056a9f8242a138e908ddeee7b6b6"
RUNTIME_IMAGE_REPOSITORY = "gcr.io/distroless/static:nonroot"
RUNTIME_IMAGE_DIGEST = "sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6"
CAPA_OWNER_COMPONENT = "cluster-api-provider-aws"
CAPA_MATERIALIZER_IMPORT = "github.com/appthrust/platform/pkg/clusterinventory/packagemanifest"
CAPACITY_FENCE_IMPORT = "github.com/appthrust/platform/pkg/capacityfence"
WATCH_FILTER_LABEL = "cluster.x-k8s.io/watch-filter"
WATCH_FILTER_SOURCE = "charts/capa-capacity-gate/values.yaml#watchFilter.value"
SERVICE_ACCOUNT_USERNAME = "system:serviceaccount:capa-system:capa-controller-manager"
SERVICE_ACCOUNT_GROUPS = [
    "system:serviceaccounts",
    "system:serviceaccounts:capa-system",
    "system:authenticated",
]
SIGNATURE_ISSUER = "https://token.actions.githubusercontent.com"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--upstream-source-digest", required=True)
    parser.add_argument("--downstream-commit", required=True)
    parser.add_argument("--downstream-source-digest", required=True)
    parser.add_argument("--downstream-tree-digest", required=True)
    parser.add_argument("--downstream-patch-digest", required=True)
    parser.add_argument("--platform-revision", required=True)
    parser.add_argument("--platform-model-subtree-digest", required=True)
    parser.add_argument("--build-workspace-digest", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--provider-manifest-digest", required=True)
    parser.add_argument("--crds-digest", required=True)
    parser.add_argument("--rbac-digest", required=True)
    parser.add_argument("--service-account-digest", required=True)
    parser.add_argument("--deployment-digest", required=True)
    parser.add_argument("--sbom-identity", required=True)
    parser.add_argument("--sbom-digest", required=True)
    parser.add_argument("--provenance-identity", required=True)
    parser.add_argument("--provenance-digest", required=True)
    parser.add_argument("--signature-identity", required=True)
    parser.add_argument("--signature-issuer", required=True)
    parser.add_argument("--signature-digest", required=True)
    parser.add_argument("--publication-visibility", required=True)
    parser.add_argument("--anonymous-pull-verified", required=True)
    return parser.parse_args()


def require_match(value: str, pattern: re.Pattern[str], field: str) -> None:
    if not pattern.fullmatch(value):
        raise ValueError(f"{field} has an invalid format")


def require_digest(value: str, field: str) -> None:
    require_match(value, SHA256_DIGEST, field)
    if value in (EMPTY_SHA256_DIGEST, EMPTY_FILE_SHA256_DIGEST):
        raise ValueError(f"{field} must identify non-empty immutable bytes")


def binding(args: argparse.Namespace) -> dict[str, Any]:
    for field in ("downstream_commit", "platform_revision"):
        require_match(getattr(args, field), GIT_OBJECT, field.replace("_", " "))
    for field in (
        "upstream_source_digest",
        "downstream_source_digest",
        "downstream_tree_digest",
        "downstream_patch_digest",
        "platform_model_subtree_digest",
        "build_workspace_digest",
        "image_digest",
        "provider_manifest_digest",
        "crds_digest",
        "rbac_digest",
        "service_account_digest",
        "deployment_digest",
        "sbom_digest",
        "provenance_digest",
        "signature_digest",
    ):
        require_digest(getattr(args, field), field.replace("_", " "))
    for field in ("sbom_identity", "provenance_identity", "signature_identity"):
        require_match(getattr(args, field), ATTESTATION_IDENTITY, field.replace("_", " "))
    require_match(args.signature_issuer, NON_EMPTY, "signature issuer")
    if args.signature_issuer != SIGNATURE_ISSUER:
        raise ValueError("signature issuer is not the GitHub Actions OIDC issuer")
    if args.publication_visibility != "public":
        raise ValueError("publication visibility must be public")
    if args.anonymous_pull_verified != "true":
        raise ValueError("anonymous pull verification must be true")


    image_reference = f"{IMAGE_REPOSITORY}@{args.image_digest}"
    for field in ("sbom_identity", "provenance_identity", "signature_identity"):
        if getattr(args, field) != image_reference:
            raise ValueError(f"{field.replace('_', ' ')} must bind the exact image digest")

    return {
        "schemaVersion": SCHEMA_VERSION,
        "upstream": {
            "repository": UPSTREAM_REPOSITORY,
            "tag": UPSTREAM_TAG,
            "tagObject": UPSTREAM_TAG_OBJECT,
            "commit": UPSTREAM_COMMIT,
            "sourceDigest": args.upstream_source_digest,
        },
        "downstream": {
            "repository": DOWNSTREAM_REPOSITORY,
            "commit": args.downstream_commit,
            "sourceDigest": args.downstream_source_digest,
            "treeDigest": args.downstream_tree_digest,
            "patchDigest": args.downstream_patch_digest,
        },
        "platform": {
            "capacityFenceRevision": args.platform_revision,
            "modelSubtreeDigest": args.platform_model_subtree_digest,
            "buildWorkspaceDigest": args.build_workspace_digest,
        },
        "build": {
            "builderImage": {
                "repository": BUILDER_IMAGE_REPOSITORY,
                "digest": BUILDER_IMAGE_DIGEST,
            },
            "runtimeImage": {
                "repository": RUNTIME_IMAGE_REPOSITORY,
                "digest": RUNTIME_IMAGE_DIGEST,
            },
        },
        "versions": {"capa": "v2.13.0", "capi": "v1.13.4"},
        "adapter": {
            "capacityFenceImport": CAPACITY_FENCE_IMPORT,
            "selector": {"label": WATCH_FILTER_LABEL, "source": WATCH_FILTER_SOURCE},
            "caller": {
                "username": SERVICE_ACCOUNT_USERNAME,
                "groups": SERVICE_ACCOUNT_GROUPS,
            },
        },
        "image": {
            "platform": "linux/amd64",
            "repository": IMAGE_REPOSITORY,
            "digest": args.image_digest,
        },
        "attestations": {
            "sbom": {"identity": args.sbom_identity, "digest": args.sbom_digest},
            "provenance": {
                "identity": args.provenance_identity,
                "digest": args.provenance_digest,
            },
            "signature": {
                "identity": args.signature_identity,
                "issuer": args.signature_issuer,
                "digest": args.signature_digest,
            },
        },
        "generated": {
            "providerManifestDigest": args.provider_manifest_digest,
            "crdsDigest": args.crds_digest,
            "rbacDigest": args.rbac_digest,
            "serviceAccountDigest": args.service_account_digest,
            "deploymentDigest": args.deployment_digest,
        },
        "publication": {
            "repository": IMAGE_REPOSITORY,
            "digest": args.image_digest,
            "visibility": "public",
            "anonymousPullVerified": True,
        },
        "ownerBinding": {
            "platform": {
                "component": CAPA_OWNER_COMPONENT,
                "permitAuthority": CAPACITY_FENCE_IMPORT,
                "materializer": CAPA_MATERIALIZER_IMPORT,
                "watchFilter": {
                    "source": WATCH_FILTER_SOURCE,
                    "label": WATCH_FILTER_LABEL,
                },
            },
            "capa": {
                "serviceAccount": {
                    "username": SERVICE_ACCOUNT_USERNAME,
                    "groups": SERVICE_ACCOUNT_GROUPS,
                },
            },
        },
    }


def main() -> int:
    args = parse_args()
    try:
        generated = binding(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if args.output.exists():
            raise ValueError("binding output already exists")
        with args.output.open("x", encoding="utf-8") as destination:
            json.dump(generated, destination, indent=2, sort_keys=True)
            destination.write("\n")
        return 0
    except (OSError, ValueError) as error:
        print(f"owner-bound binding: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
