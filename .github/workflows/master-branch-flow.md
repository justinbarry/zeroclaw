# Head Build Flow

This document explains the single GitHub Actions workflow that remains in this repository.

Use this with:

- [`docs/ci-map.md`](../../docs/contributing/ci-map.md)
- [`docs/pr-workflow.md`](../../docs/contributing/pr-workflow.md)

## Active Workflow

| File | Trigger | Purpose |
| --- | --- | --- |
| `ci-run.yml` | `push`, `workflow_dispatch` | Build the current HEAD for `x86_64-unknown-linux-gnu` and upload a downloadable artifact |

## Event Summary

| Event | Workflow triggered |
| --- | --- |
| Push to any branch | `ci-run.yml` |
| Manual dispatch | `ci-run.yml` |

## What It Produces

`ci-run.yml` builds the current commit on the `ubicloud-standard-16` runner, packages the `zeroclaw` binary into a tarball, generates a SHA-256 file, and uploads both as an Actions artifact.

Artifact format:

- `zeroclaw-x86_64-unknown-linux-gnu-<full_sha>.tar.gz`
- `zeroclaw-x86_64-unknown-linux-gnu-<full_sha>.sha256`

## Download Path

1. Open the relevant Actions run.
2. Download the uploaded artifact from the run's `Artifacts` section.
3. Copy the tarball into the VM and unpack it there.

## Quick Troubleshooting

1. Build failure: inspect the `Build current head` step in `ci-run.yml`.
2. Missing artifact: inspect the `Package artifact` and `Upload artifact` steps.
3. Wrong binary for the VM: this workflow only produces `x86_64-unknown-linux-gnu`.
