# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Proof Of Capture is a tool for cryptographically signing photographs to prove authenticity. It calculates a checksum of image pixel data (per-channel and total sums), signs the checksum string with an RSA private key, and stores the base64-encoded signature in the image's EXIF `ImageDescription` field. Verification re-derives the checksum, then checks the stored signature against a public key.

## Setup

- Python 3.12, managed with `uv`
- Virtual environment: `.venv/`
- Install deps: `uv sync`
- Key dependencies: `pillow`, `numpy`, `cryptography` (used but not yet in pyproject.toml), `c2pa-python`

## Running

The main CLI is `proofOfCapture.py`:

```bash
# Generate RSA keypair (saved to ./keys/)
python proofOfCapture.py -g

# Sign a photo (reads private key from ./keys/, writes to ./signedPhotos/output.jpg)
python proofOfCapture.py -s -i rawPhoto.jpg

# Verify a signed photo
python proofOfCapture.py -c -i signedPhotos/output.jpg

# Show EXIF metadata
python proofOfCapture.py -m -i <photo>

# Print public key
python proofOfCapture.py -pk
```

## Architecture

- `proofOfCapture.py` — Main CLI combining key generation, signing, and verification in one argparse-based script. This is the active development file.
- `checksum.py`, `generateKeys.py`, `writer.py` — Earlier standalone scripts that were consolidated into `proofOfCapture.py`.
- `main.py` — uv-generated stub entry point (unused).

## Known Issue

JPEG is lossy — saving a signed image as JPEG recompresses pixel data, so the checksum computed during verification won't match the checksum computed during signing. This is the root cause of the current signature verification failure.
