#!/usr/bin/env bash
# Sets AUTH_HEADER from GITHUB_TOKEN if present.
AUTH_HEADER=""
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    AUTH_HEADER="Authorization: token $GITHUB_TOKEN"
fi
