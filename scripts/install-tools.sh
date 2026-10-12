#!/usr/bin/env bash
# Installs the optional scanners Bairav can use. Bairav still runs without them (missing ones are skipped),
# but every scanner adds coverage. macOS (Homebrew) and Linux (apt/pip/curl) are supported.
set -uo pipefail

have() { command -v "$1" >/dev/null 2>&1; }
step() { printf '\n==> %s\n' "$1"; }

OS="$(uname -s)"

if [ "$OS" = "Darwin" ]; then
  have brew || { echo "Homebrew is required: https://brew.sh"; exit 1; }
  step "Installing scanners with Homebrew"
  brew install semgrep trivy gitleaks osv-scanner spotbugs maven node || true
elif [ "$OS" = "Linux" ]; then
  step "Installing Maven, Node and pip (apt)"
  if have apt-get; then sudo apt-get update && sudo apt-get install -y maven nodejs npm python3-pip git curl; fi
  step "semgrep"
  have semgrep || pip3 install --user semgrep
  step "trivy"
  have trivy || curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$HOME/.local/bin"
  step "gitleaks / osv-scanner / spotbugs"
  echo "Install these from their release pages if you want them:"
  echo "  gitleaks     https://github.com/gitleaks/gitleaks/releases"
  echo "  osv-scanner  https://github.com/google/osv-scanner/releases"
  echo "  spotbugs     https://github.com/spotbugs/spotbugs/releases (put 'spotbugs' on PATH)"
else
  echo "Unsupported OS '$OS'. On Windows use WSL2 (Ubuntu) and run this script there."
  exit 1
fi

step "Result"
BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin/bairav"
[ -x "$BIN" ] && "$BIN" --doctor || echo "Build Bairav first (mvn package), then run: bin/bairav --doctor"
