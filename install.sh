#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ -f ".env" ]]; then
  # shellcheck disable=SC1091
  source ".env"
fi

mkdir -p "logs" "tools" "tools/.bin"

export UV_TOOL_DIR="$ROOT_DIR/tools/."
export UV_TOOL_BIN_DIR="$ROOT_DIR/tools/.bin"
export PATH="$UV_TOOL_BIN_DIR:$PATH"

echo "[*] Syncing project dependencies with uv"
uv sync

install_uv_tool() {
  local package_name="$1"
  echo "[*] Installing/updating uv tool: ${package_name}"
  uv tool install --upgrade --reinstall "$package_name"
}

create_tool_helper () {
  local tool_name="$1"
  local tool_path="$2"
  cat > "$UV_TOOL_BIN_DIR/$tool_name" << TOOL
#!/bin/bash
uv run --script "$ROOT_DIR/tools/$tool_path" "\$@" || exit
TOOL
  chmod 755 "$UV_TOOL_BIN_DIR/$tool_name"
}

install_uv_tool "certipy-ad"
install_uv_tool "bloodyad"
install_uv_tool "bloodhound-ce"
install_uv_tool "miniresponder"

ln -sf "$ROOT_DIR/tools/certipy-ad/bin/addcomputer.py" "$UV_TOOL_BIN_DIR/"
ln -sf "$ROOT_DIR/tools/certipy-ad/bin/getST.py" "$UV_TOOL_BIN_DIR/"
ln -sf "$ROOT_DIR/tools/certipy-ad/bin/getTGT.py" "$UV_TOOL_BIN_DIR/"
ln -sf "$ROOT_DIR/tools/certipy-ad/bin/smbclient.py" "$UV_TOOL_BIN_DIR/"
ln -sf "$ROOT_DIR/tools/certipy-ad/bin/dacledit.py" "$UV_TOOL_BIN_DIR/"
ln -sf "$ROOT_DIR/tools/certipy-ad/bin/secretsdump.py" "$UV_TOOL_BIN_DIR/"
ln -sf "$ROOT_DIR/tools/certipy-ad/bin/GetUserSPNs.py" "$UV_TOOL_BIN_DIR/"
ln -sf "$ROOT_DIR/tools/certipy-ad/bin/GetNPUsers.py" "$UV_TOOL_BIN_DIR/"
ln -sf "$ROOT_DIR/tools/certipy-ad/bin/findDelegation.py" "$UV_TOOL_BIN_DIR/"
ln -sf "$ROOT_DIR/tools/certipy-ad/bin/Get-GPPPassword.py" "$UV_TOOL_BIN_DIR/"
ln -sf "$ROOT_DIR/tools/certipy-ad/bin/lookupsid.py" "$UV_TOOL_BIN_DIR/"
ln -sf "$ROOT_DIR/tools/certipy-ad/bin/ticketer.py" "$UV_TOOL_BIN_DIR/"

create_tool_helper dnstool krbrelayx/dnstool.py
create_tool_helper printerbug krbrelayx/printerbug.py
create_tool_helper krbrelayx krbrelayx/krbrelayx.py
create_tool_helper petitpotam PetitPotam.py
create_tool_helper dfscoerce dfscoerce.py
create_tool_helper shadowcoerce shadowcoerce.py

clone_if_missing() {
  local repo_url="$1"
  local destination="$2"

  if [[ -d "$destination/.git" ]]; then
    echo "[*] Using existing repository: ${destination}"
    return
  fi

  if [[ -e "$destination" ]]; then
    echo "[*] Using existing directory: ${destination}"
    return
  fi

  echo "[*] Cloning ${repo_url} -> ${destination}"
  git clone --depth 1 "$repo_url" "$destination"
}

clone_if_missing "https://github.com/dirkjanm/krbrelayx.git" "tools/krbrelayx"
clone_if_missing "https://github.com/dirkjanm/PKINITtools.git" "tools/PKINITtools"

echo "[*] Downloading PetitPotam helper script"
curl -fsSL \
  "https://raw.githubusercontent.com/topotam/PetitPotam/refs/heads/main/PetitPotam.py" \
  -o "tools/PetitPotam.py"

echo "[*] Downloading dfscoerce helper script"
curl -fsSL \
  "https://raw.githubusercontent.com/Wh04m1001/DFSCoerce/refs/heads/main/dfscoerce.py" \
  -o "tools/dfscoerce.py"

echo "[*] Downloading ShadowCoerce helper script"
curl -fsSL \
  "https://raw.githubusercontent.com/ShutdownRepo/ShadowCoerce/refs/heads/main/shadowcoerce.py" \
  -o "tools/shadowcoerce.py"

if [[ -x "tools/bloodhound-ce/bin/python" ]]; then
  echo "[*] Patching bloodhound-ce ldap3 for channel binding support"
  uv pip install --python "tools/bloodhound-ce/bin/python" --upgrade "git+https://github.com/ly4k/ldap3"
fi

TOOL_BIN_PATHS=""
for tool_bin in tools/*/bin; do
  if [[ -d "$tool_bin" ]]; then
    TOOL_BIN_PATHS="${TOOL_BIN_PATHS:+${TOOL_BIN_PATHS}:}${ROOT_DIR}/${tool_bin}"
  fi
done

if [[ -n "$TOOL_BIN_PATHS" ]]; then
  export PATH="$TOOL_BIN_PATHS:$PATH"
fi

verify_help() {
  local entrypoint="$1"
  shift

  if [[ ! -x "$entrypoint" ]]; then
    echo "[!] Missing executable entrypoint: $entrypoint"
    return 1
  fi

  "$entrypoint" "$@" >/dev/null 2>&1
}

echo "[*] Verifying tool entrypoints"
verify_help "tools/certipy-ad/bin/certipy" -h
verify_help "tools/bloodyad/bin/bloodyAD" -h
verify_help "tools/bloodhound-ce/bin/bloodhound-ce-python" -h
verify_help "tools/miniresponder/bin/miniresponder" -h
verify_help "tools/certipy-ad/bin/getTGT.py" -h
verify_help "tools/certipy-ad/bin/Get-GPPPassword.py" -h
verify_help "tools/certipy-ad/bin/ntlmrelayx.py" -h

if [[ ! -f "tools/krbrelayx/krbrelayx.py" ]]; then
  echo "[!] Missing krbrelayx.py in tools/krbrelayx"
  exit 1
fi

if [[ ! -f "tools/krbrelayx/dnstool.py" ]]; then
  echo "[!] Missing dnstool.py in tools/krbrelayx"
  exit 1
fi

if [[ ! -f "tools/PetitPotam.py" ]]; then
  echo "[!] Missing tools/PetitPotam.py"
  exit 1
fi

echo "[*] Registering modules"
uv run main.py --register-modules >/dev/null

echo "[+] Install completed successfully"
echo "[+] UV_TOOL_DIR=${UV_TOOL_DIR}"
