#!/usr/bin/env bash
set -euo pipefail

# Replace project bundle identifiers and manual signing settings for CI.
APP_BUNDLE_ID="${APP_BUNDLE_ID:-ru.altatec.sstp-client}"
TUNNEL_BUNDLE_ID="${TUNNEL_BUNDLE_ID:-ru.altatec.sstp-client.tunnel}"
BUILD_NUMBER="${BUILD_NUMBER:-1}"
IOS_TEAM_ID="${IOS_TEAM_ID:?IOS_TEAM_ID is required}"
CODE_SIGN_IDENTITY="${CODE_SIGN_IDENTITY:?CODE_SIGN_IDENTITY is required}"
APP_PROFILE_NAME="${APP_PROFILE_NAME:?APP_PROFILE_NAME is required}"
TUNNEL_PROFILE_NAME="${TUNNEL_PROFILE_NAME:?TUNNEL_PROFILE_NAME is required}"
PROJECT_FILE="com.vn.sstp.xcodeproj/project.pbxproj"

export APP_BUNDLE_ID TUNNEL_BUNDLE_ID BUILD_NUMBER IOS_TEAM_ID CODE_SIGN_IDENTITY APP_PROFILE_NAME TUNNEL_PROFILE_NAME PROJECT_FILE

python3 <<'PY'
import os
import pathlib
import re

project_path = pathlib.Path(os.environ["PROJECT_FILE"])
app_bundle_id = os.environ["APP_BUNDLE_ID"]
tunnel_bundle_id = os.environ["TUNNEL_BUNDLE_ID"]
build_number = os.environ["BUILD_NUMBER"]
team_id = os.environ["IOS_TEAM_ID"]
identity = os.environ["CODE_SIGN_IDENTITY"]
app_profile = os.environ["APP_PROFILE_NAME"]
tunnel_profile = os.environ["TUNNEL_PROFILE_NAME"].strip()
if not tunnel_profile:
    raise SystemExit("TUNNEL_PROFILE_NAME is empty")

text = project_path.read_text()

# Longer identifier first to avoid partial replacements.
text = text.replace(
    'PRODUCT_BUNDLE_IDENTIFIER = "cen.com-vn-sstp.tunnel";',
    f'PRODUCT_BUNDLE_IDENTIFIER = "{tunnel_bundle_id}";',
)
text = text.replace(
    'PRODUCT_BUNDLE_IDENTIFIER = "cen.com-vn-sstp";',
    f'PRODUCT_BUNDLE_IDENTIFIER = "{app_bundle_id}";',
)
text = re.sub(r"CURRENT_PROJECT_VERSION = \d+;", f"CURRENT_PROJECT_VERSION = {build_number};", text)
text = text.replace("CODE_SIGN_STYLE = Automatic;", "CODE_SIGN_STYLE = Manual;")
text = re.sub(r"DEVELOPMENT_TEAM = [A-Z0-9]+;", f"DEVELOPMENT_TEAM = {team_id};", text)


def upsert_setting(block: str, key: str, value: str) -> str:
    pattern = rf'{key} = ".*?";'
    replacement = f'{key} = "{value}";'
    if re.search(pattern, block):
        return re.sub(pattern, replacement, block)
    # Insert after opening buildSettings brace.
    return block.replace(
        "buildSettings = {\n",
        f'buildSettings = {{\n\t\t\t\t{replacement}\n',
        1,
    )


def patch_configs_for_bundle(source: str, bundle_id: str, profile_name: str) -> str:
    # Match a single XCBuildConfiguration buildSettings block that contains the bundle id.
    pattern = re.compile(
        r"(/\* [^*]+ \*/ = \{\n\t\t\tisa = XCBuildConfiguration;\n\t\t\tbuildSettings = \{.*?\n\t\t\t\};\n\t\t\tname = [A-Za-z]+;\n\t\t\};)",
        re.DOTALL,
    )

    matches = list(pattern.finditer(source))
    if not matches:
        raise SystemExit("No XCBuildConfiguration blocks found")

    patched = 0
    pieces = []
    last = 0
    for match in matches:
        pieces.append(source[last:match.start()])
        block = match.group(1)
        if f'PRODUCT_BUNDLE_IDENTIFIER = "{bundle_id}";' in block:
            block = upsert_setting(block, "CODE_SIGN_IDENTITY", identity)
            block = upsert_setting(block, "PROVISIONING_PROFILE_SPECIFIER", profile_name)
            patched += 1
        pieces.append(block)
        last = match.end()
    pieces.append(source[last:])

    if patched == 0:
        raise SystemExit(f"Failed to patch signing settings for bundle id {bundle_id}")
    print(f"Patched {patched} configuration(s) for {bundle_id}")
    return "".join(pieces)


text = patch_configs_for_bundle(text, app_bundle_id, app_profile)
text = patch_configs_for_bundle(text, tunnel_bundle_id, tunnel_profile)

project_path.write_text(text)
print(f"Updated bundle ids to {app_bundle_id} / {tunnel_bundle_id}")
print(f"Updated CURRENT_PROJECT_VERSION to {build_number}")
print(f"Manual signing team={team_id} identity={identity}")
print(f"App profile specifier={app_profile}")
print(f"Tunnel profile specifier={tunnel_profile}")
PY
