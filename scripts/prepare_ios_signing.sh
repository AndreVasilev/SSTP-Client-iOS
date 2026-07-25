#!/usr/bin/env bash
set -euo pipefail

# Install distribution certificate and provisioning profiles for CI signing.
# Expected env:
#   BUILD_CERTIFICATE_BASE64
#   P12_PASSWORD
#   BUILD_PROVISION_PROFILE_BASE64
# Optional:
#   BUILD_PROVISION_PROFILE_TUNNEL_BASE64

CERTIFICATE_PATH="${RUNNER_TEMP:-/tmp}/certificate.p12"
KEYCHAIN_PATH="${RUNNER_TEMP:-/tmp}/build.keychain-db"
KEYCHAIN_PASSWORD="${KEYCHAIN_PASSWORD:-}"
PROFILES_DIR="${HOME}/Library/MobileDevice/Provisioning Profiles"

append_env() {
  local key="$1"
  local value="$2"
  echo "${key}=${value}"
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    {
      echo "${key}<<EOF"
      echo "${value}"
      echo "EOF"
    } >> "${GITHUB_ENV}"
  fi
}

echo -n "${BUILD_CERTIFICATE_BASE64}" | base64 --decode > "${CERTIFICATE_PATH}"

security delete-keychain "${KEYCHAIN_PATH}" >/dev/null 2>&1 || true
security create-keychain -p "${KEYCHAIN_PASSWORD}" "${KEYCHAIN_PATH}"
security set-keychain-settings -lut 21600 "${KEYCHAIN_PATH}"
security unlock-keychain -p "${KEYCHAIN_PASSWORD}" "${KEYCHAIN_PATH}"
security import "${CERTIFICATE_PATH}" \
  -P "${P12_PASSWORD}" \
  -A \
  -t cert \
  -f pkcs12 \
  -k "${KEYCHAIN_PATH}"

security list-keychain -d user -s "${KEYCHAIN_PATH}" $(security list-keychain -d user | tr -d '"')
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "${KEYCHAIN_PASSWORD}" "${KEYCHAIN_PATH}"

mkdir -p "${PROFILES_DIR}"

install_profile() {
  local b64="$1"
  local label="$2"
  local pp_path="${RUNNER_TEMP:-/tmp}/${label}.mobileprovision"

  echo -n "${b64}" | base64 --decode > "${pp_path}"

  local plist
  plist="$(mktemp)"
  security cms -D -i "${pp_path}" > "${plist}"

  local uuid name team_id bundle_id
  uuid="$(/usr/libexec/PlistBuddy -c 'Print :UUID' "${plist}")"
  name="$(/usr/libexec/PlistBuddy -c 'Print :Name' "${plist}")"
  team_id="$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "${plist}")"
  bundle_id="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:application-identifier' "${plist}" | sed 's/^[^.]*\.//')"

  cp "${pp_path}" "${PROFILES_DIR}/${uuid}.mobileprovision"
  echo "Installed ${label} profile: name='${name}' uuid='${uuid}' bundle_id='${bundle_id}' team='${team_id}'"

  case "${label}" in
    app)
      append_env "APP_PROFILE_UUID" "${uuid}"
      append_env "APP_PROFILE_NAME" "${name}"
      append_env "IOS_TEAM_ID" "${team_id}"
      append_env "APP_PROFILE_BUNDLE_ID" "${bundle_id}"
      ;;
    tunnel)
      append_env "TUNNEL_PROFILE_UUID" "${uuid}"
      append_env "TUNNEL_PROFILE_NAME" "${name}"
      append_env "TUNNEL_PROFILE_BUNDLE_ID" "${bundle_id}"
      ;;
  esac

  rm -f "${plist}"
}

install_profile "${BUILD_PROVISION_PROFILE_BASE64}" "app"

if [[ -z "${BUILD_PROVISION_PROFILE_TUNNEL_BASE64:-}" ]]; then
  echo "ERROR: BUILD_PROVISION_PROFILE_TUNNEL_BASE64 is required for ru.altatec.sstp-client.tunnel" >&2
  exit 1
fi
install_profile "${BUILD_PROVISION_PROFILE_TUNNEL_BASE64}" "tunnel"

IDENTITY="$(security find-identity -v -p codesigning "${KEYCHAIN_PATH}" | awk -F'\"' '/Apple Distribution|iPhone Distribution/{print $2; exit}')"
if [[ -z "${IDENTITY}" ]]; then
  IDENTITY="$(security find-identity -v -p codesigning "${KEYCHAIN_PATH}" | awk -F'\"' '/\"/{print $2; exit}')"
fi
if [[ -z "${IDENTITY}" ]]; then
  echo "ERROR: No code signing identity found in keychain" >&2
  security find-identity -v -p codesigning "${KEYCHAIN_PATH}" || true
  exit 1
fi

append_env "CODE_SIGN_IDENTITY" "${IDENTITY}"
echo "Resolved CODE_SIGN_IDENTITY=${IDENTITY}"
