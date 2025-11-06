#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="$REPO_ROOT/target"

JAR_OLD="$TARGET_DIR/OneScan-v2.2.0.jar"
JAR_NEW="$TARGET_DIR/OneScan-v2.3.0.jar"

echo "[compat] Checking JAR presence..."
if [[ ! -f "$JAR_OLD" ]]; then
  echo "[compat] Missing old jar: $JAR_OLD" >&2
  exit 1
fi
if [[ ! -f "$JAR_NEW" ]]; then
  echo "[compat] Missing new jar: $JAR_NEW" >&2
  exit 1
fi

echo "[compat] Counting classes/resources..."
COUNT_OLD=$(jar tf "$JAR_OLD" | wc -l | tr -d ' ')
COUNT_NEW=$(jar tf "$JAR_NEW" | wc -l | tr -d ' ')
echo "[compat] Entries old: $COUNT_OLD"
echo "[compat] Entries new: $COUNT_NEW"

echo "[compat] Checking key packages..."
for pkg in "burp/api/montoya" "burp/onescan" "burp/common"; do
  HAS_OLD=$(jar tf "$JAR_OLD" | grep -q "$pkg" && echo yes || echo no)
  HAS_NEW=$(jar tf "$JAR_NEW" | grep -q "$pkg" && echo yes || echo no)
  echo "[compat] $pkg → old:$HAS_OLD new:$HAS_NEW"
done

echo "[compat] Extracting manifest versions..."
VER_OLD=$(jar xf "$JAR_OLD" META-INF/MANIFEST.MF && grep -E "^Implementation-Version:" META-INF/MANIFEST.MF | awk -F': ' '{print $2}' || true)
rm -f META-INF/MANIFEST.MF
VER_NEW=$(jar xf "$JAR_NEW" META-INF/MANIFEST.MF && grep -E "^Implementation-Version:" META-INF/MANIFEST.MF | awk -F': ' '{print $2}' || true)
rm -f META-INF/MANIFEST.MF
echo "[compat] Manifest old version: ${VER_OLD:-unknown}"
echo "[compat] Manifest new version: ${VER_NEW:-unknown}"

echo "[compat] Summary:"
if [[ "$COUNT_NEW" -ge "$COUNT_OLD" ]]; then
  echo "[compat] New jar contains >= entries than old (likely OK)."
else
  echo "[compat] New jar contains fewer entries than old (review differences)."
fi

echo "[compat] Checking for legacy API imports in source (advisory) ..."
LEGACY_COUNT=$(grep -R "\bI(Burp|Http|Proxy|ContextMenuFactory|MessageEditor|RequestInfo|ResponseInfo)" -n "$REPO_ROOT/src/main/java" | wc -l | tr -d ' ' || true)
echo "[compat] Legacy API references in source: $LEGACY_COUNT (some remain for interop)"

echo "[compat] Done."
