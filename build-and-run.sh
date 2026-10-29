#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_FILE="$SCRIPT_DIR/UltimateNetGuard.pro"
APP_FILE="$SCRIPT_DIR/bin/UltimateNetGuard.exe"

if [[ -n "${QT_ROOT:-}" ]]; then
    QT_CANDIDATES=("$QT_ROOT")
else
    QT_CANDIDATES=(
        "/c/Qt/6.11.1/mingw_64"
    )
fi

QMAKE=""
MAKE=""
for qt_root in "${QT_CANDIDATES[@]}" /c/Qt/*/mingw_64; do
    for candidate in "$qt_root"/bin/qmake.exe; do
        if [[ -f "$candidate" ]]; then
            QMAKE="$candidate"
            break
        fi
    done
    [[ -n "$QMAKE" ]] && break
done

if [[ -n "$QMAKE" ]]; then
    for toolchain_bin in /c/Qt/Tools/mingw1310_64/bin /c/Qt/Tools/mingw1120_64/bin /c/Qt/Tools/*/bin; do
        if [[ -f "$toolchain_bin/mingw32-make.exe" ]]; then
            MAKE="$toolchain_bin/mingw32-make.exe"
            break
        fi
    done
fi

if [[ -z "$QMAKE" || ! -f "$MAKE" ]]; then
    echo "Qt MinGW was not found. Install the Qt 6 MinGW 64-bit kit, or set QT_ROOT." >&2
    echo "Example: QT_ROOT=/c/Qt/6.11.1/mingw_64 bash build-and-run.sh" >&2
    exit 1
fi

export PATH="$(dirname "$MAKE"):$(dirname "$QMAKE"):$PATH"
cd "$SCRIPT_DIR"

echo "Using Qt: $(dirname "$(dirname "$QMAKE")")"
echo "Generating release Makefile..."
"$QMAKE" "$PROJECT_FILE" CONFIG+=release

if command -v nproc >/dev/null 2>&1; then
    JOBS="$(nproc)"
else
    JOBS="${NUMBER_OF_PROCESSORS:-4}"
fi

echo "Building with $JOBS parallel jobs..."
"$MAKE" -j"$JOBS"

if [[ ! -f "$APP_FILE" ]]; then
    echo "Build completed, but $APP_FILE was not created." >&2
    exit 1
fi

echo "Launching Ultimate NetGuard as administrator..."
if command -v cygpath >/dev/null 2>&1; then
    APP_WINDOWS_PATH="$(cygpath -w "$APP_FILE")"
else
    APP_WINDOWS_PATH="$APP_FILE"
fi

powershell.exe -NoProfile -Command "Start-Process -FilePath '$APP_WINDOWS_PATH' -Verb RunAs"
echo "Done."