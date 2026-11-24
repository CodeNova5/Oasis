#!/usr/bin/env bash
# Builds and launches Oasis with a Qt kit and the MinGW toolchain
# that belong together. Override the automatic selection with QT_ROOT (the Qt
# kit) or MINGW_ROOT (the toolchain root, i.e. the folder containing bin/).
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_FILE="$SCRIPT_DIR/Oasis.pro"
APP_FILE="$SCRIPT_DIR/bin/Oasis.exe"

# ─── Qt kit ─────────────────────────────────────────────────────────────────
# Newest MinGW kit under /c/Qt unless QT_ROOT says otherwise.
find_kit() {
    if [[ -n "${QT_ROOT:-}" ]]; then
        printf '%s\n' "${QT_ROOT%/}"
        return 0
    fi
    local kit
    for kit in /c/Qt/*/mingw_64; do
        [[ -f "$kit/bin/qmake.exe" ]] && printf '%s\n' "$kit"
    done | sort -V | tail -n 1
}

# The GCC version Qt itself was built with. A toolchain with another version
# still compiles but fails at link time (undefined reference to
# __stack_chk_fail), so the toolchain is matched against this rather than
# picked by folder name.
required_gcc_version() {
    local qconfig="$1/mkspecs/qconfig.pri"
    [[ -f "$qconfig" ]] || return 0
    local major minor
    major="$(sed -n 's/^QT_GCC_MAJOR_VERSION *= *\([0-9][0-9]*\).*/\1/p' "$qconfig" | head -n 1)"
    minor="$(sed -n 's/^QT_GCC_MINOR_VERSION *= *\([0-9][0-9]*\).*/\1/p' "$qconfig" | head -n 1)"
    [[ -n "$major" ]] && printf '%s.%s\n' "$major" "${minor:-0}"
}

toolchain_gcc_version() {
    [[ -f "$1/g++.exe" ]] || return 0
    "$1/g++.exe" -dumpversion 2>/dev/null | tr -d '\r'
}

find_toolchain_bin() {
    local kit="$1"
    local required version bin
    required="$(required_gcc_version "$kit")"

    local candidates=()
    if [[ -n "${MINGW_ROOT:-}" ]]; then
        candidates=("${MINGW_ROOT%/}/bin")
    else
        for bin in /c/Qt/Tools/mingw*/bin; do
            [[ -f "$bin/mingw32-make.exe" ]] && candidates+=("$bin")
        done
    fi
    [[ ${#candidates[@]} -gt 0 ]] || return 0

    if [[ -n "$required" ]]; then
        for bin in "${candidates[@]}"; do
            version="$(toolchain_gcc_version "$bin")"
            if [[ -n "$version" && "${version%.*}" == "$required" ]]; then
                printf '%s\n' "$bin"
                return 0
            fi
        done
        echo "Warning: no MinGW with GCC $required was found; Qt was built with it." >&2
    fi

    # Compiler not recorded, or no exact match: take the newest toolchain.
    for bin in "${candidates[@]}"; do
        printf '%s %s\n' "$(toolchain_gcc_version "$bin")" "$bin"
    done | sort -V | tail -n 1 | cut -d' ' -f2-
}

KIT="$(find_kit)"
if [[ -z "$KIT" || ! -f "$KIT/bin/qmake.exe" ]]; then
    echo "Qt for MinGW was not found under ${QT_ROOT:-/c/Qt/*/mingw_64}." >&2
    echo "Install the Qt 6 MinGW 64-bit kit, or point QT_ROOT at it:" >&2
    echo "  QT_ROOT=/c/Qt/6.11.1/mingw_64 bash run.sh" >&2
    exit 1
fi
QMAKE="$KIT/bin/qmake.exe"

TOOLCHAIN_BIN="$(find_toolchain_bin "$KIT")"
if [[ -z "$TOOLCHAIN_BIN" || ! -f "$TOOLCHAIN_BIN/mingw32-make.exe" ]]; then
    echo "No MinGW toolchain was found. Install the one that belongs to $KIT" >&2
    echo "(its bin/qtenv2.bat names it) or set MINGW_ROOT:" >&2
    echo "  MINGW_ROOT=/c/Qt/Tools/mingw1310_64 bash run.sh" >&2
    exit 1
fi

MAKE="$TOOLCHAIN_BIN/mingw32-make.exe"
export PATH="$TOOLCHAIN_BIN:$KIT/bin:$PATH"

QT_VERSION="$("$QMAKE" -query QT_VERSION | tr -d '\r')"
REQUIRED_GCC="$(required_gcc_version "$KIT")"
GCC_VERSION="$(toolchain_gcc_version "$TOOLCHAIN_BIN")"

echo "Using Qt $QT_VERSION: $KIT"
echo "Using MinGW GCC ${GCC_VERSION:-unknown}: $TOOLCHAIN_BIN"

if [[ -n "$REQUIRED_GCC" && -n "$GCC_VERSION" && "${GCC_VERSION%.*}" != "$REQUIRED_GCC" ]]; then
    echo "MinGW GCC $GCC_VERSION does not match GCC $REQUIRED_GCC, which Qt $QT_VERSION was built with." >&2
    echo "Point MINGW_ROOT at a matching toolchain." >&2
    exit 1
fi

cd "$SCRIPT_DIR"

# ─── Data Saver web assets ──────────────────────────────────────────────────
# The Data Saver page is a Preact app bundled by esbuild into
# web/datasaver/dist, which qmake's post-link rule copies to
# bin/web/datasaver/dist. Neither folder is committed, so the bundle has to be
# rebuilt here whenever its sources change; otherwise the app runs the old UI.
# build.mjs also writes bin/web/datasaver/dist directly, so a run that does not
# relink (web-only change) still picks up the new assets.
rebuild_web_assets() {
    local web_dir="$SCRIPT_DIR/web/datasaver"
    local bundle="$web_dir/dist/app.js"

    [[ -f "$web_dir/package.json" ]] || return 0

    local sources=("$web_dir/package.json" "$web_dir/build.mjs" "$web_dir/index.html")
    local source stale=0 found

    if [[ ! -f "$bundle" ]]; then
        stale=1
    else
        for source in "${sources[@]}"; do
            [[ -f "$source" ]] || continue
            if [[ "$source" -nt "$bundle" ]]; then
                stale=1
                break
            fi
        done
        if [[ $stale -eq 0 ]]; then
            found="$(find "$web_dir/src" -type f -newer "$bundle" -print -quit 2>/dev/null || true)"
            [[ -n "$found" ]] && stale=1
        fi
    fi

    [[ $stale -eq 1 ]] || return 0

    if ! command -v npm >/dev/null 2>&1; then
        echo "The Data Saver assets are out of date, but npm was not found on PATH." >&2
        echo "Install Node.js, or rebuild them manually:" >&2
        echo "  cd web/datasaver && npm install && npm run build" >&2
        exit 1
    fi

    if [[ ! -d "$web_dir/node_modules" ]]; then
        echo "Installing Data Saver dependencies..."
        ( cd "$web_dir" && npm install --no-audit --no-fund )
    fi

    echo "Rebuilding Data Saver assets..."
    ( cd "$web_dir" && npm run build )
}

rebuild_web_assets

echo "Generating release Makefile..."
"$QMAKE" "$PROJECT_FILE" CONFIG+=release

if command -v nproc >/dev/null 2>&1; then
    JOBS="$(nproc)"
else
    JOBS="${NUMBER_OF_PROCESSORS:-4}"
fi

BUILD_LOG="$(mktemp)"
echo "Building with $JOBS parallel jobs..."
set +e
"$MAKE" -j"$JOBS" 2>&1 | tee "$BUILD_LOG"
BUILD_STATUS="${PIPESTATUS[0]}"
set -e

if [[ $BUILD_STATUS -ne 0 ]]; then
    if grep -q "__stack_chk_fail" "$BUILD_LOG"; then
        echo
        echo "The link failed because the compiler does not match this Qt build." >&2
        echo "Qt $QT_VERSION uses MinGW GCC ${REQUIRED_GCC:-from its own kit}; set MINGW_ROOT accordingly." >&2
    fi
    rm -f "$BUILD_LOG"
    exit "$BUILD_STATUS"
fi
rm -f "$BUILD_LOG"

if [[ ! -f "$APP_FILE" ]]; then
    echo "Build completed, but $APP_FILE was not created." >&2
    exit 1
fi

echo "Launching Oasis as administrator..."
if command -v cygpath >/dev/null 2>&1; then
    APP_WINDOWS_PATH="$(cygpath -w "$APP_FILE")"
else
    APP_WINDOWS_PATH="$APP_FILE"
fi

powershell.exe -NoProfile -Command "Start-Process -FilePath '$APP_WINDOWS_PATH' -Verb RunAs"
echo "Done."
