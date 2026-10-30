#!/usr/bin/env bash
# Build a private, command-line ngspice installation on macOS/Linux.
set -euo pipefail
export LC_ALL=C
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NGSPICE_VERSION=47
BUILD_ROOT="$PROJECT_ROOT/tmp/build"
INSTALL_ROOT="$PROJECT_ROOT/.tools/ngspice"
ARCHIVE="$BUILD_ROOT/ngspice-${NGSPICE_VERSION}.tar.gz"
SOURCE_URL="https://downloads.sourceforge.net/project/ngspice/ng-spice-rework/${NGSPICE_VERSION}/ngspice-${NGSPICE_VERSION}.tar.gz"
mkdir -p "$BUILD_ROOT" "$INSTALL_ROOT" "$PROJECT_ROOT/results/environment"
if [[ ! -f "$ARCHIVE" ]] || ! tar -tzf "$ARCHIVE" >/dev/null 2>&1; then
  curl -L --fail --retry 3 --max-time 600 "$SOURCE_URL" -o "$ARCHIVE"
fi
EXPECTED_SHA256=894e649651f1838a14095e5a5439e7d3aa63e87ede14d283173fda4fcdef675f
if command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA256="$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')"
else
  ACTUAL_SHA256="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
fi
[[ "$ACTUAL_SHA256" == "$EXPECTED_SHA256" ]] || { printf 'Unexpected source checksum\n' >&2; exit 1; }
# libtool cannot build in a source path containing spaces (the project path may).
# Compile in a temporary directory; install all runtime files in the project.
COMPILE_ROOT="${NGSPICE_COMPILE_ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/a2-ngspice.XXXXXX")}"
tar -xzf "$ARCHIVE" -C "$COMPILE_ROOT"
cd "$COMPILE_ROOT/ngspice-${NGSPICE_VERSION}"
mkdir -p build-local
cd build-local
../configure --prefix="$INSTALL_ROOT" --without-x --with-readline=no --disable-debug --disable-openmp --disable-cider --disable-osdi > "$PROJECT_ROOT/results/environment/ngspice_configure.log" 2>&1
make -j4 > "$PROJECT_ROOT/results/environment/ngspice_build.log" 2>&1
# Automake/libtool's install recipes also mishandle spaces in the prefix.
# Override only the install prefix, then relocate to the configured runtime path.
STAGE_ROOT="$COMPILE_ROOT/stage"
make install prefix="$STAGE_ROOT" > "$PROJECT_ROOT/results/environment/ngspice_install.log" 2>&1
cp -R "$STAGE_ROOT/." "$INSTALL_ROOT/"
"$INSTALL_ROOT/bin/ngspice" --version > "$PROJECT_ROOT/results/environment/ngspice_version.txt"
printf 'Installed ngspice: %s\n' "$INSTALL_ROOT/bin/ngspice"
