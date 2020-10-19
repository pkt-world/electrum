#!/bin/bash

# This script was tested on Linux and MacOS hosts, where it can be used
# to build native libsecp256k1 binaries.
#
# You must have rustc/cargo, which you can install using rustup.
# curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
#
# It can also be used to cross-compile to Windows:
# For a Windows x86 (32-bit) target, run:
# $ rustup target add i686-pc-windows-gnu
# $ sudo apt-get install mingw-w64
# $ GCC_TRIPLET_HOST="i686-w64-mingw32" ./contrib/make_libsecp256k1.sh
#
# Or for a Windows x86_64 (64-bit) target, run:
# $ rustup target add x86_64-pc-windows-gnu
# $ sudo apt-get install mingw-w64
# $ GCC_TRIPLET_HOST="x86_64-w64-mingw32" ./contrib/make_libsecp256k1.sh

PACKETCRYPT_VERSION="9981a85a4eaaa781286087e6bcea494b502635ad"

set -e

. $(dirname "$0")/build_tools_util.sh || (echo "Could not source build_tools_util.sh" && exit 1)

here=$(dirname $(realpath "$0" 2> /dev/null || grealpath "$0"))
CONTRIB="$here"
PROJECT_ROOT="$CONTRIB/.."

pkgname="packetcrypt_dll"
info "Building $pkgname..."

if command -v cargo ; then
    CARGO=$(command -v cargo)
elif [ -f "$HOME/.cargo/bin/cargo" ] ; then
    CARGO="$HOME/.cargo/bin/cargo"
else
    fail "Cargo not found, use rustup to install"
fi

# fixes undefined reference to `__mingwthr_key_dtor'
export CARGO_TARGET_I686_PC_WINDOWS_GNU_RUSTFLAGS='-lgcc_eh -lmingw32'

(
    cd $CONTRIB
    if [ ! -d packetcrypt_rs ]; then
        git clone https://github.com/cjdelisle/packetcrypt_rs.git
    fi
    cd packetcrypt_rs/packetcrypt-dll
    if ! $(git cat-file -e ${PACKETCRYPT_VERSION}) ; then
        info "Could not find requested version $PACKETCRYPT_VERSION in local clone; fetching..."
        git fetch --all
    fi
    git reset --hard
    git clean -f -x -q
    git checkout "${PACKETCRYPT_VERSION}^{commit}"

    if [ "$GCC_TRIPLET_HOST" = "i686-w64-mingw32" ] ; then
        $CARGO build --release --target i686-pc-windows-gnu
        cp -fpv "./target/i686-pc-windows-gnu/release/packetcrypt_dll.dll" "$PROJECT_ROOT/electrum" || fail "Could not copy the $pkgname binary to its destination"
    elif [ "$GCC_TRIPLET_HOST" = "x86_64-w64-mingw32" ] ; then
        $CARGO build --release --target i686-pc-windows-gnu
        cp -fpv "./target/x86_64-pc-windows-gnu/release/packetcrypt_dll.dll" "$PROJECT_ROOT/electrum" || fail "Could not copy the $pkgname binary to its destination"
    else
        $CARGO build --release
        cp -fpv "./target/release/libpacketcrypt_dll.so" "$PROJECT_ROOT/electrum" ||
            cp -fpv "./target/release/libpacketcrypt_dll.dylib" "$PROJECT_ROOT/electrum" ||
                fail "Could not copy the $pkgname binary to its destination"
    fi
    info "packetcrypt_dll has been placed in the inner 'electrum' folder."
)
