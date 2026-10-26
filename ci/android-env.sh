#!/bin/sh
# Print the environment that makes cargo use the Android NDK (preinstalled on
# GitHub's Ubuntu runners as $ANDROID_NDK_LATEST_HOME) for a Rust target.
set -eu
target="$1"
ndk="${ANDROID_NDK_LATEST_HOME:-${ANDROID_NDK_HOME:-}}"
[ -n "$ndk" ] || { echo "Android NDK not found" >&2; exit 1; }
bin="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
api=24
case "$target" in
  aarch64-linux-android) clang="aarch64-linux-android$api-clang" ;;
  x86_64-linux-android) clang="x86_64-linux-android$api-clang" ;;
  armv7-linux-androideabi) clang="armv7a-linux-androideabi$api-clang" ;;
  *) echo "unsupported target $target" >&2; exit 1 ;;
esac
upper="$(echo "$target" | tr 'a-z-' 'A-Z_')"
lower="$(echo "$target" | tr '-' '_')"
echo "CARGO_TARGET_${upper}_LINKER=$bin/$clang"
echo "CC_${lower}=$bin/$clang"
echo "AR_${lower}=$bin/llvm-ar"
