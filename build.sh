#!/usr/bin/env bash
# 手工打 APK：aapt2 -> javac -> d8 -> zipalign -> apksigner
#
# 不依赖 Gradle、不联网。只需要 JDK 8+ 和 Android SDK（build-tools + platform）。
# 之所以不用 Gradle：整个 app 就 5 个 java 文件，起一个 Gradle 工程反而更重。
set -eu

# 调用方若设了 MSYS_NO_PATHCONV，会把 -I 的路径原样传给 aapt2.exe 导致打不开
unset MSYS_NO_PATHCONV 2>/dev/null || true

cd "$(dirname "$0")"

# ---------------------------------------------------------------- 环境探测

PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  for c in python3 python; do
    command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }
  done
fi
[ -n "$PY" ] || { echo "!! 需要 python3（第 1 步要生成 sizes.txt）"; exit 1; }

# Windows 下 build-tools 里的可执行文件带后缀
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) EXE=".exe"; D8="d8.bat"; SIGNER="apksigner.bat" ;;
  *)                    EXE="";     D8="d8";     SIGNER="apksigner" ;;
esac

find_sdk() {
  for p in "${ANDROID_SDK:-}" "${ANDROID_HOME:-}" \
           "$HOME/AppData/Local/Android/Sdk" \
           "$HOME/Library/Android/sdk" \
           "$HOME/Android/Sdk"; do
    if [ -n "${p:-}" ] && [ -d "$p/build-tools" ]; then echo "$p"; return 0; fi
  done
  return 1
}
SDK="$(find_sdk)" || { echo "!! 找不到 Android SDK，请设置 ANDROID_SDK"; exit 1; }

# build-tools 取版本号最高的那个
BT="$(ls -d "$SDK"/build-tools/*/ 2>/dev/null | sed 's:/*$::' | sort -V | tail -1)"
[ -n "${BT:-}" ] || { echo "!! $SDK/build-tools 下没有可用版本"; exit 1; }

# platform jar：优先 android-35（资源编译用），没有就取最高的
PLAT=""
for v in 35 36 34; do
  if [ -f "$SDK/platforms/android-$v/android.jar" ]; then
    PLAT="$SDK/platforms/android-$v/android.jar"; break
  fi
done
if [ -z "$PLAT" ]; then
  PLAT="$(ls -d "$SDK"/platforms/android-*/android.jar 2>/dev/null | sort -V | tail -1)"
fi
[ -n "${PLAT:-}" ] && [ -f "$PLAT" ] || { echo "!! 找不到 android.jar，请装一个 platform"; exit 1; }

OUT=build
MIN_SDK=26
TARGET_SDK=34
# 签名密钥不进仓库；不存在就用下面这个口令本地生成一个。
KS="${KS:-keystore/rootmys23.keystore}"
KS_PASS="${KS_PASS:-rootmys23}"

echo "  SDK   $SDK"
echo "  bt    $(basename "$BT")"
echo "  plat  $(basename "$(dirname "$PLAT")")"

rm -rf "$OUT"
mkdir -p "$OUT/res" "$OUT/gen" "$OUT/classes" "$OUT/dex"

echo "[1/6] 生成 sizes.txt"
"$PY" - <<'PY'
import os, sys
base = 'assets/payload'
names = ['root.sh', 'cve-2026-43499-root', 'rmg-app.so', 'ksud-dm2q', 'kernelsu-dm2q.ko']
# 设备端是 mksh：脚本里混进一个 CR 就会变成 `set -u\r` 这种
# `set: -: unknown option` 的鬼报错，而 Git Bash 的 sh -n 会静默吞掉 CR ——
# 本地检查全绿、上机即死。所以文本 payload 一律在这里强制转 LF。
for n in ('root.sh',):
    p = os.path.join(base, n)
    d = open(p, 'rb').read()
    if b'\r' in d:
        open(p, 'wb').write(d.replace(b'\r\n', b'\n'))
        print("   !! %s 原来是 CRLF，已转成 LF" % n)
    d = open(p, 'rb').read()
    if b'\r' in d:
        sys.exit("   !! %s 仍有 CR，拒绝打包" % n)
lines = ["%s %d" % (n, os.path.getsize(os.path.join(base, n))) for n in names]
open(os.path.join(base, 'sizes.txt'), 'w').write("\n".join(lines) + "\n")
print("   " + "  ".join("%s=%d" % (n, os.path.getsize(os.path.join(base, n))) for n in names))
PY

echo "[2/6] aapt2 compile"
"$BT/aapt2$EXE" compile --dir res -o "$OUT/res.zip"

echo "[3/6] aapt2 link"
"$BT/aapt2$EXE" link \
  -o "$OUT/base.apk" \
  -I "$PLAT" \
  --manifest AndroidManifest.xml \
  -R "$OUT/res.zip" \
  --java "$OUT/gen" \
  -A assets \
  --min-sdk-version "$MIN_SDK" \
  --target-sdk-version "$TARGET_SDK" \
  --auto-add-overlay

echo "[4/6] javac"
SRCS=$(find src "$OUT/gen" -name '*.java' | tr '\n' ' ')
# 别用 `| grep -v … || true` 过滤告警：那样 javac 真失败也会被吞，
# 直到 d8 报几百行缺类才发现。先落盘判返回值，成功后再挑掉噪音。
if ! javac -J-Duser.language=en -J-Duser.country=US \
      -encoding UTF-8 -source 8 -target 8 -nowarn \
      -classpath "$PLAT" -d "$OUT/classes" $SRCS > "$OUT/javac.log" 2>&1; then
  echo "!! javac 失败:"
  cat "$OUT/javac.log"
  exit 1
fi
grep -a -viE "^Note:|bootstrap class path|source value 8|target value 8|deprecat" "$OUT/javac.log" || true

echo "[5/6] d8"
CLASSES=$(find "$OUT/classes" -name '*.class' | tr '\n' ' ')
"$BT/$D8" --min-api "$MIN_SDK" --lib "$PLAT" --output "$OUT/dex" $CLASSES

echo "[5/6] 打包 classes.dex"
"$PY" - "$OUT" <<'PY'
import os, sys, zipfile, shutil
out = sys.argv[1]
base, dex = os.path.join(out, "base.apk"), os.path.join(out, "dex", "classes.dex")
tmp = os.path.join(out, "unsigned.apk")
with zipfile.ZipFile(base) as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
    for it in zin.infolist():
        zout.writestr(it, zin.read(it.filename))
    zout.write(dex, "classes.dex")
shutil.move(tmp, base)
print("   entries:", len(zipfile.ZipFile(base).namelist()))
PY

echo "[6/6] zipalign + sign"
"$BT/zipalign$EXE" -f -p 4 "$OUT/base.apk" "$OUT/aligned.apk"
mkdir -p "$(dirname "$KS")"
if [ ! -f "$KS" ]; then
  echo "   生成签名密钥 $KS（口令来自 KS_PASS，默认 rootmys23）"
  keytool -genkeypair -keystore "$KS" -storepass "$KS_PASS" -keypass "$KS_PASS" \
    -alias rootmys23 -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=root-my-s23, O=self, C=CN" >/dev/null 2>&1
fi
"$BT/$SIGNER" sign --ks "$KS" --ks-pass "pass:$KS_PASS" --key-pass "pass:$KS_PASS" \
  --min-sdk-version "$MIN_SDK" \
  --out "$OUT/root-my-s23.apk" "$OUT/aligned.apk"

ls -l "$OUT/root-my-s23.apk"
echo "OK -> $OUT/root-my-s23.apk"
