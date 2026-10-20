#!/usr/bin/env bash
# 端到端验收：重启后【完全不碰手机】，看 App 能否自己把 root 抢回来。
#
# 用法：tools/e2e.sh [设备序列号]
#   不传序列号就取 adb 里的第一台。全程只读日志，直到出现 "=== 完成 ===" 或超时。
#
# 注意：这个脚本会重启手机。
set -u

for p in "${ANDROID_SDK:-}" "${ANDROID_HOME:-}" \
         "$HOME/AppData/Local/Android/Sdk" \
         "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
  [ -n "${p:-}" ] && [ -d "$p/platform-tools" ] && PATH="$p/platform-tools:$PATH"
done
export PATH

command -v adb >/dev/null 2>&1 || { echo "!! 找不到 adb"; exit 1; }

ADB="adb"
[ $# -ge 1 ] && ADB="adb -s $1"

echo "=== reboot $(date +%H:%M:%S) ==="
$ADB reboot
sleep 8

deadline=$(( $(date +%s) + 540 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  # soft-reboot 会打断 logcat 连接，所以外面套一层重连
  timeout 120 adb wait-for-device >/dev/null 2>&1 || continue
  $ADB logcat -s rootmys23:I 2>/dev/null | while IFS= read -r line; do
    printf '%s\n' "$line"
    case "$line" in
      *"=== 完成 ==="*)
        echo "=== OK $(date +%H:%M:%S) ==="
        exit 0
        ;;
    esac
  done
  sleep 2
done

echo "=== TIMEOUT $(date +%H:%M:%S) ==="
