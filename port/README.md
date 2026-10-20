# 参考移植：`dm1q` / SM-S9110 / `S9110ZHS8FZI1`

这套 profile **不在上游仓库里**——上游 [`Root-My-Galaxy-Payloads`](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads) 没有这个固件。它是本项目自己移植的，`assets/payload/` 里那两个二进制就是从这份源码编出来的。

放在这里有两个目的：让本 APK 可复现；给「其他 S23 怎么自己做」一个能逐行对照的完整样例。

## 怎么用

```bash
git clone https://github.com/BuSung-dev/Root-My-Galaxy-Payloads.git rmg
cd rmg
git apply /path/to/root-my-s23/patches/upstream-late-load.patch

# 把本目录整个放进 target 树
cp -r /path/to/root-my-s23/port/dm1q-S9110ZHS8FZI1 src/targets/

make TARGET=dm1q-S9110ZHS8FZI1 ANDROID_NDK_HOME=/path/to/ndk all
```

`target.h` 里的 `P0_FINGERPRINT_HEADER` 写的是 `targets/dm1q-S9110ZHS8FZI1/p0_fingerprint.h`，对应 `Makefile` 的 `-Isrc`，目录名不能改。

给别的固件移植时：复制本目录 → 改名 → 按 [主 README](../README.md#其他-s23--其他固件怎么自己做) 第 3、4 步重算里面的常量，**不要复用这里的数值**。

## 身份

| 项 | 值 |
| --- | --- |
| 型号 | SM-S9110（`dm1q`，SM8550） |
| 固件 | `S9110ZHS8FZI1`，CSC TGY，Android 16，SPL 2026-09-05 |
| 指纹 | `samsung/dm1qzhx/dm1q:16/BP4A.251205.006/S9110ZHS8FZI1:user/release-keys` |
| 内核 | `5.15.189-android13-8-33413713-abS9110ZHS8FZI1` |
| `boot.img` md5 | `bce09927a3ed874970f0d54eec19ab02` |
| raw `Image` sha256 | `255B57E18CF7DE475FB2D589ADFBD628D34F080163A488598AE1F4F051F9D627` |
| raw `Image` 大小 | 46860800 B（`0x2CB0A00`），`text_offset 0x0`，`image_size 0x2f50000`，`flags 0xa` |
| `vmlinux.elf` | 126224 个 kallsyms 符号，`_text = 0xffffffc008000000` |
| BTF blob | `[0x021ef2ac, 0x027bf256)`，6094762 B，139558 个类型 |

## 关键常量从哪来

| 常量 | 值 | 依据 |
| --- | --- | --- |
| `SLIDE_TRACEFS_EVENT_ID` | `108` | `enum trace_type __TRACE_LAST_TYPE = 20`；`__event_sched_blocked_reason` 在 `__start_ftrace_events` 之后第 88 项 |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | `0x0010db44` | `worker_thread` 里 `bl schedule` 的返回地址 |
| `SLIDE_TRACEFS_VFORK_CALLER_OFF` | `0x000c8fe4` | `wait_for_vfork_done` 里 `bl wait_for_common` 的返回地址 |
| `SKB_DATA_DELTA` / `SKB_SEND_SIZE` | `-0xe80` / `0x8e80` | BTF 的 `sk_buff` 布局 |
| `MM_STRUCT_SZ` | `0x400` | BTF `sizeof(mm_struct)=0x3e0`，`SLAB_HWCACHE_ALIGN` 后是 `0x400` |
| `MM_ORDER` | `3` | 要凑 32 个对象进一个 order-3 页组 |
| `COMPACT_RT_MUTEX_WAITER` | `1` | 三星 5.15 回移了 `prio`/`deadline`，`rt_mutex_waiter` 是 `0x58` 而不是老版 `0x40` |
| `KERNELSNITCH_THRESHOLD_MULT` | `8` | 默认 10 实测在 `only found 0 collisions` 死掉；计时诊断显示 2048 futex 的峰值只有基线的 ~8.5 倍 |
| `SLIDE_KSNITCH_APPENDED_FUTEXES` | `4096` | 加倍链长，信号更干净 |
| `P0_ORACLE_PROBE_OFFSET` | `0x1f8000` | 见下 |
| `P0_KERNEL_PHYS_LOAD` | `0x80080000` | 与 `SM-S911U1` 同平台，那边是硬件验证过的 |
| `SLIDE_P0_OFFSET_CANDIDATES` | 64 项，`0 .. 0x1f8000` | 步进 `0x8000`，不是 `0x10000` |

## 两个容易踩的点

**1. KASLR 粒度是 `0x8000`，不是 `0x10000`。** 实测 slide 有 `0x090000`、`0x0e0000`、`0x010000`、`0x150000`。上游 `tools/generate_p0_fingerprint.pl` 默认按 `0x10000` 生成 32 行，在 dm1q 上会让奇数 `0x?8000` 的 slide 全部落空。必须改成：

```perl
for my $slide (map { $_ * 0x8000 } 0 .. 63) {
```

本目录的 `p0_fingerprint.h` 就是 64 行版本。

**2. `--ephemeral` 不是所有 `ksud` 都认。** 上游 `su_daemon.c` 在 late-load 时固定传 `--ephemeral`，dm1q/dm2q/dm3q 的 kdp 构建会把它当成未知参数直接退出。`patches/upstream-late-load.patch` 把它改成编译期开关，并让 `KSU_LOADER_PATH` 可按 target 覆盖（本 target 指向 `/data/local/tmp/ksud-dm2q`）。不应用这个补丁，`late` 阶段必然失败。

## 产物

| 文件 | 大小 | 去处 |
| --- | --- | --- |
| `build/dm1q-S9110ZHS8FZI1/cve-2026-43499-root` | 27232 | `assets/payload/cve-2026-43499-root` |
| `build/dm1q-S9110ZHS8FZI1/cve-2026-43499-app.so` | 135544 | `assets/payload/rmg-app.so` |

`ksud-dm2q` / `kernelsu-dm2q.ko` 与 target 无关，来自上游 `kernelsu/android13-5.15.189_*dm2q*`。

## 验证边界

- **tracefs 路线**：真机验证过，5 个独立 boot 全部命中，slide 各不相同；另有 2 次失败集中在同一个 boot（slide `0x188000`）。
- **物理 P0 oracle**：这张表从 raw `Image` 逐字节核对过 512 个 qword，但真机上五次全走的 tracefs，**这条 fallback 没在硅片上跑过**。tracefs 失手时它是否可靠，没有证据。
- **内核模块**：用的是 `dm2q-S916BXXSAFZG1` 的构建，`vermagic` 里的 localversion 不同，靠 late-load 的手工装载绕过。同内核 build `33413713` 成立；换 build 就得换 ko。
- **ARM64 Image 的 `flags = 0xa`**：`text_offset` 为 0 时不代表加载地址是 0，`P0_KERNEL_PHYS_LOAD` 仍是 `0x80080000`。
