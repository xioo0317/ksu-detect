# ksu-detect-cpp

Manager-level kernel root detector for **KernelSU**, **APatch / KernelPatch** and
**Magisk**, rewritten in C++ from [xioo0317/ksu-detect](https://github.com/xioo0317/ksu-detect).

This tool performs **real manager-level handshake** — it replicates the exact
protocol each official manager client uses to talk to its daemon / kernel
module, and reports the actual privilege level obtained.  It is not just a
trivial "hello" probe.

---

# ksu-detect-cpp（中文说明）

针对 **KernelSU / APatch(KernelPatch) / Magisk** 的管理器级 Root 检测工具，使用 C++
从 [xioo0317/ksu-detect](https://github.com/xioo0317/ksu-detect) 重写。

本工具执行的是**真实的管理器级握手**，而不是简单的 "hello" 探测：它复刻各官方管理器客户端
与内核模块 / 守护进程通信的完整协议，并报告实际获得的权限层级。

## 为什么是 "manager-level"（管理器级）？

KernelSU 与 APatch 都有分层权限模型。简单的 hello 探测只能说明"内核模块存在"，
而真正的管理器必须向内核证明自己的身份才能访问特权操作。

### KernelSU

| 权限 | 如何获得 | 能做什么 |
|------|----------|----------|
| User（fd 持有者） | 调用 `reboot(DEADBEEF, CAFEBABE, …)` 魔术数 | `GET_INFO`（always_allow），查看基础版本/标志 |
| Manager-or-Root | `uid == 0` 或 是管理器 App 的 UID | `GET_MANAGER_APPID`、allow list、features、mark 等 |
| Manager（UID 匹配） | 你的 UID 等于 throne_tracker 跟踪的管理器 appid | `GET_APP_PROFILE`（仅限管理器），`GET_INFO` 返回 `MANAGER` 标志 |
| Root | uid 0 | 一切，包括 `GRANT_ROOT`、`REPORT_EVENT`、`SET_SEPOLICY` |

**管理器身份**由内核在开机时扫描 `/data/app/*.apk`（`throne_tracker.c`），用期望的管理器
证书校验 APK 签名（`apk_sign.c`），并记录得到的 UID 来建立。当管理器 App 启动时，内核中的
`setresuid` hook 会自动安装带管理器权限的 driver fd。

### APatch / KernelPatch

APatch 没有基于 UID 的身份体系 —— 认证完全依赖一个用简单 `hash_key()` 函数哈希的 **superkey** 字符串。

| 权限 | 如何获得 | 能做什么 |
|------|----------|----------|
| None | - | 无；调用会落到真实的 `truncate()` |
| SU-list | 密钥是 `"su"` 且你的 UID 在 allow list 上 | `SU`、版本查询、su list 等，与 `kp` 二进制相同 |
| Superkey | 真实 superkey 匹配存储的密钥 | 一切：`SKEY_GET/SET`、KPM 加载/卸载、su 授权/撤销等 |

## 检测策略

### KernelSU 检测

1. 通过 reboot syscall 魔术数（0xDEADBEEF / 0xCAFEBABE）安装 driver fd
2. **`KSU_IOCTL_GET_INFO`** — 读取版本、标志、feature、UAPI 版本
   - 若设了 `KSU_GET_INFO_FLAG_MANAGER` → **我们就是管理器 UID**
3. **`KSU_IOCTL_GET_MANAGER_APPID`** — 若成功 → 至少有 manager_or_root 权限；返回管理器 appid
4. **Legacy fallback** — 针对旧版 KernelSU 使用 `prctl(0x4B535500, …)`

### APatch 检测

1. 尝试给定的 superkey（或从 `/data/adb/ap/superkey` 读取）
2. **`SUPERCALL_HELLO`** — 若返回 `0x11581158` → 内核存在
3. **`SUPERCALL_SKEY_GET`** — 若成功 → **我们持有真实 superkey**（管理器级）；失败但 hello 成功 → 在 su allow list 上
4. 查询 **KP version**、**kernel version**、**su UID 数量**、**KPM 数量**、**safemode 状态**以完整诊断
5. 若无密钥，尝试以 `"su"` 作为密钥（当调用者是允许的 uid 时有效）

### Magisk 检测

> 这是从 Magisk 31.0 源码（`native/src/core/daemon.rs`、`lib.rs`）逐行还原的 **root 握手** 检测，
> 是全量检测逻辑中唯一判定 "Magisk 正在运行" 的依据。

Magisk 的 root 是**用户空间守护进程 magiskd** 通过 **Unix socket** 通信，不涉及内核魔术数。

**Socket 路径（文件系统 socket，不是抽象 socket）：**

```
sock_path = get_magisk_tmp() + "/.magisk/device/socket"
# get_magisk_tmp() 返回：
#   /debug_ramdisk  （存在 /debug_ramdisk/.magisk 时）
#   /sbin           （存在 /sbin/.magisk 时）
```

即真实路径为 `/debug_ramdisk/.magisk/device/socket` 或 `/sbin/.magisk/device/socket`。
主路径首选检查这两个位置，若找不到再从 `/proc/net/unix` 扫描任何包含
`.magisk/device/socket` 的文件系统 socket（兼容不同 MAGISKTMP 位置）。

**握手协议（5 步，与官方客户端一致）：**

1. `connect` 到 socket 路径
2. 写入 i32 请求码 `RequestCode`
3. 读取 i32 响应码 `RespondCode`，`OK(0)` 即握手成功
4. `CHECK_VERSION_CODE=2` → 再读 i32 返回 `MAGISK_VER_CODE`（如 31000）
   `CHECK_VERSION=1` → 按 `[int32 len][bytes]` 编码读取版本字符串（如 `31.0:MAGISK:R`）
5. 非 root / 非 zygote / 非 magisk 自身二进制的对端会被 daemon 以 `ACCESS_DENIED` 断开

**注意事项：**
- 检测需以 **root** 身份运行才能通过 magiskd 的对端身份校验（否则会在第 5 步被拒绝）。
- Zygisk、su 二进制、模块列表等只作为**附加线索**展示，**不再作为 "present" 的判定依据**；
  是否检测到 Magisk 只取决于 daemon 握手是否成功。

## 构建

### Android (NDK)

```bash
# arm64-v8a（默认）
make NDK_HOME=/path/to/android-ndk

# 指定 ABI
make NDK_HOME=/path/to/android-ndk ABI=armeabi-v7a
make NDK_HOME=/path/to/android-ndk ABI=x86_64

# 全部 ABI
make all-abis NDK_HOME=/path/to/android-ndk
```

### Linux host（用于测试）

```bash
make host
# 或使用 CMake
make host-cmake
```

## 使用

```bash
# 基础检测
ksu-detect-cpp

# 提供 APatch superkey 做完整管理器级验证
ksu-detect-cpp -k your-superkey-here

# JSON 输出（便于脚本处理）
ksu-detect-cpp -j

# 详细输出
ksu-detect-cpp -v

# 通过环境变量指定 superkey
AP_SUPERKEY=your-key ksu-detect-cpp
```

## 输出示例

```
=== Manager-Level Kernel Root Detection ===

[KernelSU]
  Present     : yes
  Version     : 15000
  UAPI        : 4
  Mode        : lkm
  Flags       : 0x00000003
  Priv level  : manager
  Manager UID : u0_a1234 (appid 1234)
  [✓] MANAGER-LEVEL CONFIRMED: caller matches manager UID

[APatch / KernelPatch]
  Present     : no
  Status      : unconfirmed (no superkey available)
                Use -k <superkey> for kernel-level verification.

[Magisk / Zygisk]
  Present     : yes (daemon running, handshake confirmed)
  Version     : 31.0:MAGISK:R
  Version code: 31000 (31.0)
  Socket      : /debug_ramdisk/.magisk/device/socket
  Priv level  : su
  [✓] SU ACCESS: root shell available

=== Summary ===
  Detected    : magisk
```

## 架构

```
include/
  ksu_uapi.hpp       — KernelSU UAPI 常量（ioctl cmd、struct、flags）
  apatch_uapi.hpp    — APatch supercall 定义（cmd codes、结构体）
  magisk_uapi.hpp    — Magisk 守护进程协议常量（请求/响应码、socket 路径、变体标志）
  detector.hpp       — 公开的 Detector 类接口

src/
  detector.cpp       — 核心检测逻辑（握手 + 权限验证）
  main.cpp           — CLI 入口（人类可读 + JSON 输出）
```

## 安全说明

- reboot 魔术数无破坏性：当魔术数匹配时 kprobe pre-handler 只安装一个匿名 inode fd，
  实际的 reboot syscall 不会执行（会按魔术数返回 -EINVAL 或类似）。
- 在 seccomp 拦截 reboot 的环境中会妥善处理 SIGSYS。
- 内核无法识别的 APatch supercall 会落到真实的 `truncate()` syscall，无害地返回 -EFAULT/-EINVAL。
- 不修改任何状态；所有探测均为只读。

## License

GPL-3.0-or-later —— 与原始 ksu-detect 及该工具互操作的 KernelSU / APatch 项目相同。