# ksu-detect-cpp

Manager-level kernel root detector for **KernelSU** and **APatch / KernelPatch**,
rewritten in C++ from [xioo0317/ksu-detect](https://github.com/xioo0317/ksu-detect).

This tool performs **real manager-level handshake** with the kernel — not just
a trivial "hello" probe.  It replicates the exact protocol each official
manager client uses to talk to its kernel module, and reports the actual
privilege level obtained.

## Why "manager-level"?

Both KernelSU and APatch have layered permission models.  A simple `hello`
probe only tells you "the kernel module is present".  A proper manager must
prove its identity to the kernel to access privileged operations.

### KernelSU

| Privilege | How to get it | What you can do |
|-----------|---------------|-----------------|
| User (fd holder) | Call `reboot(DEADBEEF, CAFEBABE, …)` magic | `GET_INFO` (always_allow), see basic version/flags |
| Manager-or-Root | Be `uid == 0` **or** be the manager app's UID | `GET_MANAGER_APPID`, allow list, features, mark, etc. |
| Manager (UID match) | Your UID equals the manager appid tracked by throne_tracker | `GET_APP_PROFILE` (only_manager), and `GET_INFO` returns `MANAGER` flag |
| Root | uid 0 | Everything, including `GRANT_ROOT`, `REPORT_EVENT`, `SET_SEPOLICY` |

The **manager identity** is established by the kernel scanning `/data/app/*.apk`
at boot (`throne_tracker.c`), checking APK signatures against the expected
manager certificate (`apk_sign.c`), and recording the resulting UID.  When the
manager app starts, `setresuid` hook in the kernel auto-installs the driver
fd with manager privilege.

### APatch / KernelPatch

APatch has no UID-based identity system — authentication is purely via a
**superkey** string hashed with a simple `hash_key()` function.

| Privilege | How to get it | What you can do |
|-----------|---------------|-----------------|
| None | - | Nothing; calls fall through to real `truncate()` |
| SU-list | Key is `"su"` and your UID is on the allow list | `SU`, version queries, su list, etc. — same as `kp` binary |
| Superkey | Real superkey matches stored key | Everything: SKEY_GET/SET, KPM load/unload, su grant/revoke, etc. |

## Detection Strategy

### KernelSU detection

1. **Install driver fd** via reboot syscall magic (0xDEADBEEF / 0xCAFEBABE)
2. **`KSU_IOCTL_GET_INFO`** — reads version, flags, features, UAPI version
   - If `KSU_GET_INFO_FLAG_MANAGER` is set → **we ARE the manager UID**
3. **`KSU_IOCTL_GET_MANAGER_APPID`** — if it succeeds → we have at least
   manager_or_root privilege; returns the manager's appid
4. **Legacy fallback** — `prctl(0x4B535500, …)` for old KernelSU versions

### APatch detection

1. Try the provided superkey (or read from `/data/adb/ap/superkey`)
2. **`SUPERCALL_HELLO`** — if returns `0x11581158` → kernel is present
3. **`SUPERCALL_SKEY_GET`** — if succeeds → **we have the real superkey**
   (manager level); if fails but hello works → we're on the su allow list
4. Query **KP version**, **kernel version**, **su UID count**, **KPM count**,
   **safemode state** for full diagnosis
5. If no key provided, try `"su"` as key (works when caller is allowed uid)

## Building

### Android (NDK)

```bash
# arm64-v8a (default)
make NDK_HOME=/path/to/android-ndk

# specific ABI
make NDK_HOME=/path/to/android-ndk ABI=armeabi-v7a
make NDK_HOME=/path/to/android-ndk ABI=x86_64

# all ABIs
make all-abis NDK_HOME=/path/to/android-ndk
```

### Linux host (for testing)

```bash
make host
# or with CMake
make host-cmake
```

## Usage

```bash
# Basic detection
ksu-detect-cpp

# With APatch superkey for full manager-level verification
ksu-detect-cpp -k your-superkey-here

# JSON output (for scripting)
ksu-detect-cpp -j

# Verbose output
ksu-detect-cpp -v

# Superkey via environment
AP_SUPERKEY=your-key ksu-detect-cpp
```

## Output example

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

=== Summary ===
  Detected    : kernelsu
```

## Architecture

```
include/
  ksu_uapi.hpp       — KernelSU UAPI constants (ioctl cmds, structs, flags)
  apatch_uapi.hpp    — APatch supercall definitions (cmd codes, structures)
  detector.hpp       — public Detector class interface

src/
  detector.cpp       — Core detection logic (handshake + privilege verification)
  main.cpp           — CLI entry point (human + JSON output)
```

## Notes on safety

- The reboot magic is non-destructive: the kprobe pre-handler only installs
  an anonymous inode fd when the magic matches; the actual reboot syscall
  never executes (it returns -EINVAL or whatever the magic dictates).
- SIGSYS is handled gracefully for environments where seccomp blocks reboot.
- APatch supercalls that aren't recognized by the kernel fall through to the
  real `truncate()` syscall, which harmlessly returns -EFAULT/-EINVAL.
- No state is modified; all probes are read-only.

## License

GPL-3.0-or-later — same as the original ksu-detect and the KernelSU / APatch
projects this tool interoperates with.
