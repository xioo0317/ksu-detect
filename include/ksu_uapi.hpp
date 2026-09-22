// SPDX-License-Identifier: GPL-3.0-or-later
//
// KernelSU userspace API - aligned with uapi/supercall.h from the main repo.
//
// The handshake between KernelSU kernel module and its manager works like this:
//
//   1. Kernel hooks `__NR_reboot` via kprobe (reboot_handler_pre in supercall.c).
//      When userspace calls reboot(MAGIC1=0xDEADBEEF, MAGIC2=0xCAFEBABE, ...),
//      the handler queues a task_work that installs an anonymous inode fd named
//      "[ksu_driver]" into the current process.  This is "installing the driver fd".
//
//   2. The manager (KernelSU app) is UID-whitelisted by the kernel side
//      "throne tracker" - it scans /data/app/*.apk for a signature matching
//      the expected manager certificate, and records the resulting UID.
//      When that UID goes through setresuid (zygote fork), the kernel calls
//      ksu_install_fd() directly in setuid_hook.c - the fd is already there.
//
//   3. On the installed fd, userspace can call ioctl() commands.  Every
//      command has a permission check (see dispatch.c / ksu_ioctl_handlers[]):
//        always_allow  - anyone who has a driver fd can call it
//        manager_or_root - caller must be the manager UID *or* root
//        only_manager  - caller must be the manager UID
//        only_root     - caller must be root
//
//      KSU_IOCTL_GET_INFO is always_allow, but returns KSU_GET_INFO_FLAG_MANAGER
//      in its flags only when the *caller's UID matches the manager app id*.
//      This is the key "manager level" signal.
//
//   4. Legacy (older KernelSU) used prctl(KSU_LEGACY_MAGIC, ...) as the probe,
//      returning the version number directly.  This is kept as a fallback.
//
// To detect at "manager level" we therefore need to:
//   - obtain a ksu_driver fd (reboot magic),
//   - call KSU_IOCTL_GET_INFO,
//   - check the KSU_GET_INFO_FLAG_MANAGER bit.
//   - additionally, use KSU_IOCTL_GET_MANAGER_APPID (manager_or_root) to
//     distinguish "we are root" vs "we are the manager" - if we are root
//     this ioctl succeeds and returns the manager appid, but if we're just
//     a regular app it returns -EPERM.
//

#pragma once

#include <cstdint>
#include <linux/ioctl.h>

namespace ksu {

// --- Magic numbers used for fd installation via the reboot syscall hook ---
constexpr uint32_t INSTALL_MAGIC1 = 0xDEADBEEF;
constexpr uint32_t INSTALL_MAGIC2 = 0xCAFEBABE;

// --- Legacy prctl magic (older KernelSU versions) ---
constexpr uint32_t LEGACY_MAGIC = 0x4B535500u;  // "KSU\0"

// --- Feature / flag bits returned in ksu_get_info_cmd::flags ---
constexpr uint32_t GET_INFO_FLAG_LKM        = (1u << 0);
constexpr uint32_t GET_INFO_FLAG_MANAGER    = (1u << 1);  // set iff caller is the manager UID
constexpr uint32_t GET_INFO_FLAG_LATE_LOAD  = (1u << 2);
constexpr uint32_t GET_INFO_FLAG_PR_BUILD   = (1u << 3);
constexpr uint32_t GET_INFO_FLAG_BUNDLED    = (1u << 4);

// --- UAPI version expected by this detector ---
constexpr uint32_t UAPI_VERSION = 4;

// --- IOCTL command structures ---
struct get_info_cmd {
    uint32_t version;      // output: KERNEL_SU_VERSION
    uint32_t flags;        // output: GET_INFO_FLAG_* bits
    uint32_t features;     // output: max feature ID supported
    uint32_t uapi_version; // output: UAPI version
};

struct get_manager_appid_cmd {
    uint32_t appid;        // output: manager app id (UID % 100000)
};

// --- IOCTL command opcodes ---
constexpr uint32_t IOCTL_GRANT_ROOT       = _IOC(_IOC_NONE, 'K', 1, 0);
constexpr uint32_t IOCTL_GET_INFO         = _IOR('K', 2, struct get_info_cmd);
constexpr uint32_t IOCTL_GET_INFO_LEGACY  = _IOC(_IOC_READ, 'K', 2, 0);
constexpr uint32_t IOCTL_REPORT_EVENT     = _IOC(_IOC_WRITE, 'K', 3, 0);
constexpr uint32_t IOCTL_SET_SEPOLICY     = _IOC(_IOC_READ | _IOC_WRITE, 'K', 4, 0);
constexpr uint32_t IOCTL_CHECK_SAFEMODE   = _IOC(_IOC_READ, 'K', 5, 0);
constexpr uint32_t IOCTL_GET_MANAGER_APPID = _IOC(_IOC_READ, 'K', 10, 0);

// --- Permission classes (for documentation / detection strategy) ---
enum class PermClass {
    AlwaysAllow,
    ManagerOrRoot,
    OnlyManager,
    OnlyRoot,
};

} // namespace ksu
