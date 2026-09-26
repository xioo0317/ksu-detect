// SPDX-License-Identifier: GPL-3.0-or-later
//
// susfs_uapi.hpp — SusFS kernel module UAPI constants.
//
// SusFS exposes a private control interface by hooking standard Linux
// syscalls. Two ABIs exist:
//
//   * prctl era (susfs v1.5.2 - v1.5.12):
//       prctl(0xDEADBEEF /*option*/, cmd, arg, NULL, &error);
//       error == 0  -> command executed
//       error == -1 -> command unsupported
//
//   * reboot syscall era (susfs v2.0.0+):
//       syscall(SYS_reboot, 0xDEADBEEF, 0xFAFAFAFA, cmd, info);
//       info->err == 0   -> command executed
//       info->err == 255 -> command unsupported
//
// SusFS presence is confirmed ONLY when the kernel actually executes
// SHOW_VERSION and the error field comes back 0. There is no fallback:
// if neither ABI answers, SusFS is reported as absent.

#pragma once

#include <cstdint>
#include <cstddef>

namespace susfs {

// prctl option magic / reboot first magic (shared with the KernelSU hook).
constexpr unsigned long OPTION_MAGIC  = 0xDEADBEEFUL;

// SusFS-specific reboot second magic. The KernelSU core itself uses
// 0xCAFEBABE; 0xFAFAFAFA routes the reboot call to the SusFS handler.
constexpr unsigned int  REBOOT_MAGIC2 = 0xFAFAFAFAu;

// Command opcodes (identical across all SusFS versions).
constexpr unsigned long CMD_SHOW_VERSION          = 0x555e1UL;
constexpr unsigned long CMD_SHOW_ENABLED_FEATURES = 0x555e2UL;

// reboot ABI error sentinel for "command not supported".
constexpr int ERR_CMD_NOT_SUPPORTED = 255;

// prctl ABI error value for "command not supported".
constexpr int PRCTL_ERR_UNSUPPORTED = -1;

constexpr size_t VERSION_STR_LEN = 16;

// reboot ABI (v2.0.0+) SHOW_VERSION response. The kernel appends an err
// field to every userspace structure it fills in.
struct version_cmd {
    char susfs_version[VERSION_STR_LEN];
    int  err;
};

} // namespace susfs
