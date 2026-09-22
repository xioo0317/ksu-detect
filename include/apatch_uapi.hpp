// SPDX-License-Identifier: GPL-3.0-or-later
//
// APatch / KernelPatch supercall UAPI definitions.
//
// The handshake between KernelPatch (KP) kernel module and APatch manager
// works very differently from KernelSU:
//
//   1. There is NO anonymous inode / fd mechanism.  Everything is done
//      through a raw syscall: syscall(__NR_supercall=45, key, ver_and_cmd, ...)
//      The kernel hooks the `truncate` syscall entry (syscall #45 on all
//      architectures) and intercepts calls that match the 0x1158 magic in
//      bits [31:16] of the second argument.
//
//   2. Authentication is purely via the *superkey* string passed as the
//      first argument.  The kernel-side has a stored superkey; the first
//      argument is hashed with a simple hash_key() function:
//          hash = 1000000007;
//          for each byte: hash = hash * 31 + key[i];
//      If the hash matches the stored key, the call is allowed.
//      Additionally, if the caller's UID is on the "su allowed list"
//      AND the key is exactly the literal string "su", the call is also
//      accepted.  This is how the `kp`/`su` binary gains privilege.
//
//   3. The "hello" probe (SUPERCALL_HELLO=0x1000) returns
//      SUPERCALL_HELLO_MAGIC (0x11581158) when the key is valid.
//      Without a valid key, the kernel does NOT intercept the call at all
//      and the real truncate() syscall runs instead (returns -EFAULT / -EINVAL
//      because the first arg is not a valid path).
//
//   4. Superkey is stored persistently in kernel memory and can be read/set
//      with SKEY_GET / SKEY_SET commands (both require superkey auth, obviously).
//      On Android, the key is also stored in /data/adb/ap/superkey so apd
//      can re-elevate itself after boot.
//
// "Manager level" detection for APatch therefore means:
//   - we have the actual superkey (either supplied by user, or read from
//     /data/adb/ap/superkey if we have root access),
//   - we can call commands that *require* superkey privilege and get
//     proper results back (e.g. KP version, su list count, safemode state,
//     module list, etc.),
//   - we can distinguish "root via su list" (key="su") from "real superkey"
//     by trying a manager-only command like SKEY_GET.
//
// Compare with KernelSU, where manager identity is proven by UID matching
// (the kernel knows the manager's package name via throne_tracker).

#pragma once

#include <cstdint>
#include <sys/types.h>
#include <unistd.h>

namespace apatch {

// --- Syscall number ---
constexpr long NR_SUPERCALL = 45;  // __NR_truncate on arm64/arm/x86

// --- Magic ---
constexpr uint32_t HELLO_MAGIC = 0x11581158u;
constexpr const char* HELLO_ECHO = "hello1158";

// --- Supercall command codes (lower 16 bits of ver_and_cmd) ---
constexpr uint16_t SUPERCALL_HELLO              = 0x1000;
constexpr uint16_t SUPERCALL_KLOG               = 0x1004;
constexpr uint16_t SUPERCALL_BUILD_TIME         = 0x1007;
constexpr uint16_t SUPERCALL_KERNELPATCH_VER    = 0x1008;
constexpr uint16_t SUPERCALL_KERNEL_VER         = 0x1009;
constexpr uint16_t SUPERCALL_SKEY_GET           = 0x100a;
constexpr uint16_t SUPERCALL_SKEY_SET           = 0x100b;
constexpr uint16_t SUPERCALL_SKEY_ROOT_ENABLE   = 0x100c;
constexpr uint16_t SUPERCALL_SU                 = 0x1010;
constexpr uint16_t SUPERCALL_SU_TASK            = 0x1011;
constexpr uint16_t SUPERCALL_KPM_LOAD           = 0x1020;
constexpr uint16_t SUPERCALL_KPM_UNLOAD         = 0x1021;
constexpr uint16_t SUPERCALL_KPM_CONTROL        = 0x1022;
constexpr uint16_t SUPERCALL_KPM_NUMS           = 0x1030;
constexpr uint16_t SUPERCALL_KPM_LIST           = 0x1031;
constexpr uint16_t SUPERCALL_KPM_INFO           = 0x1032;
constexpr uint16_t SUPERCALL_KSTORAGE_WRITE     = 0x1041;
constexpr uint16_t SUPERCALL_KSTORAGE_READ      = 0x1042;
constexpr uint16_t SUPERCALL_KSTORAGE_LIST_IDS  = 0x1043;
constexpr uint16_t SUPERCALL_KSTORAGE_REMOVE    = 0x1044;
constexpr uint16_t SUPERCALL_CONTROL_FEATURE    = 0x1046;
constexpr uint16_t SUPERCALL_BOOTLOG            = 0x10fd;
constexpr uint16_t SUPERCALL_PANIC              = 0x10fe;
constexpr uint16_t SUPERCALL_TEST               = 0x10ff;
constexpr uint16_t SUPERCALL_SU_GRANT_UID       = 0x1100;
constexpr uint16_t SUPERCALL_SU_REVOKE_UID      = 0x1101;
constexpr uint16_t SUPERCALL_SU_NUMS            = 0x1102;
constexpr uint16_t SUPERCALL_SU_LIST            = 0x1103;
constexpr uint16_t SUPERCALL_SU_PROFILE         = 0x1104;
constexpr uint16_t SUPERCALL_SU_GET_ALLOW_SCTX  = 0x1105;
constexpr uint16_t SUPERCALL_SU_SET_ALLOW_SCTX  = 0x1106;
constexpr uint16_t SUPERCALL_SU_GET_PATH        = 0x1110;
constexpr uint16_t SUPERCALL_SU_RESET_PATH      = 0x1111;
constexpr uint16_t SUPERCALL_SU_GET_SAFEMODE    = 0x1112;
constexpr uint16_t SUPERCALL_MAX                = 0x1200;

// --- Limits ---
constexpr size_t KEY_MAX_LEN      = 0x40;
constexpr size_t SCONTEXT_LEN     = 0x60;
constexpr size_t SU_PATH_MAX_LEN  = 128;

// --- Kernel storage groups ---
constexpr int KSTORAGE_SU_LIST_GROUP      = 0;
constexpr int KSTORAGE_EXCLUDE_LIST_GROUP = 1;

// --- Android filesystem paths ---
constexpr const char* APD_PATH       = "/data/adb/apd";
constexpr const char* AP_DIR         = "/data/adb/ap";
constexpr const char* SUPERKEY_PATH  = "/data/adb/ap/superkey";
constexpr const char* SU_PATH_FILE   = "/data/adb/ap/su_path";

// --- su profile structure (matches kernel definition) ---
struct su_profile {
    uid_t  uid;
    uid_t  to_uid;
    char   scontext[SCONTEXT_LEN];
};

// --- Build the 64-bit `ver_and_cmd` second argument ---
// Bits: [63:32] version_code, [31:16] 0x1158 magic, [15:0] cmd
static inline uint64_t make_ver_and_cmd(uint32_t version_code, uint16_t cmd) {
    return (static_cast<uint64_t>(version_code) << 32) |
           (static_cast<uint64_t>(0x1158) << 16) |
           static_cast<uint64_t>(cmd);
}

// --- The same simple hash function the kernel uses ---
static inline long hash_key(const char* key) {
    long hash = 1000000007;
    for (int i = 0; key[i]; i++) {
        hash = hash * 31 + key[i];
    }
    return hash;
}

// --- Privilege levels determined by detection ---
enum class PrivLevel {
    None,           // no APatch detected
    Unconfirmed,    // key not provided, can't confirm
    SuList,         // key = "su" (we're an allowed uid, not the manager)
    SuperKey,       // real superkey (full manager-level access)
};

} // namespace apatch
