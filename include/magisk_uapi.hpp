// SPDX-License-Identifier: GPL-3.0-or-later
//
// Magisk userspace API - manager-level handshake detection.
//
// Magisk is structurally different from KernelSU and APatch:
// it runs a userspace daemon (magiskd) that listens on an abstract
// Unix domain socket, and the Magisk Manager app connects to it
// to request root, list modules, toggle settings, etc.
//
// The "manager-level handshake" therefore means:
//   1. We can find and connect to the magiskd abstract socket,
//   2. We speak the Magisk daemon protocol and get valid replies,
//   3. We can distinguish:
//        - "magiskd is present" (any app can connect for some ops)
//        - "we have su access" (we can call su-related requests)
//        - "we are the manager" (manager package is whitelisted by
//          magiskd's pkg_name / signature check)
//
// Additional detection vectors:
//   - /sbin/.magisk/ mount namespace traces
//   - Zygisk (Zygote injection) detection via /proc/self/maps,
//     /proc/self/attr/current, or Zygisk-specific files
//   - su binary behavior (Magisk's su replies with specific output)
//   - /data/adb/magisk/ filesystem traces
//
// Magisk daemon protocol (simplified):
//   - Client connects to abstract socket @magiskd (or dynamic name),
//   - Sends a request header + payload,
//   - Daemon responds with a response header + payload.
//   - Request types include: version check, su request, module list, etc.
//
// Historical note: older Magisk versions used /dev/socket/magiskd
// (filesystem socket); newer versions use abstract sockets with
// dynamically-generated names to hinder detection.  We probe both.

#pragma once

#include <cstdint>
#include <cstddef>

namespace magisk {

// --- Socket path patterns -------------------------------------------------

// Abstract socket prefix for magiskd.  Modern Magisk generates
// a random suffix, but the prefix is consistent.
constexpr const char* ABSTRACT_SOCKET_PREFIX = "magiskd";

// Legacy filesystem socket path (older Magisk versions)
constexpr const char* LEGACY_SOCKET_PATH = "/dev/socket/magiskd";

// --- Filesystem hint paths ------------------------------------------------

constexpr const char* MAGISK_SBIN_DIR      = "/sbin/.magisk";
constexpr const char* MAGISK_DATA_ADB_DIR  = "/data/adb/magisk";
constexpr const char* MAGISK_DB_PATH       = "/data/adb/magisk.db";
constexpr const char* MAGISK_MODULES_DIR   = "/data/adb/modules";
constexpr const char* MAGISK_MODULES_UPDATE_DIR = "/data/adb/modules_update";
constexpr const char* MAGISK_POST_FS_DATA  = "/data/adb/post-fs-data.d";
constexpr const char* MAGISK_SERVICE_D     = "/data/adb/service.d";

// --- Su binary detection --------------------------------------------------

// Magisk's su --version outputs a string like "xx.x:MAGISK"
constexpr const char* SU_VERSION_MAGIC = "MAGISK";

// --- Zygisk detection -----------------------------------------------------

// Zygisk injects libzygisk.so into zygote. We can check for:
//   1. /proc/self/maps containing "zygisk"
//   2. /proc/self/maps containing "libzygisk"
//   3. ro.zygisk property (if available - often hidden)
constexpr const char* ZYGISK_LIB_NAME     = "zygisk";
constexpr const char* ZYGISK_PROPERTY     = "ro.zygisk";

// SusFS detection - susfs is a Magisk/KernelSU module/feature for
// hiding root traces. We detect it by checking for:
//   - /proc/sys/kernel/susfs_*  (kernel parameter)
//   - SusFS-specific entries in /sys/module/
//   - susfs su loop device markers
constexpr const char* SUSFS_PROC_PREFIX   = "/proc/sys/kernel/susfs_";
constexpr const char* SUSFS_MODULE_DIR    = "/sys/module/susfs";
constexpr const char* SUSFS_KSU_MARKER    = "/data/adb/ksu/modules/susfs";

// --- Daemon request/response codes ---------------------------------------
//
// These are simplified / commonly-known Magisk daemon opcodes.
// The actual protocol may change between versions, so we use a
// "best-effort" approach: try the version query and if we get a
// sane-looking response, we know magiskd is present.

// Socket request header magic
constexpr uint32_t DAEMON_REQ_MAGIC = 0x4D414749u;  // "MAGI" (partial)

// Common request codes (approximate - may vary by version)
enum DaemonRequestCode : uint32_t {
    CHECK_VERSION    = 0,   // query daemon version
    POST_FS_DATA     = 1,
    LATE_START       = 2,
    BOOT_COMPLETED   = 3,
    HANDLE_PROCESS   = 4,
    GET_VERSION      = 5,   // get magisk version string
    SU_REQUEST       = 10,
    SU_RESULT        = 11,
    LIST_MODULES     = 20,
    GET_MODULE_INFO  = 21,
    ENABLE_MODULE    = 22,
    DISABLE_MODULE   = 23,
    REBOOT           = 100,
};

// Response header
struct daemon_response {
    int32_t  code;      // response code / error
    int32_t  pid;       // originating pid
    uint32_t version;   // magisk version code (if version query)
    uint32_t padding;
};

// Version code encoding: e.g. 26400 = 26.4
static inline int version_major(uint32_t ver_code) {
    return static_cast<int>(ver_code / 1000);
}
static inline int version_minor(uint32_t ver_code) {
    return static_cast<int>((ver_code % 1000) / 10);
}

// --- Privilege levels determined by detection -----------------------------

enum class PrivLevel {
    None,           // no Magisk detected
    Unconfirmed,    // traces found but no handshake confirmation
    DaemonOnly,     // magiskd socket found + handshake works
    Su,             // we can get a root shell via su
    Manager,        // we are the manager app (package whitelisted)
};

// --- Magisk variant flags -------------------------------------------------

enum class Variant : uint32_t {
    Standard     = 0,
    Zygisk       = (1u << 0),  // Zygisk enabled
    Shamiko      = (1u << 1),  // Shamiko module (hide)
    SusFS        = (1u << 2),  // SusFS hide
    LSPosed      = (1u << 3),  // LSPosed / Xposed framework
    MagiskHide   = (1u << 4),  // MagiskHide active
    Kitsune      = (1u << 5),  // Kitsune Magisk (Magisk Delta fork)
    Alpha        = (1u << 6),  // Magisk Alpha fork
    LSPosedLite  = (1u << 7),  // LSPosed lite / zygisk-next
};

inline Variant operator|(Variant a, Variant b) {
    return static_cast<Variant>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline Variant operator&(Variant a, Variant b) {
    return static_cast<Variant>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}
inline bool has_variant(Variant v, Variant flag) {
    return (static_cast<uint32_t>(v) & static_cast<uint32_t>(flag)) != 0;
}

} // namespace magisk
