// SPDX-License-Identifier: GPL-3.0-or-later
//
// Manager-level kernel root detector for KernelSU, KernelPatch/APatch,
// and Magisk / Zygisk / SusFS / GKI / jailbreak variants.
//
// Unlike simple "hello probe" detectors, this class performs the same
// handshake that the official manager clients do, and verifies the
// privilege level we actually have.
//
// For KernelSU:
//   - installs a driver fd via reboot magic,
//   - calls GET_INFO -> flags tell us if *we* are the manager UID,
//   - calls GET_MANAGER_APPID -> if it succeeds we have manager-or-root
//     level access,
//   - can call only_manager ioctls (GET_APP_PROFILE for our own uid) as
//     the ultimate proof of manager identity.
//
// For APatch:
//   - tries the hello probe with the provided superkey,
//   - if key == "su", distinguishes su-list access from real superkey by
//     trying SKEY_GET (only real superkey can read the key back),
//   - reads KP version, kernel version, su uid count, safemode, module count.
//
// For Magisk:
//   - probes the magiskd abstract Unix socket (modern) or /dev/socket/magiskd (legacy),
//   - sends a version handshake request and checks for a valid reply,
//   - checks Zygisk presence via /proc/self/maps,
//   - checks su binary signature,
//   - determines privilege level: daemon-only / su-access / manager.
//
// Variant detection (KSU GKI, SusFS, jailbreak, LSPosed, etc.):
//   - KernelSU GKI mode (kprobe on GKI kernel + LKM late-load)
//   - SusFS (kernel-level hide module)
//   - LSPosed / Zygisk / Shamiko / MagiskHide
//   - Jailbreak-style root (custom ROM, unsecured boot, etc.)

#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <cstddef>
#include <signal.h>

namespace ksu {
struct get_info_cmd;
}  // namespace ksu

namespace ksu_detector {

// --- Result types ---

enum class KernelType {
    Unknown,
    None,          // no kernel root detected
    KernelSU,
    KernelPatch,   // APatch / KernelPatch
    Magisk,        // Magisk / Zygisk
    Mixed,         // more than one detected
};

// --- KernelSU ---

enum class KsuPrivLevel {
    None,
    User,            // we have a driver fd but are just a random app
    ManagerOrRoot,   // we can call manager_or_root ioctls
    Manager,         // GET_INFO returned MANAGER flag - we ARE the manager UID
    Root,            // we are root (uid 0)
};

enum class KsuVariant : uint32_t {
    Standard     = 0,
    GKI          = (1u << 0),  // GKI mode (LKM on GKI kernel)
    LateLoad     = (1u << 1),  // late-load mode
    BuiltIn      = (1u << 2),  // built-in (non-GKI)
    LKM          = (1u << 3),  // loadable kernel module
    SusFS        = (1u << 4),  // SusFS hide module active
    PRBuild      = (1u << 5),  // PR build / unofficial
    KMICompatible= (1u << 6),  // KMI-compatible GKI LKM
};

inline KsuVariant operator|(KsuVariant a, KsuVariant b) {
    return static_cast<KsuVariant>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline bool has_ksu_variant(KsuVariant v, KsuVariant flag) {
    return (static_cast<uint32_t>(v) & static_cast<uint32_t>(flag)) != 0;
}

struct KsuResult {
    bool present = false;
    uint32_t version = 0;
    uint32_t uapi_version = 0;
    uint32_t flags = 0;
    uint32_t features = 0;
    KsuPrivLevel priv_level = KsuPrivLevel::None;
    KsuVariant variant = KsuVariant::Standard;
    std::optional<uint32_t> manager_appid;  // if we could query it
    std::string mode_str;                   // "lkm", "built-in", "late-load", etc.
    bool susfs_detected = false;
    std::string susfs_detail;
    bool kernel_compromised = false;
    std::string compromise_reason;
};

// --- APatch ---

enum class ApPrivLevel {
    None,
    Unconfirmed,
    SuList,
    SuperKey,
};

struct ApResult {
    bool present = false;
    ApPrivLevel priv_level = ApPrivLevel::None;
    uint32_t kp_version = 0;
    uint32_t kernel_version = 0;
    std::optional<long> su_uid_count;
    std::optional<long> kpm_count;
    std::optional<long> safemode;
    std::string detected_key_source;
};

// --- Magisk ---

enum class MagiskPrivLevel {
    None,
    Unconfirmed,
    DaemonOnly,
    Su,
    Manager,
};

struct MagiskResult {
    bool present = false;
    MagiskPrivLevel priv_level = MagiskPrivLevel::None;
    uint32_t version_code = 0;
    std::string version_str;
    std::string socket_path;
    bool zygisk_detected = false;
    std::string zygisk_detail;
    bool su_binary_detected = false;
    std::string su_binary_path;
    bool has_zygisk     = false;
    bool has_shamiko    = false;
    bool has_susfs      = false;
    bool has_lsposed    = false;
    bool has_magiskhide = false;
    bool is_kitsune     = false;
    bool is_alpha       = false;
};

// --- Jailbreak ---

struct JailbreakHint {
    bool detected = false;
    std::vector<std::string> indicators;
};

// --- SusFS (independent kernel-level handshake) ---

// Which syscall ABI answered the SHOW_VERSION handshake.
enum class SusfsAbi {
    None,      // no SusFS interface answered
    Prctl,     // v1.5.3 - v1.5.12: prctl(0xDEADBEEF, ...)
    RebootV2,  // v2.0.0+     : reboot(0xDEADBEEF, 0xFAFAFAFA, ...)
};

struct SusfsResult {
    bool detected = false;
    SusfsAbi abi = SusfsAbi::None;
    std::string version;        // exact string reported by the kernel, e.g. "v1.5.9" / "v2.1.0"
    std::string detail;         // human-readable handshake description
};

// --- Top-level result ---

struct DetectResult {
    KernelType type = KernelType::None;
    KsuResult ksu;
    ApResult  ap;
    MagiskResult magisk;
    SusfsResult susfs;
    JailbreakHint jailbreak;
    bool susfs_detected = false;
    std::string susfs_source;
};

class Detector {
public:
    Detector();
    ~Detector();
    void set_ap_superkey(const std::string& key);
    void enable_sigsys_handler(bool enable);
    DetectResult run_all();
    KsuResult probe_ksu();
    ApResult  probe_apatch();
    MagiskResult probe_magisk();
    SusfsResult probe_susfs();
    void probe_variants(DetectResult& out);
    void probe_jailbreak(DetectResult& out);

private:
    std::string ap_superkey_;
    bool sigsys_installed_ = false;
    static volatile bool g_sigsys_hit_;
    static void sigsys_handler(int sig, siginfo_t* si, void* ctx);
    void install_sigsys();
    void uninstall_sigsys();
    int ksu_install_fd();
    bool ksu_do_get_info(int fd, ksu::get_info_cmd& info);
    bool ksu_do_get_manager_appid(int fd, uint32_t& appid);
    std::string try_find_superkey();
    long ap_raw_call(const char* key, uint16_t cmd,
                     long arg3 = 0, long arg4 = 0,
                     long arg5 = 0, long arg6 = 0);
    bool ap_hello(const char* key);
    uint32_t ap_kp_ver(const char* key);
    uint32_t ap_k_ver(const char* key);
    long ap_su_nums(const char* key);
    long ap_kpm_nums(const char* key);
    long ap_safemode(const char* key);
    bool ap_try_skey_get(const char* key, char* buf, size_t buf_len);
    bool magisk_find_socket(std::string& out_path);
    bool magisk_probe_daemon(const std::string& socket_path,
                             uint32_t& out_version_code,
                             std::string& out_version_str);
    bool magisk_check_zygisk();
    bool magisk_check_su_binary(std::string& out_path);
    bool magisk_check_module(const std::string& module_id);
    bool magisk_check_kitsune();
    bool magisk_check_alpha();
};

} // namespace ksu_detector
