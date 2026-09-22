// SPDX-License-Identifier: GPL-3.0-or-later
//
// Manager-level kernel root detector for KernelSU and KernelPatch/APatch.
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

#pragma once

#include <string>
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
    Both,          // both detected (very rare, usually impossible)
};

enum class KsuPrivLevel {
    None,
    User,            // we have a driver fd but are just a random app
    ManagerOrRoot,   // we can call manager_or_root ioctls
    Manager,         // GET_INFO returned MANAGER flag - we ARE the manager UID
    Root,            // we are root (uid 0)
};

struct KsuResult {
    bool present = false;
    uint32_t version = 0;
    uint32_t uapi_version = 0;
    uint32_t flags = 0;
    uint32_t features = 0;
    KsuPrivLevel priv_level = KsuPrivLevel::None;
    std::optional<uint32_t> manager_appid;  // if we could query it
    std::string mode_str;                   // "lkm", "built-in", "late-load", etc.
};

enum class ApPrivLevel {
    None,
    Unconfirmed,     // no key provided, can't check kernel level
    SuList,          // "su" key works (we're on the allow list)
    SuperKey,        // real superkey works (full manager access)
};

struct ApResult {
    bool present = false;
    ApPrivLevel priv_level = ApPrivLevel::None;
    uint32_t kp_version = 0;
    uint32_t kernel_version = 0;
    std::optional<long> su_uid_count;
    std::optional<long> kpm_count;
    std::optional<long> safemode;
    std::string detected_key_source;  // "user", "su-path", "superkey-file", etc.
};

struct DetectResult {
    KernelType type = KernelType::None;
    KsuResult ksu;
    ApResult  ap;

    // filesystem fingerprint results
    bool ksu_filesystem_hint = false;
    bool ap_filesystem_hint  = false;
};

class Detector {
public:
    Detector();
    ~Detector();

    // Set the APatch superkey to use (if known).
    // If not set, we'll try to read it from /data/adb/ap/superkey
    // (only works if we already have root or we're the manager).
    void set_ap_superkey(const std::string& key);

    // Enable or disable seccomp SIGSYS trap handling
    // (KernelSU reboot magic can be blocked by seccomp; we catch the signal).
    void enable_sigsys_handler(bool enable);

    // Run all detection probes.
    DetectResult run_all();

    // Individual probes
    KsuResult probe_ksu();
    ApResult  probe_apatch();

    // Filesystem fingerprint check (no kernel interaction)
    void probe_filesystem(DetectResult& out);

private:
    std::string ap_superkey_;
    bool sigsys_installed_ = false;
    static volatile bool g_sigsys_hit_;

    static void sigsys_handler(int sig, siginfo_t* si, void* ctx);
    void install_sigsys();
    void uninstall_sigsys();

    // KernelSU helpers
    int ksu_install_fd();
    bool ksu_do_get_info(int fd, ksu::get_info_cmd& info);
    bool ksu_do_get_manager_appid(int fd, uint32_t& appid);

    // APatch helpers
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
};

} // namespace ksu_detector
