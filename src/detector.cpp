// SPDX-License-Identifier: GPL-3.0-or-later
//
// Manager-level detector implementation for KernelSU and APatch.
//
// This file implements the actual handshake with the kernel.
//

#include "detector.hpp"
#include "ksu_uapi.hpp"
#include "apatch_uapi.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <string>
#include <fstream>
#include <sstream>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace ksu_detector {

// --- SIGSYS handler ---------------------------------------------------------
//
// The reboot syscall is commonly blocked by seccomp on Android.  If the
// kernel module is present, the kprobe pre-handler fires BEFORE seccomp
// check on some architectures, but in general the reboot() call may still
// return -EPERM via SIGSYS.  We catch SIGSYS so the process doesn't die,
// and set a flag so we know seccomp got in the way.

volatile bool Detector::g_sigsys_hit_ = false;

void Detector::sigsys_handler(int sig, siginfo_t* si, void* ctx) {
    (void)sig;
    if (!si || si->si_code != 1 /* SYS_SECCOMP */) return;
    g_sigsys_hit_ = true;
#if defined(__aarch64__)
    ucontext_t* uc = static_cast<ucontext_t*>(ctx);
    uc->uc_mcontext.regs[0] = static_cast<uint64_t>(-EPERM);
#elif defined(__x86_64__)
    ucontext_t* uc = static_cast<ucontext_t*>(ctx);
    uc->uc_mcontext.gregs[REG_RAX] = static_cast<long>(-EPERM);
#else
    (void)ctx;
#endif
}

void Detector::install_sigsys() {
    if (sigsys_installed_) return;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigsys_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, nullptr);
    sigsys_installed_ = true;
}

void Detector::uninstall_sigsys() {
    if (!sigsys_installed_) return;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, nullptr);
    sigsys_installed_ = false;
}

// --- Detector lifecycle ----------------------------------------------------

Detector::Detector() = default;
Detector::~Detector() {
    if (sigsys_installed_) uninstall_sigsys();
}

void Detector::set_ap_superkey(const std::string& key) {
    ap_superkey_ = key;
}

void Detector::enable_sigsys_handler(bool enable) {
    if (enable) install_sigsys();
    else uninstall_sigsys();
}

// --- KernelSU: install driver fd -------------------------------------------
//
// This replicates what ksud/manager does: call reboot() with the magic
// constants; the kernel kprobe on the reboot symbol's pre_handler queues
// a task_work that creates an anonymous inode "[ksu_driver]" and installs
// it into the caller's fd table.  The 4th argument points to an int that
// receives the new fd.

int Detector::ksu_install_fd() {
    g_sigsys_hit_ = false;
    int fd = -1;

    // reboot(magic1, magic2, cmd=0, arg=&fd)
    long r = syscall(SYS_reboot,
                     static_cast<unsigned int>(ksu::INSTALL_MAGIC1),
                     static_cast<unsigned int>(ksu::INSTALL_MAGIC2),
                     0, &fd);

    if (g_sigsys_hit_) {
        // seccomp blocked reboot - if KSU is present it may still have
        // installed the fd via kprobe pre_handler.  Check fd validity.
        // On some setups the pre_handler runs before seccomp, on others
        // not.  We just return whatever fd we got.
    }

    if (r < 0 && fd < 0) return -1;
    if (fd < 0) return -1;

    // Validate by checking if the fd is open (fstat succeeds).
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

bool Detector::ksu_do_get_info(int fd, ksu::get_info_cmd& info) {
    memset(&info, 0, sizeof(info));
    if (ioctl(fd, ksu::IOCTL_GET_INFO, &info) < 0) return false;
    return info.version != 0;
}

bool Detector::ksu_do_get_manager_appid(int fd, uint32_t& appid) {
    ksu::get_manager_appid_cmd cmd{};
    if (ioctl(fd, ksu::IOCTL_GET_MANAGER_APPID, &cmd) < 0) return false;
    appid = cmd.appid;
    return true;
}

// --- KernelSU: full probe --------------------------------------------------

KsuResult Detector::probe_ksu() {
    KsuResult result;

    // Always install SIGSYS before reboot magic
    install_sigsys();

    // Phase 1: get a driver fd (modern KernelSU)
    int fd = ksu_install_fd();
    if (fd >= 0) {
        ksu::get_info_cmd info;
        if (ksu_do_get_info(fd, info)) {
            result.present = true;
            result.version = info.version;
            result.uapi_version = info.uapi_version;
            result.flags = info.flags;
            result.features = info.features;

            // Determine mode string
            if (info.flags & ksu::GET_INFO_FLAG_LATE_LOAD) {
                result.mode_str = "late-load";
            } else if (info.flags & ksu::GET_INFO_FLAG_LKM) {
                result.mode_str = (info.flags & ksu::GET_INFO_FLAG_BUNDLED)
                                      ? "lkm-bundled" : "lkm";
            } else {
                result.mode_str = "built-in";
            }

            // Determine privilege level
            uid_t uid = getuid();
            if (uid == 0) {
                result.priv_level = KsuPrivLevel::Root;
            } else if (info.flags & ksu::GET_INFO_FLAG_MANAGER) {
                result.priv_level = KsuPrivLevel::Manager;
            } else {
                // Check if we can call a manager_or_root ioctl
                uint32_t appid = 0;
                if (ksu_do_get_manager_appid(fd, appid)) {
                    result.priv_level = KsuPrivLevel::ManagerOrRoot;
                    result.manager_appid = appid;
                } else {
                    result.priv_level = KsuPrivLevel::User;
                    // Even though we can't call it, we might still want
                    // to know the manager appid... but only privileged
                    // callers can get it.
                }
            }

            // Always try to get manager appid if we're privileged enough
            if (result.manager_appid == std::nullopt &&
                result.priv_level >= KsuPrivLevel::ManagerOrRoot) {
                uint32_t appid = 0;
                if (ksu_do_get_manager_appid(fd, appid)) {
                    result.manager_appid = appid;
                }
            }
        }
        close(fd);
    }

    // Phase 2: legacy prctl probe (if modern method failed)
    if (!result.present) {
        long legacy_ver = prctl(ksu::LEGACY_MAGIC, 0, 0, 0, 0);
        if (legacy_ver >= 0) {
            result.present = true;
            result.version = static_cast<uint32_t>(legacy_ver);
            result.mode_str = "legacy-prctl";
            result.priv_level = KsuPrivLevel::User;  // legacy has no priv levels
        }
    }

    return result;
}

// --- APatch: low-level supercall wrapper -----------------------------------

long Detector::ap_raw_call(const char* key, uint16_t cmd,
                           long arg3, long arg4,
                           long arg5, long arg6) {
    if (!key || !key[0]) return -EINVAL;

    // Use version_code 0 for probing - the kernel doesn't strictly validate
    // the upper 32 bits for most commands, but we set it to 0xA050 (10.5)
    // which is a widely-compatible version.  Actually, better to use 0
    // since we don't know the target version.
    //
    // From kernel source (kp_supercall): the kernel verifies cmd's magic
    // bits (0x1158) but not the version field for basic commands.
    uint64_t ver_cmd = apatch::make_ver_and_cmd(0, cmd);

    return syscall(static_cast<long>(apatch::NR_SUPERCALL),
                   key, static_cast<long>(ver_cmd),
                   arg3, arg4, arg5, arg6);
}

bool Detector::ap_hello(const char* key) {
    if (!key || !key[0]) return false;
    long ret = ap_raw_call(key, apatch::SUPERCALL_HELLO);
    return static_cast<uint32_t>(ret) == apatch::HELLO_MAGIC;
}

uint32_t Detector::ap_kp_ver(const char* key) {
    if (!key || !key[0]) return 0;
    long ret = ap_raw_call(key, apatch::SUPERCALL_KERNELPATCH_VER);
    return static_cast<uint32_t>(ret);
}

uint32_t Detector::ap_k_ver(const char* key) {
    if (!key || !key[0]) return 0;
    long ret = ap_raw_call(key, apatch::SUPERCALL_KERNEL_VER);
    return static_cast<uint32_t>(ret);
}

long Detector::ap_su_nums(const char* key) {
    return ap_raw_call(key, apatch::SUPERCALL_SU_NUMS);
}

long Detector::ap_kpm_nums(const char* key) {
    return ap_raw_call(key, apatch::SUPERCALL_KPM_NUMS);
}

long Detector::ap_safemode(const char* key) {
    return ap_raw_call(key, apatch::SUPERCALL_SU_GET_SAFEMODE);
}

bool Detector::ap_try_skey_get(const char* key, char* buf, size_t buf_len) {
    if (!key || !key[0] || !buf || buf_len < apatch::KEY_MAX_LEN) return false;
    long ret = ap_raw_call(key, apatch::SUPERCALL_SKEY_GET,
                           reinterpret_cast<long>(buf),
                           static_cast<long>(buf_len));
    return ret == 0;
}

// --- APatch: find superkey from filesystem ---------------------------------

std::string Detector::try_find_superkey() {
    // First, try the standard location
    std::ifstream f(apatch::SUPERKEY_PATH);
    if (f.is_open()) {
        std::string key;
        std::getline(f, key);
        // Trim whitespace
        while (!key.empty() && (key.back() == '\n' || key.back() == '\r' || key.back() == ' '))
            key.pop_back();
        if (!key.empty() && key.size() < apatch::KEY_MAX_LEN) {
            return key;
        }
    }
    return {};
}

// --- APatch: full probe ----------------------------------------------------

ApResult Detector::probe_apatch() {
    ApResult result;
    std::string key = ap_superkey_;
    std::string key_source = "user-provided";

    // If no key provided, try to find it
    if (key.empty()) {
        key = try_find_superkey();
        if (!key.empty()) key_source = "superkey-file";
    }

    // Also try "su" as key (works if our uid is on the su allow list)
    bool try_su_key = true;
    std::string su_key = "su";

    // Phase 1: try user-provided / file-found key first
    if (!key.empty()) {
        if (ap_hello(key.c_str())) {
            result.present = true;
            result.detected_key_source = key_source;

            // Determine if it's the real superkey or just "su"
            char key_buf[apatch::KEY_MAX_LEN + 1] = {0};
            if (ap_try_skey_get(key.c_str(), key_buf, sizeof(key_buf))) {
                result.priv_level = ApPrivLevel::SuperKey;
            } else {
                // Hmm, hello worked but skey_get didn't - could be a
                // limited key, or a weird setup.  Fall back to checking
                // if it's "su" equivalent.
                result.priv_level = ApPrivLevel::SuList;
            }

            result.kp_version = ap_kp_ver(key.c_str());
            result.kernel_version = ap_k_ver(key.c_str());

            // Try additional info commands
            long nums = ap_su_nums(key.c_str());
            if (nums >= 0) result.su_uid_count = nums;

            long kpms = ap_kpm_nums(key.c_str());
            if (kpms >= 0) result.kpm_count = kpms;

            long sm = ap_safemode(key.c_str());
            if (sm >= 0) result.safemode = sm;

            return result;
        }
    }

    // Phase 2: try "su" key (works if we're an allowed UID)
    if (try_su_key && ap_hello(su_key.c_str())) {
        result.present = true;
        result.priv_level = ApPrivLevel::SuList;
        result.detected_key_source = "su-allow-list";

        result.kp_version = ap_kp_ver(su_key.c_str());
        result.kernel_version = ap_k_ver(su_key.c_str());

        long nums = ap_su_nums(su_key.c_str());
        if (nums >= 0) result.su_uid_count = nums;

        long kpms = ap_kpm_nums(su_key.c_str());
        if (kpms >= 0) result.kpm_count = kpms;

        long sm = ap_safemode(su_key.c_str());
        if (sm >= 0) result.safemode = sm;

        return result;
    }

    // Phase 3: nothing worked
    if (key.empty()) {
        result.priv_level = ApPrivLevel::Unconfirmed;
    } else {
        result.priv_level = ApPrivLevel::None;
    }
    return result;
}

// --- Filesystem fingerprint ------------------------------------------------

static bool file_exists(const char* path) {
    struct stat st;
    return stat(path, &st) == 0;
}

void Detector::probe_filesystem(DetectResult& out) {
    out.ksu_filesystem_hint =
        file_exists("/data/adb/ksud") || file_exists("/data/adb/ksu");
    out.ap_filesystem_hint =
        file_exists(apatch::APD_PATH) || file_exists(apatch::AP_DIR);
}

// --- Top-level entry -------------------------------------------------------

DetectResult Detector::run_all() {
    DetectResult result;

    result.ksu = probe_ksu();
    result.ap  = probe_apatch();
    probe_filesystem(result);

    // Determine overall type
    bool has_ksu = result.ksu.present;
    bool has_ap  = result.ap.present;

    if (has_ksu && has_ap) {
        result.type = KernelType::Both;
    } else if (has_ksu) {
        result.type = KernelType::KernelSU;
    } else if (has_ap) {
        result.type = KernelType::KernelPatch;
    } else {
        result.type = KernelType::None;
    }

    return result;
}

} // namespace ksu_detector
