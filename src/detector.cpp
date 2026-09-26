// SPDX-License-Identifier: GPL-3.0-or-later
//
// Manager-level detector implementation for KernelSU, APatch,
// Magisk (with Zygisk / SusFS / variants), and jailbreak hints.
//

#include "detector.hpp"
#include "ksu_uapi.hpp"
#include "apatch_uapi.hpp"
#include "magisk_uapi.hpp"
#include "susfs_uapi.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <string>
#include <vector>
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
#include <sys/un.h>
#include <sys/socket.h>
#include <dirent.h>

namespace ksu_detector {

volatile bool Detector::g_sigsys_hit_ = false;

void Detector::sigsys_handler(int sig, siginfo_t* si, void* ctx) {
    (void)sig;
    if (!si || si->si_code != 1) return;
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

// ===========================================================================
// KernelSU
// ===========================================================================

int Detector::ksu_install_fd() {
    g_sigsys_hit_ = false;
    int fd = -1;
    long r = syscall(SYS_reboot,
                     static_cast<unsigned int>(ksu::INSTALL_MAGIC1),
                     static_cast<unsigned int>(ksu::INSTALL_MAGIC2),
                     0, &fd);
    if (r < 0 && fd < 0) return -1;
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
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

static bool check_gki_kernel() {
    FILE* f = fopen("/proc/version", "r");
    if (f) {
        char buf[512];
        if (fgets(buf, sizeof(buf), f)) {
            fclose(f);
            if (strstr(buf, "android") || strstr(buf, "gki")) return true;
        } else { fclose(f); }
    }
    return false;
}

KsuResult Detector::probe_ksu() {
    KsuResult result;
    install_sigsys();
    int fd = ksu_install_fd();
    if (fd >= 0) {
        ksu::get_info_cmd info;
        if (ksu_do_get_info(fd, info)) {
            result.present = true;
            result.kernel_compromised = true;
            result.compromise_reason = "ksu-driver-fd (reboot-magic install + GET_INFO success)";
            result.version = info.version;
            result.uapi_version = info.uapi_version;
            result.flags = info.flags;
            result.features = info.features;
            result.variant = KsuVariant::Standard;

            if (info.flags & ksu::GET_INFO_FLAG_LATE_LOAD) {
                result.mode_str = "late-load";
                result.variant = result.variant | KsuVariant::LateLoad;
            } else if (info.flags & ksu::GET_INFO_FLAG_LKM) {
                result.mode_str = (info.flags & ksu::GET_INFO_FLAG_BUNDLED) ? "lkm-bundled" : "lkm";
                result.variant = result.variant | KsuVariant::LKM;
                if (check_gki_kernel())
                    result.variant = result.variant | KsuVariant::GKI | KsuVariant::KMICompatible;
            } else {
                result.mode_str = "built-in";
                result.variant = result.variant | KsuVariant::BuiltIn;
            }
            if (info.flags & ksu::GET_INFO_FLAG_PR_BUILD)
                result.variant = result.variant | KsuVariant::PRBuild;

            uid_t uid = getuid();
            if (uid == 0) result.priv_level = KsuPrivLevel::Root;
            else if (info.flags & ksu::GET_INFO_FLAG_MANAGER) result.priv_level = KsuPrivLevel::Manager;
            else {
                uint32_t appid = 0;
                if (ksu_do_get_manager_appid(fd, appid)) {
                    result.priv_level = KsuPrivLevel::ManagerOrRoot;
                    result.manager_appid = appid;
                } else { result.priv_level = KsuPrivLevel::User; }
            }
            if (result.manager_appid == std::nullopt && result.priv_level >= KsuPrivLevel::ManagerOrRoot) {
                uint32_t appid = 0;
                if (ksu_do_get_manager_appid(fd, appid)) result.manager_appid = appid;
            }
            // SusFS is detected independently via its own syscall handshake
            // (see probe_susfs()); no file-path guessing here.
        }
        close(fd);
    }
    if (!result.present) {
        long legacy_ver = prctl(ksu::LEGACY_MAGIC, 0, 0, 0, 0);
        if (legacy_ver >= 0) {
            result.present = true;
            result.kernel_compromised = true;
            result.compromise_reason = "legacy-prctl (prctl(KSU_LEGACY_MAGIC) succeeded)";
            result.version = static_cast<uint32_t>(legacy_ver);
            result.mode_str = "legacy-prctl";
            result.priv_level = KsuPrivLevel::User;
        }
    }
    return result;
}

// ===========================================================================
// APatch
// ===========================================================================

long Detector::ap_raw_call(const char* key, uint16_t cmd, long arg3, long arg4, long arg5, long arg6) {
    if (!key || !key[0]) return -EINVAL;
    uint64_t ver_cmd = apatch::make_ver_and_cmd(0, cmd);
    return syscall(static_cast<long>(apatch::NR_SUPERCALL), key, static_cast<long>(ver_cmd), arg3, arg4, arg5, arg6);
}

bool Detector::ap_hello(const char* key) {
    if (!key || !key[0]) return false;
    long ret = ap_raw_call(key, apatch::SUPERCALL_HELLO);
    return static_cast<uint32_t>(ret) == apatch::HELLO_MAGIC;
}

uint32_t Detector::ap_kp_ver(const char* key) { return static_cast<uint32_t>(ap_raw_call(key, apatch::SUPERCALL_KERNELPATCH_VER)); }
uint32_t Detector::ap_k_ver(const char* key) { return static_cast<uint32_t>(ap_raw_call(key, apatch::SUPERCALL_KERNEL_VER)); }
long Detector::ap_su_nums(const char* key) { return ap_raw_call(key, apatch::SUPERCALL_SU_NUMS); }
long Detector::ap_kpm_nums(const char* key) { return ap_raw_call(key, apatch::SUPERCALL_KPM_NUMS); }
long Detector::ap_safemode(const char* key) { return ap_raw_call(key, apatch::SUPERCALL_SU_GET_SAFEMODE); }

bool Detector::ap_try_skey_get(const char* key, char* buf, size_t buf_len) {
    if (!key || !key[0] || !buf || buf_len < apatch::KEY_MAX_LEN) return false;
    return ap_raw_call(key, apatch::SUPERCALL_SKEY_GET, reinterpret_cast<long>(buf), static_cast<long>(buf_len)) == 0;
}

std::string Detector::try_find_superkey() {
    std::ifstream f(apatch::SUPERKEY_PATH);
    if (f.is_open()) {
        std::string key;
        std::getline(f, key);
        while (!key.empty() && (key.back() == '\n' || key.back() == '\r' || key.back() == ' ')) key.pop_back();
        if (!key.empty() && key.size() < apatch::KEY_MAX_LEN) return key;
    }
    return {};
}

ApResult Detector::probe_apatch() {
    ApResult result;
    std::string key = ap_superkey_;
    std::string key_source = "user-provided";
    if (key.empty()) { key = try_find_superkey(); if (!key.empty()) key_source = "superkey-file"; }
    std::string su_key = "su";

    if (!key.empty() && ap_hello(key.c_str())) {
        result.present = true;
        result.detected_key_source = key_source;
        char key_buf[apatch::KEY_MAX_LEN + 1] = {0};
        if (ap_try_skey_get(key.c_str(), key_buf, sizeof(key_buf))) result.priv_level = ApPrivLevel::SuperKey;
        else result.priv_level = ApPrivLevel::SuList;
        result.kp_version = ap_kp_ver(key.c_str());
        result.kernel_version = ap_k_ver(key.c_str());
        long nums = ap_su_nums(key.c_str()); if (nums >= 0) result.su_uid_count = nums;
        long kpms = ap_kpm_nums(key.c_str()); if (kpms >= 0) result.kpm_count = kpms;
        long sm = ap_safemode(key.c_str()); if (sm >= 0) result.safemode = sm;
        return result;
    }
    if (ap_hello(su_key.c_str())) {
        result.present = true;
        result.priv_level = ApPrivLevel::SuList;
        result.detected_key_source = "su-allow-list";
        result.kp_version = ap_kp_ver(su_key.c_str());
        result.kernel_version = ap_k_ver(su_key.c_str());
        long nums = ap_su_nums(su_key.c_str()); if (nums >= 0) result.su_uid_count = nums;
        long kpms = ap_kpm_nums(su_key.c_str()); if (kpms >= 0) result.kpm_count = kpms;
        long sm = ap_safemode(su_key.c_str()); if (sm >= 0) result.safemode = sm;
        return result;
    }
    result.priv_level = key.empty() ? ApPrivLevel::Unconfirmed : ApPrivLevel::None;
    return result;
}

// ===========================================================================
// Magisk
// ===========================================================================

bool Detector::magisk_find_socket(std::string& out_path) {
    auto is_sock = [](const char* p) {
        struct stat st;
        return stat(p, &st) == 0 && S_ISSOCK(st.st_mode);
    };

    // 1) Preferred filesystem socket paths (Magisk 31: get_magisk_tmp() + "/.magisk/device/socket")
    if (is_sock(magisk::DSOCKET_PATH))      { out_path = magisk::DSOCKET_PATH; return true; }
    if (is_sock(magisk::SBIN_SOCKET_PATH))  { out_path = magisk::SBIN_SOCKET_PATH; return true; }

    // 2) Scan /proc/net/unix for any *filesystem* socket whose path contains
    //    the magisk device socket dir (robust across MAGISKTMP location).
    FILE* f = fopen("/proc/net/unix", "r");
    if (f) {
        char line[512];
        if (fgets(line, sizeof(line), f)) {
            while (fgets(line, sizeof(line), f)) {
                // columns are e.g.:
                // 0000000000000000: 00000002 00000000 00010000 0001 01 31867 /debug_ramdisk/.magisk/device/socket
                // abstract sockets start with '@' — skip those.
                char* sp = strrchr(line, ' ');
                if (!sp) continue;
                while (*sp == ' ' || *sp == '\n' || *sp == '\r') { *sp = '\0'; if (sp == line) break; --sp; }
                char* path = strrchr(line, ' ');
                if (!path) continue;
                ++path;
                if (*path == '@' || !*path) continue;                    // abstract or empty
                if (strstr(path, magisk::SOCKET_DIR_MARKER)) {
                    out_path = path;
                    fclose(f);
                    return true;
                }
            }
        }
        fclose(f);
    }

    // 3) Last-resort legacy path (obsolete for Magisk 31)
    if (is_sock(magisk::LEGACY_SOCKET_PATH)) { out_path = magisk::LEGACY_SOCKET_PATH; return true; }
    return false;
}

bool Detector::magisk_probe_daemon(const std::string& socket_path, uint32_t& out_version_code, std::string& out_version_str) {
    // --- helper: connect to a (filesystem or abstract) unix socket ---
    auto do_connect = [](const std::string& path) -> int {
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) return -1;
        struct sockaddr_un addr; memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        bool is_abstract = path[0] == '@';
        std::string name = is_abstract ? path.substr(1) : path;
        if (name.size() >= sizeof(addr.sun_path)) { close(sock); return -1; }
        if (is_abstract) {
            addr.sun_path[0] = '\0';
            memcpy(addr.sun_path + 1, name.c_str(), name.size());
        } else {
            memcpy(addr.sun_path, name.c_str(), name.size());
        }
        socklen_t addr_len = static_cast<socklen_t>(offsetof(struct sockaddr_un, sun_path) +
                             (is_abstract ? 1 : 0) + name.size());
        if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), addr_len) < 0) {
            close(sock); return -1;
        }
        return sock;
    };

    auto write_i32 = [](int sock, int32_t v) -> bool {
        ssize_t n = write(sock, &v, sizeof(v));
        return n == static_cast<ssize_t>(sizeof(v));
    };
    auto read_i32 = [](int sock, int32_t& v) -> bool {
        ssize_t n = read(sock, &v, sizeof(v));
        return n == static_cast<ssize_t>(sizeof(v));
    };

    // Magisk 31 daemon flow (daemon.rs handle_requests):
    //   connect -> write_pod(RequestCode) -> read_pod(RespondCode)
    //   OK(0)  => handshake acknowledged, then read request payload.
    // Non-root / non-magisk / non-zygote peers get ACCESS_DENIED(2) and are
    // dropped, so the caller is expected to run this detector as root.

    // --- Probe 1: CHECK_VERSION_CODE(2) -> replies MAGISK_VER_CODE (int32) ---
    {
        int sock = do_connect(socket_path);
        if (sock < 0) return false;
        if (!write_i32(sock, magisk::DaemonRequestCode::CHECK_VERSION_CODE)) { close(sock); return false; }
        int32_t resp = -1;
        if (!read_i32(sock, resp)) { close(sock); return false; }
        if (resp != magisk::DaemonRespondCode::RESP_OK) { close(sock); return false; } // access denied etc.
        int32_t ver = 0;
        if (!read_i32(sock, ver) || ver <= 0) { close(sock); return false; }
        out_version_code = static_cast<uint32_t>(ver);
        close(sock);
    }

    // --- Probe 2 (best effort): CHECK_VERSION(1) -> replies version STRING ---
    // str encoding: [int32 len][bytes] (socket.rs Encodable for str)
    {
        int sock = do_connect(socket_path);
        if (sock < 0) return true;   // vcode probe already proved daemon
        bool ok = write_i32(sock, magisk::DaemonRequestCode::CHECK_VERSION);
        int32_t resp = -1;
        if (!ok || !read_i32(sock, resp) || resp != magisk::DaemonRespondCode::RESP_OK) { close(sock); return true; }
        int32_t len = 0;
        if (read_i32(sock, len) && len > 0 && len < 4096) {
            std::vector<char> buf(static_cast<size_t>(len) + 1, 0);
            ssize_t total = 0;
            while (total < len) {
                ssize_t n = read(sock, buf.data() + total, static_cast<size_t>(len - total));
                if (n <= 0) break;
                total += n;
            }
            buf[total] = '\0';
            out_version_str = std::string(buf.data());
        }
        close(sock);
    }
    return true;
}

bool Detector::magisk_check_zygisk() {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    char line[1024]; bool found = false;
    while (fgets(line, sizeof(line), f)) { if (strstr(line, "zygisk") || strstr(line, "Zygisk")) { found = true; break; } }
    fclose(f); return found;
}

bool Detector::magisk_check_su_binary(std::string& out_path) {
    static const char* su_paths[] = { "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/magisk/.core/bin/su", nullptr };
    for (int i = 0; su_paths[i]; i++) { struct stat st; if (stat(su_paths[i], &st) == 0) { out_path = su_paths[i]; return true; } }
    return false;
}

bool Detector::magisk_check_module(const std::string& module_id) {
    std::string path = std::string(magisk::MAGISK_MODULES_DIR) + "/" + module_id;
    struct stat st; return stat(path.c_str(), &st) == 0;
}

bool Detector::magisk_check_kitsune() {
    struct stat st;
    return stat("/data/adb/magisk_delta", &st) == 0 || stat("/data/adb/delta", &st) == 0 || stat("/sbin/.magisk/config", &st) == 0;
}

bool Detector::magisk_check_alpha() {
    struct stat st;
    return stat("/data/adb/magisk_alpha", &st) == 0 || stat("/data/adb/alpha", &st) == 0;
}

MagiskResult Detector::probe_magisk() {
    MagiskResult result;
    std::string sock_path;
    // Root handshake is the ONLY proof Magisk is actively running.
    if (magisk_find_socket(sock_path)) {
        result.socket_path = sock_path;
        uint32_t ver_code = 0; std::string ver_str;
        if (magisk_probe_daemon(sock_path, ver_code, ver_str)) {
            result.present = true;
            result.priv_level = MagiskPrivLevel::DaemonOnly;
            result.version_code = ver_code;
            result.version_str = ver_str;
            if (getuid() == 0) result.priv_level = MagiskPrivLevel::Su;
        }
    }
    // Traces are informational only — they never assert "present".
    result.has_zygisk = magisk_check_zygisk();
    if (result.has_zygisk) { result.zygisk_detected = true; result.zygisk_detail = "maps-scan"; }
    std::string su_path;
    if (magisk_check_su_binary(su_path)) { result.su_binary_detected = true; result.su_binary_path = su_path; }
    if (result.present) {
        result.has_shamiko = magisk_check_module("shamiko");
        result.has_lsposed = magisk_check_module("lsposed") || magisk_check_module("zygisk_lsposed") || magisk_check_module("riru_lsposed");
        result.has_magiskhide = magisk_check_module("magiskhide");
        result.is_kitsune = magisk_check_kitsune();
        result.is_alpha = magisk_check_alpha();
        // SusFS is confirmed via its own syscall handshake (probe_susfs()),
        // not by guessing proc/sys paths.
    }
    return result;
}

// ===========================================================================
// SusFS (independent kernel-level handshake)
// ===========================================================================

SusfsResult Detector::probe_susfs() {
    SusfsResult result;
    install_sigsys();

    // Phase 1 — v2.0.0+ reboot ABI:
    //   syscall(SYS_reboot, 0xDEADBEEF, 0xFAFAFAFA, SHOW_VERSION, &v2)
    // The SusFS reboot handler recognises the second magic 0xFAFAFAFA,
    // executes SHOW_VERSION, writes the version string and sets err = 0.
    {
        susfs::version_cmd v2;
        memset(&v2, 0, sizeof(v2));
        v2.err = susfs::ERR_CMD_NOT_SUPPORTED;  // preset 255
        g_sigsys_hit_ = false;
        syscall(SYS_reboot,
                static_cast<unsigned int>(susfs::OPTION_MAGIC),
                susfs::REBOOT_MAGIC2,
                static_cast<unsigned long>(susfs::CMD_SHOW_VERSION),
                &v2);
        if (!g_sigsys_hit_ && v2.err == 0) {
            v2.susfs_version[susfs::VERSION_STR_LEN - 1] = '\0';
            result.detected = true;
            result.abi = SusfsAbi::RebootV2;
            result.version = v2.susfs_version;
            result.detail = "reboot-magic handshake (susfs v2 ABI)";
            return result;
        }
    }

    // Phase 2 — v1.5.3 - v1.5.12 prctl ABI:
    //   prctl(0xDEADBEEF, SHOW_VERSION, buf, NULL, &error)
    // The SusFS prctl hook recognises option 0xDEADBEEF, executes
    // SHOW_VERSION, writes the version string and sets error = 0.
    {
        char ver_buf[susfs::VERSION_STR_LEN];
        memset(ver_buf, 0, sizeof(ver_buf));
        int error = susfs::PRCTL_ERR_UNSUPPORTED;  // preset -1
        prctl(static_cast<int>(susfs::OPTION_MAGIC),
              static_cast<unsigned long>(susfs::CMD_SHOW_VERSION),
              ver_buf, NULL, &error);
        if (error == 0) {
            ver_buf[susfs::VERSION_STR_LEN - 1] = '\0';
            result.detected = true;
            result.abi = SusfsAbi::Prctl;
            result.version = ver_buf;
            result.detail = "prctl handshake (susfs v1 ABI)";
            return result;
        }
    }

    // No fallback: neither ABI executed SHOW_VERSION -> SusFS is absent.
    return result;
}

void Detector::probe_variants(DetectResult& out) {
    if (!out.susfs.detected) return;
    out.susfs_detected = true;
    // Attribute the finding to whichever root solution is active.
    if (out.ksu.present)       out.susfs_source = "kernelsu";
    else if (out.magisk.present) out.susfs_source = "magisk";
    else                       out.susfs_source = "kernel";

    // Backfill the variant flags on the matching solution result.
    if (out.ksu.present) {
        out.ksu.susfs_detected = true;
        out.ksu.susfs_detail = out.susfs.detail;
        out.ksu.variant = out.ksu.variant | KsuVariant::SusFS;
    }
    if (out.magisk.present) out.magisk.has_susfs = true;
}

void Detector::probe_jailbreak(DetectResult& out) {
    JailbreakHint& jb = out.jailbreak;
    FILE* fp = popen("getprop ro.debuggable 2>/dev/null", "r");
    if (fp) { char val[16]={0}; if (fgets(val, sizeof(val), fp) && atoi(val)==1) jb.indicators.push_back("ro.debuggable=1"); pclose(fp); }
    fp = popen("getprop ro.boot.verifiedbootstate 2>/dev/null", "r");
    if (fp) { char val[32]={0}; if (fgets(val, sizeof(val), fp) && (strstr(val,"orange")||strstr(val,"yellow"))) jb.indicators.push_back("verified_boot_state=orange/yellow"); pclose(fp); }
    fp = popen("getprop ro.build.type 2>/dev/null", "r");
    if (fp) { char val[32]={0}; if (fgets(val, sizeof(val), fp) && (strstr(val,"userdebug")||strstr(val,"eng"))) jb.indicators.push_back("build_type=userdebug/eng"); pclose(fp); }
    fp = popen("getprop ro.build.tags 2>/dev/null", "r");
    if (fp) { char val[64]={0}; if (fgets(val, sizeof(val), fp) && strstr(val,"test-keys")) jb.indicators.push_back("build_tags=test-keys"); pclose(fp); }
    fp = fopen("/sys/fs/selinux/enforce", "r");
    if (fp) { int enforce=1; if (fscanf(fp,"%d",&enforce)==1 && enforce==0) jb.indicators.push_back("selinux=permissive"); fclose(fp); }
    struct stat st;
    if (stat("/data/data/de.robv.android.xposed.installer",&st)==0 || stat("/system/framework/XposedBridge.jar",&st)==0 || stat("/system/framework/edxp",&st)==0)
        jb.indicators.push_back("xposed-framework");
    jb.detected = !jb.indicators.empty();
}

DetectResult Detector::run_all() {
    DetectResult result;
    result.ksu = probe_ksu();
    result.ap = probe_apatch();
    result.magisk = probe_magisk();
    result.susfs = probe_susfs();
    probe_variants(result);
    probe_jailbreak(result);
    int count = 0;
    if (result.ksu.present) count++;
    if (result.ap.present) count++;
    if (result.magisk.present) count++;
    if (count > 1) result.type = KernelType::Mixed;
    else if (result.ksu.present) result.type = KernelType::KernelSU;
    else if (result.ap.present) result.type = KernelType::KernelPatch;
    else if (result.magisk.present) result.type = KernelType::Magisk;
    else result.type = KernelType::None;
    return result;
}

} // namespace ksu_detector
