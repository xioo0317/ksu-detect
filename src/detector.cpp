// SPDX-License-Identifier: GPL-3.0-or-later
//
// Manager-level detector implementation for KernelSU, APatch,
// Magisk (with Zygisk / SusFS / variants), and jailbreak hints.
//

#include "detector.hpp"
#include "ksu_uapi.hpp"
#include "apatch_uapi.hpp"
#include "magisk_uapi.hpp"

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

static bool check_proc_susfs() {
    return access("/proc/sys/kernel/susfs_version", F_OK) == 0 ||
           access("/proc/sys/kernel/susfs_booting", F_OK) == 0 ||
           access("/proc/sys/kernel/susfs_magisk_sulist", F_OK) == 0;
}

static bool check_module_susfs() {
    return access("/sys/module/susfs", F_OK) == 0;
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
            if (check_proc_susfs() || check_module_susfs()) {
                result.susfs_detected = true;
                result.variant = result.variant | KsuVariant::SusFS;
                result.susfs_detail = "kernel-level (proc/sys/module)";
            } else if (access("/data/adb/ksu/modules/susfs", F_OK) == 0) {
                result.susfs_detected = true;
                result.variant = result.variant | KsuVariant::SusFS;
                result.susfs_detail = "module-installed (not active)";
            }
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
    FILE* f = fopen("/proc/net/unix", "r");
    if (!f) return false;
    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return false; }
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        char* path_str = strchr(line, '@');
        if (!path_str) continue;
        size_t len = strlen(path_str);
        while (len > 0 && (path_str[len-1] == '\n' || path_str[len-1] == ' ')) path_str[--len] = '\0';
        if (strstr(path_str, "magiskd") != nullptr) { out_path = path_str; found = true; break; }
    }
    fclose(f);
    if (!found) {
        struct stat st;
        if (stat(magisk::LEGACY_SOCKET_PATH, &st) == 0 && S_ISSOCK(st.st_mode)) { out_path = magisk::LEGACY_SOCKET_PATH; found = true; }
    }
    return found;
}

bool Detector::magisk_probe_daemon(const std::string& socket_path, uint32_t& out_version_code, std::string& out_version_str) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return false;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    bool is_abstract = (socket_path[0] == '@');
    if (is_abstract) {
        addr.sun_path[0] = '\0';
        size_t name_len = socket_path.size() - 1;
        if (name_len > sizeof(addr.sun_path) - 1) name_len = sizeof(addr.sun_path) - 1;
        memcpy(addr.sun_path + 1, socket_path.c_str() + 1, name_len);
    } else {
        strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
    }
    socklen_t addr_len = sizeof(addr.sun_family) + (is_abstract ? socket_path.size() : strlen(addr.sun_path) + 1);
    if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), addr_len) < 0) { close(sock); return false; }
    uint32_t req[2]; req[0] = 5; req[1] = 0;
    ssize_t w = write(sock, req, sizeof(req));
    if (w != sizeof(req)) { close(sock); return false; }
    int32_t resp_code = -1;
    ssize_t r = read(sock, &resp_code, sizeof(resp_code));
    if (r != sizeof(resp_code) || resp_code < 0) { close(sock); return false; }
    uint32_t payload_len = 0;
    r = read(sock, &payload_len, sizeof(payload_len));
    if (r == sizeof(payload_len) && payload_len > 0 && payload_len < 4096) {
        std::vector<char> buf(payload_len + 1, 0);
        ssize_t total = 0;
        while (total < static_cast<ssize_t>(payload_len)) {
            ssize_t n = read(sock, buf.data() + total, payload_len - total);
            if (n <= 0) break;
            total += n;
        }
        out_version_str = std::string(buf.data());
        const char* p = strstr(buf.data(), "(");
        if (p) out_version_code = static_cast<uint32_t>(atoi(p + 1));
    }
    close(sock);
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
    result.has_zygisk = magisk_check_zygisk();
    if (result.has_zygisk) { result.zygisk_detected = true; result.zygisk_detail = "maps-scan"; }
    std::string su_path;
    if (magisk_check_su_binary(su_path)) { result.su_binary_detected = true; result.su_binary_path = su_path; }
    if (result.present || result.su_binary_detected || result.has_zygisk) {
        result.has_shamiko = magisk_check_module("shamiko");
        result.has_lsposed = magisk_check_module("lsposed") || magisk_check_module("zygisk_lsposed") || magisk_check_module("riru_lsposed");
        result.has_magiskhide = magisk_check_module("magiskhide");
        result.is_kitsune = magisk_check_kitsune();
        result.is_alpha = magisk_check_alpha();
        if (check_proc_susfs() || check_module_susfs()) result.has_susfs = true;
    }
    return result;
}

void Detector::probe_variants(DetectResult& out) {
    if (out.ksu.susfs_detected) { out.susfs_detected = true; out.susfs_source = "kernelsu"; }
    else if (out.magisk.has_susfs) { out.susfs_detected = true; out.susfs_source = "magisk"; }
    else if (check_proc_susfs() || check_module_susfs()) { out.susfs_detected = true; out.susfs_source = "kernel"; }
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
