// SPDX-License-Identifier: GPL-3.0-or-later
//
// ksu-detect-cpp — Manager-level KernelSU / APatch / Magisk detector
// with GKI, SusFS, Zygisk, and jailbreak variant analysis.
//
// Detection semantics:
//   - <solution>.present = true  →  the solution IS RUNNING right now
//                                   (KSU: driver fd + GET_INFO ok;
//                                    Magisk: daemon handshake ok;
//                                    APatch: SUPERCALL_HELLO answered)
//   - traces (zygisk, su binary, modules)  →  leftover / hint only,
//                                              NOT proof of active root
//   - KSU kernel_compromised  →  kernel has been tampered with (same as
//                                present=true conceptually, but explicit)
//
// Usage:
//   ksu-detect-cpp                        # auto-detect active root solution
//   ksu-detect-cpp -j                     # JSON output
//   ksu-detect-cpp --verbose              # detailed output
//

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <vector>

#include <nlohmann/json.hpp>

#include "detector.hpp"
#include "ksu_uapi.hpp"
#include "magisk_uapi.hpp"

using namespace ksu_detector;
using json = nlohmann::json;

static void print_usage(const char* prog) {
    printf("Usage: %s [options]\n", prog);
    printf("  -j, --json             Output results as JSON\n");
    printf("  -v, --verbose          Verbose output\n");
    printf("  -h, --help             Show this help\n");
}

static const char* kernel_type_str(KernelType t) {
    switch (t) {
        case KernelType::Unknown:    return "unknown";
        case KernelType::None:       return "none";
        case KernelType::KernelSU:   return "kernelsu";
        case KernelType::KernelPatch: return "kernelpatch";
        case KernelType::Magisk:     return "magisk";
        case KernelType::Mixed:      return "mixed";
    }
    return "unknown";
}

static const char* ksu_priv_str(KsuPrivLevel p) {
    switch (p) {
        case KsuPrivLevel::None:          return "none";
        case KsuPrivLevel::User:          return "user";
        case KsuPrivLevel::ManagerOrRoot: return "manager_or_root";
        case KsuPrivLevel::Manager:       return "manager";
        case KsuPrivLevel::Root:          return "root";
    }
    return "none";
}

static const char* magisk_priv_str(MagiskPrivLevel p) {
    switch (p) {
        case MagiskPrivLevel::None:       return "none";
        case MagiskPrivLevel::Unconfirmed:return "unconfirmed";
        case MagiskPrivLevel::DaemonOnly: return "daemon_only";
        case MagiskPrivLevel::Su:         return "su";
        case MagiskPrivLevel::Manager:    return "manager";
    }
    return "none";
}

static const char* susfs_abi_str(SusfsAbi a) {
    switch (a) {
        case SusfsAbi::None:     return "none";
        case SusfsAbi::Prctl:    return "prctl";      // susfs v1.5.3 - v1.5.12
        case SusfsAbi::RebootV2: return "reboot_v2";  // susfs v2.0.0+
    }
    return "unknown";
}

static void print_human(const DetectResult& r, bool verbose) {
    printf("=== Manager-Level Root Detection ===\n\n");

    // === KernelSU ===
    printf("[KernelSU]\n");
    if (r.ksu.present) {
        printf("  Present     : yes\n");
        printf("  Version     : %u\n", r.ksu.version);
        printf("  UAPI        : %u\n", r.ksu.uapi_version);
        printf("  Mode        : %s\n", r.ksu.mode_str.c_str());
        printf("  Flags       : 0x%08x\n", r.ksu.flags);
        if (verbose) {
            printf("  Features    : %u\n", r.ksu.features);
            printf("    LKM       : %s\n", (r.ksu.flags & ksu::GET_INFO_FLAG_LKM) ? "yes" : "no");
            printf("    Manager   : %s\n", (r.ksu.flags & ksu::GET_INFO_FLAG_MANAGER) ? "yes" : "no");
            printf("    Late-load : %s\n", (r.ksu.flags & ksu::GET_INFO_FLAG_LATE_LOAD) ? "yes" : "no");
            printf("    PR build  : %s\n", (r.ksu.flags & ksu::GET_INFO_FLAG_PR_BUILD) ? "yes" : "no");
            printf("    Bundled   : %s\n", (r.ksu.flags & ksu::GET_INFO_FLAG_BUNDLED) ? "yes" : "no");
        }
        printf("  Priv level  : %s\n", ksu_priv_str(r.ksu.priv_level));
        if (r.ksu.manager_appid.has_value())
            printf("  Manager UID : u0_a%u (appid %u)\n", r.ksu.manager_appid.value(), r.ksu.manager_appid.value());
        if (has_ksu_variant(r.ksu.variant, KsuVariant::GKI)) printf("  [Variant]   GKI mode (LKM on GKI kernel)\n");
        if (has_ksu_variant(r.ksu.variant, KsuVariant::LateLoad)) printf("  [Variant]   Late-load mode\n");
        if (r.ksu.susfs_detected) printf("  [Variant]   SusFS detected (%s)\n", r.ksu.susfs_detail.c_str());
        if (r.ksu.kernel_compromised) printf("  [Jailbreak] : yes - kernel tampered by KSU (%s)\n", r.ksu.compromise_reason.c_str());
        if (r.ksu.priv_level == KsuPrivLevel::Manager) printf("  [✓] MANAGER-LEVEL CONFIRMED: caller matches manager UID\n");
        else if (r.ksu.priv_level == KsuPrivLevel::Root) printf("  [✓] ROOT-LEVEL: running as uid 0 (full access)\n");
        else if (r.ksu.priv_level == KsuPrivLevel::ManagerOrRoot) printf("  [✓] PRIVILEGED: manager_or_root ioctls accessible\n");
        else printf("  [i] User-level only; kernel is jailbroken but we have no elevated privileges\n");
    } else {
        printf("  Present     : no (kernel layer)\n");
        printf("  [Jailbreak]  : no (no KSU driver fd / no kprobe hook)\n");
    }
    printf("\n");

    // === APatch ===
    printf("[APatch / KernelPatch]\n");
    if (r.ap.present) {
        printf("  Present     : yes (SUPERCALL_HELLO answered)\n");
        printf("  KP version  : %u (0x%08x)\n", r.ap.kp_version, r.ap.kp_version);
        printf("  K version   : %u (0x%08x)\n", r.ap.kernel_version, r.ap.kernel_version);
        if (r.ap.su_uid_count.has_value()) printf("  SU UIDs     : %ld\n", r.ap.su_uid_count.value());
        if (r.ap.kpm_count.has_value()) printf("  KPM modules : %ld\n", r.ap.kpm_count.value());
        if (r.ap.safemode.has_value()) printf("  Safe mode   : %s\n", r.ap.safemode.value() ? "on" : "off");
        printf("  [✓] APATCH KERNEL MODULE RUNNING\n");
    } else {
        printf("  Present     : no\n");
    }
    printf("\n");

    // === Magisk ===
    printf("[Magisk / Zygisk]\n");
    if (r.magisk.present) {
        printf("  Present     : yes (daemon running, handshake confirmed)\n");
        if (!r.magisk.version_str.empty()) printf("  Version     : %s\n", r.magisk.version_str.c_str());
        if (r.magisk.version_code > 0) printf("  Version code: %u (%d.%d)\n", r.magisk.version_code, magisk::version_major(r.magisk.version_code), magisk::version_minor(r.magisk.version_code));
        if (!r.magisk.socket_path.empty()) printf("  Socket      : %s\n", r.magisk.socket_path.c_str());
        printf("  Priv level  : %s\n", magisk_priv_str(r.magisk.priv_level));
        if (r.magisk.priv_level == MagiskPrivLevel::Manager) printf("  [✓] MANAGER-LEVEL: manager app identity confirmed\n");
        else if (r.magisk.priv_level == MagiskPrivLevel::Su) printf("  [✓] SU ACCESS: root shell available\n");
        else if (r.magisk.priv_level == MagiskPrivLevel::DaemonOnly) printf("  [✓] DAEMON HANDSHAKE: magiskd socket responded to version query\n");
    } else {
        printf("  Present     : no (daemon not reachable)\n");
    }
    bool has_traces = r.magisk.has_zygisk || r.magisk.su_binary_detected || r.magisk.has_shamiko || r.magisk.has_lsposed || r.magisk.has_magiskhide || r.magisk.has_susfs || r.magisk.is_kitsune || r.magisk.is_alpha;
    if (has_traces) {
        printf("  Traces      :");
        if (r.magisk.has_zygisk) printf(" Zygisk");
        if (r.magisk.su_binary_detected) printf(" su-binary");
        if (r.magisk.has_shamiko) printf(" Shamiko");
        if (r.magisk.has_susfs) printf(" SusFS");
        if (r.magisk.has_lsposed) printf(" LSPosed");
        if (r.magisk.has_magiskhide) printf(" MagiskHide");
        if (r.magisk.is_kitsune) printf(" Kitsune/Delta");
        if (r.magisk.is_alpha) printf(" Alpha");
        printf("\n");
        if (r.magisk.su_binary_detected) printf("  su binary   : %s\n", r.magisk.su_binary_path.c_str());
        if (!r.magisk.present) printf("  Note        : traces found but magiskd daemon not running/reachable\n");
    }
    printf("\n");

    // === SusFS (independent kernel-level handshake) ===
    printf("[SusFS]\n");
    if (r.susfs.detected) {
        printf("  Present     : yes (kernel handshake confirmed)\n");
        printf("  Version     : %s\n", r.susfs.version.c_str());
        printf("  ABI         : %s\n", susfs_abi_str(r.susfs.abi));
        if (r.susfs.abi == SusfsAbi::Prctl)    printf("                (susfs v1.5.3 - v1.5.12 prctl interface)\n");
        if (r.susfs.abi == SusfsAbi::RebootV2) printf("                (susfs v2.0.0+ reboot interface)\n");
        printf("  Handshake   : %s\n", r.susfs.detail.c_str());
        if (!r.susfs_source.empty()) printf("  Paired with : %s\n", r.susfs_source.c_str());
        printf("  [✓] SUSFS INTERFACE CONFIRMED: kernel executed SHOW_VERSION\n");
    } else {
        printf("  Present     : no\n");
        printf("  Status      : no SusFS syscall interface answered (SHOW_VERSION failed)\n");
    }
    printf("\n");
    if (r.jailbreak.detected) {
        printf("[Jailbreak / Compromise Indicators]\n");
        for (const auto& ind : r.jailbreak.indicators) printf("  - %s\n", ind.c_str());
        printf("\n");
    }

    printf("=== Summary ===\n");
    printf("  Detected    : %s\n", kernel_type_str(r.type));
    if (r.type == KernelType::None) {
        if (!r.jailbreak.detected) printf("  Conclusion  : No active root detected\n");
        else printf("  Hints       : %zu jailbreak indicators (not kernel-active)\n", r.jailbreak.indicators.size());
    } else if (r.type == KernelType::Mixed) {
        printf("  Note        : Multiple root solutions detected (confirmed active)\n");
    }
}

static void print_json(const DetectResult& r) {
    json out;
    out["detected"] = kernel_type_str(r.type);

    // === KernelSU ===
    {
        json k;
        k["present"] = r.ksu.present;
        if (r.ksu.present) {
            k["version"] = r.ksu.version;
            k["uapi_version"] = r.ksu.uapi_version;
            k["flags"] = r.ksu.flags;
            k["features"] = r.ksu.features;
            k["mode"] = r.ksu.mode_str;
            k["priv_level"] = ksu_priv_str(r.ksu.priv_level);
            if (r.ksu.manager_appid.has_value())
                k["manager_appid"] = r.ksu.manager_appid.value();
            k["is_manager"] =
                static_cast<bool>(r.ksu.flags & ksu::GET_INFO_FLAG_MANAGER);
            k["is_lkm"] =
                static_cast<bool>(r.ksu.flags & ksu::GET_INFO_FLAG_LKM);
            k["is_late_load"] =
                static_cast<bool>(r.ksu.flags & ksu::GET_INFO_FLAG_LATE_LOAD);
            k["is_gki"] =
                has_ksu_variant(r.ksu.variant, KsuVariant::GKI);
            k["kernel_compromised"] = r.ksu.kernel_compromised;
            k["compromise_reason"] = r.ksu.compromise_reason;
            k["has_susfs"] = r.ksu.susfs_detected;
        }
        out["kernelsu"] = std::move(k);
    }

    // === APatch ===
    {
        json a;
        a["present"] = r.ap.present;
        if (r.ap.present) {
            a["kp_version"] = r.ap.kp_version;
            a["kernel_version"] = r.ap.kernel_version;
            if (r.ap.su_uid_count.has_value())
                a["su_uid_count"] = r.ap.su_uid_count.value();
            if (r.ap.kpm_count.has_value())
                a["kpm_count"] = r.ap.kpm_count.value();
            if (r.ap.safemode.has_value())
                a["safemode"] = r.ap.safemode.value();
        }
        out["apatch"] = std::move(a);
    }

    // === Magisk ===
    {
        json m;
        m["present"] = r.magisk.present;
        m["priv_level"] = magisk_priv_str(r.magisk.priv_level);
        m["version_code"] = r.magisk.version_code;
        m["version_str"] = r.magisk.version_str;
        m["socket_path"] = r.magisk.socket_path;
        m["has_zygisk"] = r.magisk.has_zygisk;
        m["has_shamiko"] = r.magisk.has_shamiko;
        m["has_susfs"] = r.magisk.has_susfs;
        m["has_lsposed"] = r.magisk.has_lsposed;
        m["has_magiskhide"] = r.magisk.has_magiskhide;
        m["is_kitsune"] = r.magisk.is_kitsune;
        m["is_alpha"] = r.magisk.is_alpha;
        m["su_binary_detected"] = r.magisk.su_binary_detected;
        m["su_binary_path"] = r.magisk.su_binary_path;
        out["magisk"] = std::move(m);
    }

    // === SusFS (independent kernel-level handshake) ===
    {
        json s;
        s["present"] = r.susfs.detected;
        if (r.susfs.detected) {
            s["version"] = r.susfs.version;
            s["abi"] = susfs_abi_str(r.susfs.abi);
            s["detail"] = r.susfs.detail;
            s["paired_with"] = r.susfs_source;
        }
        out["susfs"] = std::move(s);
    }

    // === Jailbreak ===
    {
        json j;
        j["detected"] = r.jailbreak.detected;
        j["indicators"] = r.jailbreak.indicators;
        out["jailbreak"] = std::move(j);
    }

    std::cout << out.dump(2) << std::endl;
}

int main(int argc, char** argv) {
    bool json_output = false;
    bool verbose = false;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-j" || arg == "--json") { json_output = true; }
        else if (arg == "-v" || arg == "--verbose") { verbose = true; }
        else if (arg == "-h" || arg == "--help") { print_usage(argv[0]); return 0; }
        else { fprintf(stderr, "Unknown option: %s\n", arg.c_str()); print_usage(argv[0]); return 1; }
    }
    Detector detector;
    DetectResult result = detector.run_all();
    if (json_output) print_json(result);
    else print_human(result, verbose);
    return (result.type != KernelType::None) ? 0 : 1;
}
