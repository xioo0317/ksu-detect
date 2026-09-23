// SPDX-License-Identifier: GPL-3.0-or-later
//
// ksu-detect-cpp — Manager-level KernelSU / APatch / Magisk detector
// with GKI, SusFS, Zygisk, and jailbreak variant analysis.
//
// Detection semantics:
//   - <solution>.present = true  →  the solution IS RUNNING right now
//                                   (KSU: driver fd + GET_INFO ok;
//                                    Magisk: daemon handshake ok;
//                                    APatch: hello probe ok)
//   - traces (zygisk, su binary, modules)  →  leftover / hint only,
//                                              NOT proof of active root
//   - KSU kernel_compromised  →  kernel has been tampered with (same as
//                                present=true conceptually, but explicit)
//
// Usage:
//   ksu-detect-cpp                        # auto-detect, try to find superkey
//   ksu-detect-cpp -k <superkey>          # provide APatch superkey
//   ksu-detect-cpp -j                     # JSON output
//   ksu-detect-cpp --verbose              # detailed output
//
// Environment:
//   AP_SUPERKEY=<key>    # fallback superkey

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <vector>

#include "detector.hpp"
#include "ksu_uapi.hpp"
#include "magisk_uapi.hpp"

using namespace ksu_detector;

static void print_usage(const char* prog) {
    printf("Usage: %s [options]\n", prog);
    printf("  -k, --key <superkey>   APatch superkey for kernel-level detection\n");
    printf("  -j, --json             Output results as JSON\n");
    printf("  -v, --verbose          Verbose output\n");
    printf("  -h, --help             Show this help\n");
    printf("\n");
    printf("Environment variables:\n");
    printf("  AP_SUPERKEY            Fallback APatch superkey\n");
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

static const char* ap_priv_str(ApPrivLevel p) {
    switch (p) {
        case ApPrivLevel::None:        return "none";
        case ApPrivLevel::Unconfirmed: return "unconfirmed";
        case ApPrivLevel::SuList:      return "su_list";
        case ApPrivLevel::SuperKey:    return "superkey";
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

// ---------------------------------------------------------------------------
// Human-readable output
// ---------------------------------------------------------------------------

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
            printf("    Manager   : %s (caller is manager UID)\n",
                   (r.ksu.flags & ksu::GET_INFO_FLAG_MANAGER) ? "yes" : "no");
            printf("    Late-load : %s\n",
                   (r.ksu.flags & ksu::GET_INFO_FLAG_LATE_LOAD) ? "yes" : "no");
            printf("    PR build  : %s\n",
                   (r.ksu.flags & ksu::GET_INFO_FLAG_PR_BUILD) ? "yes" : "no");
            printf("    Bundled   : %s\n",
                   (r.ksu.flags & ksu::GET_INFO_FLAG_BUNDLED) ? "yes" : "no");
        }
        printf("  Priv level  : %s\n", ksu_priv_str(r.ksu.priv_level));
        if (r.ksu.manager_appid.has_value()) {
            printf("  Manager UID : u0_a%u (appid %u)\n",
                   r.ksu.manager_appid.value(),
                   r.ksu.manager_appid.value());
        }

        // Variant info
        if (has_ksu_variant(r.ksu.variant, KsuVariant::GKI)) {
            printf("  [Variant]   GKI mode (LKM on GKI kernel)\n");
        }
        if (has_ksu_variant(r.ksu.variant, KsuVariant::LateLoad)) {
            printf("  [Variant]   Late-load mode\n");
        }
        if (r.ksu.susfs_detected) {
            printf("  [Variant]   SusFS detected (%s)\n", r.ksu.susfs_detail.c_str());
        }

        // Jailbreak / compromise assessment
        //   The very fact that we can get a driver fd + call GET_INFO
        //   means the kernel has been tampered with = device is jailbroken.
        //   Priv level tells us *how much access we personally have*,
        //   not whether the device is compromised.
        if (r.ksu.kernel_compromised) {
            printf("  [Jailbreak] : yes - kernel tampered by KSU (%s)\n",
                   r.ksu.compromise_reason.c_str());
        }

        // Manager-level verification
        if (r.ksu.priv_level == KsuPrivLevel::Manager) {
            printf("  [\u2713] MANAGER-LEVEL CONFIRMED: caller matches manager UID\n");
        } else if (r.ksu.priv_level == KsuPrivLevel::Root) {
            printf("  [\u2713] ROOT-LEVEL: running as uid 0 (full access)\n");
        } else if (r.ksu.priv_level == KsuPrivLevel::ManagerOrRoot) {
            printf("  [\u2713] PRIVILEGED: manager_or_root ioctls accessible\n");
        } else {
            printf("  [i] User-level only; kernel is jailbroken but we have no elevated privileges\n");
        }
    } else {
        printf("  Present     : no (kernel layer)\n");
        printf("  [Jailbreak]  : no (no KSU driver fd / no kprobe hook)\n");
    }
    printf("\n");

    // === APatch ===
    printf("[APatch / KernelPatch]\n");
    if (r.ap.present) {
        printf("  Present     : yes\n");
        printf("  KP version  : %u (0x%08x)\n", r.ap.kp_version, r.ap.kp_version);
        printf("  K version   : %u (0x%08x)\n", r.ap.kernel_version, r.ap.kernel_version);
        printf("  Priv level  : %s\n", ap_priv_str(r.ap.priv_level));
        if (!r.ap.detected_key_source.empty()) {
            printf("  Key source  : %s\n", r.ap.detected_key_source.c_str());
        }
        if (r.ap.su_uid_count.has_value()) {
            printf("  SU UIDs     : %ld\n", r.ap.su_uid_count.value());
        }
        if (r.ap.kpm_count.has_value()) {
            printf("  KPM modules : %ld\n", r.ap.kpm_count.value());
        }
        if (r.ap.safemode.has_value()) {
            printf("  Safe mode   : %s\n", r.ap.safemode.value() ? "on" : "off");
        }
        if (r.ap.priv_level == ApPrivLevel::SuperKey) {
            printf("  [\u2713] SUPERKEY CONFIRMED: full manager-level access\n");
        } else if (r.ap.priv_level == ApPrivLevel::SuList) {
            printf("  [\u2713] SU-LIST ACCESS: caller is on allow list (uid-elevated)\n");
        }
    } else {
        printf("  Present     : no\n");
        if (r.ap.priv_level == ApPrivLevel::Unconfirmed) {
            printf("  Status      : unconfirmed (no superkey available)\n");
            printf("                Use -k <superkey> for kernel-level verification.\n");
        }
    }
    printf("\n");

    // === Magisk ===
    printf("[Magisk / Zygisk]\n");
    if (r.magisk.present) {
        printf("  Present     : yes (daemon running, handshake confirmed)\n");
        if (!r.magisk.version_str.empty()) {
            printf("  Version     : %s\n", r.magisk.version_str.c_str());
        }
        if (r.magisk.version_code > 0) {
            printf("  Version code: %u (%d.%d)\n",
                   r.magisk.version_code,
                   magisk::version_major(r.magisk.version_code),
                   magisk::version_minor(r.magisk.version_code));
        }
        if (!r.magisk.socket_path.empty()) {
            printf("  Socket      : %s\n", r.magisk.socket_path.c_str());
        }
        printf("  Priv level  : %s\n", magisk_priv_str(r.magisk.priv_level));

        // Privilege level confirmation
        if (r.magisk.priv_level == MagiskPrivLevel::Manager) {
            printf("  [\u2713] MANAGER-LEVEL: manager app identity confirmed\n");
        } else if (r.magisk.priv_level == MagiskPrivLevel::Su) {
            printf("  [\u2713] SU ACCESS: root shell available\n");
        } else if (r.magisk.priv_level == MagiskPrivLevel::DaemonOnly) {
            printf("  [\u2713] DAEMON HANDSHAKE: magiskd socket responded to version query\n");
        }
    } else {
        printf("  Present     : no (daemon not reachable)\n");
    }

    // Traces / modules - always shown, regardless of daemon status
    // These are NOT proof that Magisk is running right now.
    bool has_traces = r.magisk.has_zygisk || r.magisk.su_binary_detected ||
                      r.magisk.has_shamiko || r.magisk.has_lsposed ||
                      r.magisk.has_magiskhide || r.magisk.has_susfs ||
                      r.magisk.is_kitsune || r.magisk.is_alpha;
    if (has_traces) {
        printf("  Traces      :");
        if (r.magisk.has_zygisk)         printf(" Zygisk");
        if (r.magisk.su_binary_detected) printf(" su-binary");
        if (r.magisk.has_shamiko)        printf(" Shamiko");
        if (r.magisk.has_susfs)          printf(" SusFS");
        if (r.magisk.has_lsposed)        printf(" LSPosed");
        if (r.magisk.has_magiskhide)     printf(" MagiskHide");
        if (r.magisk.is_kitsune)         printf(" Kitsune/Delta");
        if (r.magisk.is_alpha)           printf(" Alpha");
        printf("\n");
        if (r.magisk.su_binary_detected) {
            printf("  su binary   : %s\n", r.magisk.su_binary_path.c_str());
        }
        if (!r.magisk.present) {
            printf("  Note        : traces found but magiskd daemon not running/reachable\n");
        }
    }
    printf("\n");

    // === Filesystem ===
    printf("[Filesystem Fingerprints]\n");
    printf("  KernelSU    : %s\n", r.ksu_filesystem_hint ? "yes" : "no");
    printf("  APatch      : %s\n", r.ap_filesystem_hint ? "yes" : "no");
    printf("  Magisk      : %s\n", r.magisk_filesystem_hint ? "yes" : "no");
    printf("\n");

    // === Global Variant Summary ===
    if (r.susfs_detected) {
        printf("[Global: SusFS]\n");
        printf("  Detected via: %s\n", r.susfs_source.c_str());
        printf("\n");
    }

    // === Jailbreak Hints ===
    if (r.jailbreak.detected) {
        printf("[Jailbreak / Compromise Indicators]\n");
        for (const auto& ind : r.jailbreak.indicators) {
            printf("  - %s\n", ind.c_str());
        }
        printf("\n");
    }

    // === Summary ===
    printf("=== Summary ===\n");
    printf("  Detected    : %s\n", kernel_type_str(r.type));

    if (r.type == KernelType::None) {
        int hints = 0;
        if (r.ksu_filesystem_hint) hints++;
        if (r.ap_filesystem_hint) hints++;
        if (r.magisk_filesystem_hint) hints++;

        if (hints == 0 && !r.jailbreak.detected) {
            printf("  Conclusion  : No active root detected\n");
        } else {
            printf("  Hints       : ");
            if (r.ksu_filesystem_hint) printf("KernelSU traces ");
            if (r.ap_filesystem_hint)  printf("APatch traces ");
            if (r.magisk_filesystem_hint) printf("Magisk traces ");
            if (r.jailbreak.detected) printf("%zu jailbreak indicators ",
                                              r.jailbreak.indicators.size());
            printf("(not kernel-active)\n");
        }
    } else if (r.type == KernelType::Mixed) {
        printf("  Note        : Multiple root solutions detected (confirmed active)\n");
    }
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

static void print_json(const DetectResult& r) {
    printf("{\n");
    printf("  \"detected\": \"%s\",\n", kernel_type_str(r.type));

    // ---- KernelSU ----
    printf("  \"kernelsu\": {\n");
    printf("    \"present\": %s", r.ksu.present ? "true" : "false");
    if (r.ksu.present) {
        printf(",\n");
        printf("    \"version\": %u,\n", r.ksu.version);
        printf("    \"uapi_version\": %u,\n", r.ksu.uapi_version);
        printf("    \"flags\": %u,\n", r.ksu.flags);
        printf("    \"features\": %u,\n", r.ksu.features);
        printf("    \"mode\": \"%s\",\n", r.ksu.mode_str.c_str());
        printf("    \"priv_level\": \"%s\",\n", ksu_priv_str(r.ksu.priv_level));
        if (r.ksu.manager_appid.has_value()) {
            printf("    \"manager_appid\": %u,\n", r.ksu.manager_appid.value());
        }
        printf("    \"is_manager\": %s,\n",
               (r.ksu.flags & ksu::GET_INFO_FLAG_MANAGER) ? "true" : "false");
        printf("    \"is_lkm\": %s,\n",
               (r.ksu.flags & ksu::GET_INFO_FLAG_LKM) ? "true" : "false");
        printf("    \"is_late_load\": %s,\n",
               (r.ksu.flags & ksu::GET_INFO_FLAG_LATE_LOAD) ? "true" : "false");
        printf("    \"is_gki\": %s,\n",
               has_ksu_variant(r.ksu.variant, KsuVariant::GKI) ? "true" : "false");
        printf("    \"kernel_compromised\": %s,\n",
               r.ksu.kernel_compromised ? "true" : "false");
        printf("    \"compromise_reason\": \"%s\",\n",
               r.ksu.compromise_reason.c_str());
        printf("    \"has_susfs\": %s", r.ksu.susfs_detected ? "true" : "false");
    } else {
        printf("\n");
    }
    printf("\n  },\n");

    // ---- APatch ----
    printf("  \"apatch\": {\n");
    printf("    \"present\": %s,", r.ap.present ? "true" : "false");
    if (r.ap.present) {
        printf("\n");
        printf("    \"kp_version\": %u,\n", r.ap.kp_version);
        printf("    \"kernel_version\": %u,\n", r.ap.kernel_version);
        printf("    \"priv_level\": \"%s\",\n", ap_priv_str(r.ap.priv_level));
        printf("    \"key_source\": \"%s\",\n", r.ap.detected_key_source.c_str());
        if (r.ap.su_uid_count.has_value()) {
            printf("    \"su_uid_count\": %ld,\n", r.ap.su_uid_count.value());
        }
        if (r.ap.kpm_count.has_value()) {
            printf("    \"kpm_count\": %ld,\n", r.ap.kpm_count.value());
        }
        if (r.ap.safemode.has_value()) {
            printf("    \"safemode\": %ld\n", r.ap.safemode.value());
        }
    } else {
        printf("\n    \"priv_level\": \"%s\"\n", ap_priv_str(r.ap.priv_level));
    }
    printf("  },\n");

    // ---- Magisk ----
    printf("  \"magisk\": {\n");
    printf("    \"present\": %s,\n", r.magisk.present ? "true" : "false");
    printf("    \"priv_level\": \"%s\",\n", magisk_priv_str(r.magisk.priv_level));
    printf("    \"version_code\": %u,\n", r.magisk.version_code);
    printf("    \"version_str\": \"%s\",\n", r.magisk.version_str.c_str());
    printf("    \"socket_path\": \"%s\",\n", r.magisk.socket_path.c_str());
    printf("    \"has_zygisk\": %s,\n", r.magisk.has_zygisk ? "true" : "false");
    printf("    \"has_shamiko\": %s,\n", r.magisk.has_shamiko ? "true" : "false");
    printf("    \"has_susfs\": %s,\n", r.magisk.has_susfs ? "true" : "false");
    printf("    \"has_lsposed\": %s,\n", r.magisk.has_lsposed ? "true" : "false");
    printf("    \"has_magiskhide\": %s,\n", r.magisk.has_magiskhide ? "true" : "false");
    printf("    \"is_kitsune\": %s,\n", r.magisk.is_kitsune ? "true" : "false");
    printf("    \"is_alpha\": %s,\n", r.magisk.is_alpha ? "true" : "false");
    printf("    \"su_binary_detected\": %s,\n", r.magisk.su_binary_detected ? "true" : "false");
    printf("    \"su_binary_path\": \"%s\"", r.magisk.su_binary_path.c_str());
    printf("\n  },\n");

    // ---- Filesystem ----
    printf("  \"filesystem\": {\n");
    printf("    \"kernelsu\": %s,\n", r.ksu_filesystem_hint ? "true" : "false");
    printf("    \"apatch\": %s,\n", r.ap_filesystem_hint ? "true" : "false");
    printf("    \"magisk\": %s\n", r.magisk_filesystem_hint ? "true" : "false");
    printf("  },\n");

    // ---- Variants ----
    printf("  \"variants\": {\n");
    printf("    \"susfs_detected\": %s,\n", r.susfs_detected ? "true" : "false");
    printf("    \"susfs_source\": \"%s\"\n", r.susfs_source.c_str());
    printf("  },\n");

    // ---- Jailbreak ----
    printf("  \"jailbreak\": {\n");
    printf("    \"detected\": %s,\n", r.jailbreak.detected ? "true" : "false");
    printf("    \"indicators\": [");
    for (size_t i = 0; i < r.jailbreak.indicators.size(); i++) {
        printf("\"%s\"", r.jailbreak.indicators[i].c_str());
        if (i + 1 < r.jailbreak.indicators.size()) printf(", ");
    }
    printf("]\n");
    printf("  }\n");

    printf("}\n");
}

int main(int argc, char** argv) {
    std::string superkey;
    bool json_output = false;
    bool verbose = false;

    // Check environment
    const char* env_key = getenv("AP_SUPERKEY");
    if (env_key) superkey = env_key;

    // Parse args
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if ((arg == "-k" || arg == "--key") && i + 1 < argc) {
            superkey = argv[++i];
        } else if (arg == "-j" || arg == "--json") {
            json_output = true;
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", arg.c_str());
            print_usage(argv[0]);
            return 1;
        }
    }

    Detector detector;
    if (!superkey.empty()) {
        detector.set_ap_superkey(superkey);
    }

    DetectResult result = detector.run_all();

    if (json_output) {
        print_json(result);
    } else {
        print_human(result, verbose);
    }

    // Exit code: 0 = detected something active, 1 = nothing active
    return (result.type != KernelType::None) ? 0 : 1;
}
