// SPDX-License-Identifier: GPL-3.0-or-later
//
// ksu-detect-cpp — Manager-level KernelSU / APatch detector
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

#include "detector.hpp"
#include "ksu_uapi.hpp"

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
        case KernelType::Both:       return "both";
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

static void print_human(const DetectResult& r, bool verbose) {
    printf("=== Manager-Level Kernel Root Detection ===\n\n");

    // KernelSU section
    printf("[KernelSU]\n");
    if (r.ksu.present) {
        printf("  Present     : yes\n");
        printf("  Version     : %u\n", r.ksu.version);
        printf("  UAPI        : %u\n", r.ksu.uapi_version);
        printf("  Mode        : %s\n", r.ksu.mode_str.c_str());
        printf("  Flags       : 0x%08x\n", r.ksu.flags);
        if (verbose) {
            printf("  Features    : %u\n", r.ksu.features);
            // Decode flag bits
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
        // Manager-level verification
        if (r.ksu.priv_level == KsuPrivLevel::Manager) {
            printf("  [✓] MANAGER-LEVEL CONFIRMED: caller matches manager UID\n");
        } else if (r.ksu.priv_level == KsuPrivLevel::Root) {
            printf("  [✓] ROOT-LEVEL: running as uid 0 (full access)\n");
        } else if (r.ksu.priv_level == KsuPrivLevel::ManagerOrRoot) {
            printf("  [✓] PRIVILEGED: manager_or_root ioctls accessible\n");
        } else {
            printf("  [i] User-level only; use su or run as manager to get full access\n");
        }
    } else {
        printf("  Present     : no (kernel layer)\n");
    }
    printf("\n");

    // APatch section
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
        // Manager-level verification
        if (r.ap.priv_level == ApPrivLevel::SuperKey) {
            printf("  [✓] SUPERKEY CONFIRMED: full manager-level access\n");
        } else if (r.ap.priv_level == ApPrivLevel::SuList) {
            printf("  [✓] SU-LIST ACCESS: caller is on allow list (uid-elevated)\n");
        }
    } else {
        printf("  Present     : no\n");
        if (r.ap.priv_level == ApPrivLevel::Unconfirmed) {
            printf("  Status      : unconfirmed (no superkey available)\n");
            printf("                Use -k <superkey> for kernel-level verification.\n");
        }
    }
    printf("\n");

    // Filesystem section
    printf("[Filesystem Fingerprints]\n");
    printf("  KernelSU    : %s\n", r.ksu_filesystem_hint ? "yes" : "no");
    printf("  APatch      : %s\n", r.ap_filesystem_hint ? "yes" : "no");
    printf("\n");

    // Summary
    printf("=== Summary ===\n");
    printf("  Detected    : %s\n", kernel_type_str(r.type));

    if (r.type == KernelType::None) {
        if (r.ksu_filesystem_hint && !r.ap_filesystem_hint) {
            printf("  Hint        : KernelSU filesystem traces found (not kernel-active)\n");
        } else if (r.ap_filesystem_hint && !r.ksu_filesystem_hint) {
            printf("  Hint        : APatch filesystem traces found (not kernel-active)\n");
        } else if (r.ksu_filesystem_hint && r.ap_filesystem_hint) {
            printf("  Hint        : Both filesystem traces present\n");
        } else {
            printf("  Conclusion  : No kernel root detected\n");
        }
    }
}

static void print_json(const DetectResult& r) {
    printf("{\n");
    printf("  \"detected\": \"%s\",\n", kernel_type_str(r.type));

    // KernelSU
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
        printf("    \"is_late_load\": %s\n",
               (r.ksu.flags & ksu::GET_INFO_FLAG_LATE_LOAD) ? "true" : "false");
    } else {
        printf("\n");
    }
    printf("  },\n");

    // APatch
    printf("  \"apatch\": {\n");
    printf("    \"present\": %s,\n", r.ap.present ? "true" : "false");
    if (r.ap.present) {
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
        printf("    \"priv_level\": \"%s\"\n", ap_priv_str(r.ap.priv_level));
    }
    printf("  },\n");

    // Filesystem
    printf("  \"filesystem\": {\n");
    printf("    \"kernelsu\": %s,\n", r.ksu_filesystem_hint ? "true" : "false");
    printf("    \"apatch\": %s\n", r.ap_filesystem_hint ? "true" : "false");
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

    // Exit code: 0 = detected something, 1 = nothing detected
    return (result.type != KernelType::None) ? 0 : 1;
}
