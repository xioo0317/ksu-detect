#define _GNU_SOURCE
/*
 * ksu-detect — 判定设备当前是 KernelSU 还是 KernelPatch(APatch) 在工作
 *
 * 检测分两层：
 *
 *  [内核层 · 权威]
 *   KernelSU (新版, main):
 *       kprobe hook reboot。reboot(MAGIC1=0xDEADBEEF, MAGIC2=0xCAFEBABE,
 *                                  0, &fd) 会返回一个 driver fd，
 *       再 ioctl(fd, KSU_IOCTL_GET_INFO) 得到版本/标志。
 *   KernelSU (老版):
 *       prctl(0x4B535500, "KSU") 直接返回版本号。作为 fallback。
 *   KernelPatch / APatch:
 *       hook 第 45 号系统调用(truncate) 作为 "supercall"。
 *       syscall(45, key, ver|0x1158|HELLO[0x1000]) 成功返回 0x11581158。
 *       需要正确的 superkey(或调用方是已授权 root 的 uid)。
 *       无有效 key 时内核直接放行真正的 truncate，因此无法无 key 判定。
 *
 *  [文件指纹层 · 无需 root 的兜底]
 *       KernelSU:  /data/adb/ksud, /data/adb/ksu/
 *       APatch:    /data/adb/apd,  /data/adb/ap/
 *
 * 用法:
 *   ksu-detect                    自动检测(无 key 时只能给出文件指纹结论)
 *   ksu-detect -k <superkey>      用 superkey 精确判定 APatch
 *   或环境变量 AP_SUPERKEY=<key>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <ucontext.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

/* ---- KernelSU ---- */
#define KSU_LEGACY_MAGIC      0x4B535500u   /* prctl, 老版本 KernelSU */
#define KSU_INSTALL_MAGIC1    0xDEADBEEFu   /* reboot arg1 */
#define KSU_INSTALL_MAGIC2    0xCAFEBABEu   /* reboot arg2 */

/* GET_INFO: _IOR('K', 2, struct ksu_get_info_cmd) */
struct ksu_get_info_cmd {
    uint32_t version;
    uint32_t flags;
    uint32_t features;
    uint32_t uapi_version;
};
#define KSU_IOCTL_GET_INFO   _IOR('K', 2, struct ksu_get_info_cmd)

#define KSU_GET_INFO_FLAG_LKM        (1u << 0)
#define KSU_GET_INFO_FLAG_LATE_LOAD  (1u << 2)

/* ---- KernelPatch / APatch ---- */
#define __NR_supercall        45            /* arm64/arm/x86 上 hook truncate */
#define SUPERCALL_HELLO       0x1000
#define SUPERCALL_HELLO_MAGIC 0x11581158u

static volatile sig_atomic_t g_sigsys_hit = 0;

/* reboot 魔法被 seccomp 拦截时内核会发 SIGSYS；接住并让该调用返回 -EPERM */
static void sigsys_handler(int sig, siginfo_t *si, void *ctx) {
    (void)sig;
    if (!si || si->si_code != 1 /* SYS_SECCOMP */) return;
    g_sigsys_hit = 1;
#if defined(__aarch64__)
    ucontext_t *uc = (ucontext_t *)ctx;
    uc->uc_mcontext.regs[0] = (uint64_t)(-EPERM);
#elif defined(__x86_64__)
    ucontext_t *uc = (ucontext_t *)ctx;
    uc->uc_mcontext.gregs[REG_RAX] = (long)(-EPERM);
#else
    (void)ctx;
#endif
}

static void install_sigsys(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigsys_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, NULL);
}

/* 新版 KernelSU：reboot 魔法取 driver fd，ioctl 取信息。成功返回 1 */
static int probe_ksu_new(struct ksu_get_info_cmd *info) {
    int fd = -1;
    g_sigsys_hit = 0;
    /* reboot(magic1, magic2, cmd=0, arg=&fd)；4 参数走裸 syscall */
    long r = syscall(SYS_reboot, KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, &fd);
    if (g_sigsys_hit) return 0;            /* 被 seccomp 拦了，不是 KSU 通道 */
    if (r < 0) return 0;
    if (fd < 0) return 0;

    memset(info, 0, sizeof(*info));
    if (ioctl(fd, KSU_IOCTL_GET_INFO, info) < 0) {
        close(fd);
        return 0;
    }
    close(fd);
    return info->version != 0;
}

/* 老版 KernelSU：prctl。返回版本号(>=0)，-1 表示不存在 */
static long probe_ksu_legacy(void) {
    return prctl(KSU_LEGACY_MAGIC, 0, 0, 0, 0);
}

/* APatch HELLO。返回 1 表示命中(HELLO_MAGIC)，0 表示未确认 */
static int probe_apatch(const char *key) {
    if (!key || !key[0]) return 0;

    /* ver_and_cmd：高32位放版本(这里给0，内核当前不校验)，
       中间16位固定 0x1158，低16位放 HELLO 命令 */
    long ver_cmd = ((long)0 << 32) | ((long)0x1158 << 16) | (SUPERCALL_HELLO & 0xFFFF);

    long ret = syscall(__NR_supercall, key, ver_cmd);
    return (uint32_t)ret == SUPERCALL_HELLO_MAGIC;
}

static int file_exists(const char *p) {
    return access(p, F_OK) == 0;
}

int main(int argc, char **argv) {
    const char *key = getenv("AP_SUPERKEY");

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) && i + 1 < argc) {
            key = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-k|--key <superkey>]\n", argv[0]);
            printf("       or set env AP_SUPERKEY\n");
            return 0;
        }
    }

    install_sigsys();

    /* ---- 内核层 ---- */
    struct ksu_get_info_cmd info;
    int ksu_new = probe_ksu_new(&info);
    long ksu_legacy = ksu_new ? -1 : probe_ksu_legacy();
    int ap = probe_apatch(key);

    if (ksu_new) {
        const char *mode = (info.flags & KSU_GET_INFO_FLAG_LATE_LOAD) ? "late-load"
                         : (info.flags & KSU_GET_INFO_FLAG_LKM)       ? "lkm"
                         : "built-in";
        printf("[+] KernelSU active (kernel)\n");
        printf("    version=%u mode=%s uapi=%u\n",
               info.version, mode, info.uapi_version);
    } else if (ksu_legacy >= 0) {
        printf("[+] KernelSU active (legacy prctl)\n");
        printf("    version=%ld\n", ksu_legacy);
    } else {
        printf("[-] KernelSU not found (kernel)\n");
    }

    if (ap) {
        printf("[+] KernelPatch/APatch active (kernel)\n");
    } else if (key && key[0]) {
        printf("[-] KernelPatch/APatch not found (kernel, key provided)\n");
    } else {
        printf("[?] KernelPatch/APatch unconfirmed (no superkey)\n");
    }

    /* ---- 文件指纹层 ---- */
    int ksu_fp = file_exists("/data/adb/ksud") || file_exists("/data/adb/ksu");
    int ap_fp  = file_exists("/data/adb/apd")  || file_exists("/data/adb/ap");
    printf("[i] Filesystem: KernelSU=%s APatch=%s\n",
           ksu_fp ? "yes" : "no", ap_fp ? "yes" : "no");

    /* ---- 总结 ---- */
    int kernel_hit = ksu_new || ksu_legacy >= 0 || ap;
    if (!kernel_hit) {
        if (ksu_fp && !ap_fp) {
            printf("==> Likely KernelSU (filesystem hint; run as root to confirm)\n");
        } else if (ap_fp && !ksu_fp) {
            printf("==> Likely KernelPatch/APatch (filesystem hint; provide superkey to confirm)\n");
        } else if (ap_fp && ksu_fp) {
            printf("==> Both footprints present; run as root / with superkey to decide\n");
        } else {
            printf("==> No KernelSU / APatch detected\n");
        }
    }
    return 0;
}
