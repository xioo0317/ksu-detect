/*
 * KernelSU / KernelPatch(APatch) detector
 *
 * 通过 prctl 私有 cmd 探测内核侧接口是否存在：
 *   KSU_MAGIC    0x4B535500  ("KSU\0")  KernelSU
 *   KPATCH_MAGIC 0x4B505443  ("KPTC")   KernelPatch / APatch
 *
 * 返回值 >= 0 表示对应方案存在，并给出版本号。
 */
#include <stdio.h>
#include <sys/prctl.h>

#define KSU_MAGIC    0x4B535500
#define KPATCH_MAGIC 0x4B505443

int main(void) {
    unsigned long ksu_ver = prctl(KSU_MAGIC, 0, 0, 0, 0);
    unsigned long kp_ver  = prctl(KPATCH_MAGIC, 0, 0, 0, 0);

    if ((long)ksu_ver >= 0) {
        printf("[+] KernelSU found, ver:%lu\n", ksu_ver);
    } else {
        printf("[-] KernelSU not found\n");
    }

    if ((long)kp_ver >= 0) {
        printf("[+] KernelPatch(APatch) found, ver:%lu\n", kp_ver);
    } else {
        printf("[-] KernelPatch(APatch) not found\n");
    }

    return 0;
}
