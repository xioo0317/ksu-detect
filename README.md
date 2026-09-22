# ksu-detect

判定设备当前是 **KernelSU** 还是 **KernelPatch(APatch)** 在工作。基于对三个官方仓库（[KernelSU](https://github.com/tiann/KernelSU)、[APatch](https://github.com/bmax121/APatch)、[KernelPatch](https://github.com/bmax121/KernelPatch)）源码的分析实现，分两层检测。

## 检测逻辑

### 内核层（权威）

| 方案 | 机制 | 判定 |
| --- | --- | --- |
| KernelSU（新版 main） | kprobe hook `reboot`：`reboot(0xDEADBEEF, 0xCAFEBABE, 0, &fd)` 返回 driver fd | `ioctl(fd, KSU_IOCTL_GET_INFO)` 得到版本/模式 |
| KernelSU（老版） | `prctl(0x4B535500)` | 返回值为版本号（fallback） |
| KernelPatch / APatch | hook 第 45 号系统调用（`truncate`）做 supercall | HELLO 命令返回 `0x11581158` |

> ⚠️ **重要前提**
> - KernelSU 的 reboot 魔法在普通内核上因 magic1 不匹配只会返回 `EINVAL`，**不会真重启**；被 seccomp 拦截时通过 SIGSYS 处理器安全返回。
> - APatch 的 supercall **需要正确的 superkey**（或调用 uid 已被授予 root）。源码 `common/supercall.c` 的 `before()` 中，无有效 key 时直接放行真正的 `truncate`，所以**没有 key 时系统调用层无法判定 APatch**。
> - 内核层探测一般需要 **root**。

### 文件指纹层（无需 root 兜底）

- KernelSU：`/data/adb/ksud`、`/data/adb/ksu/`
- APatch：`/data/adb/apd`、`/data/adb/ap/`

内核层没命中时，用文件指纹给出 "Likely ..." 提示。

## 用法

```bash
# 自动检测（无 key 时 APatch 只能给文件指纹结论）
./ksu-detect

# 用 superkey 精确判定 APatch
./ksu-detect -k <your_superkey>

# 或用环境变量
AP_SUPERKEY=<key> ./ksu-detect
```

输出示例：

```text
[+] KernelSU active (kernel)
    version=12559 mode=built-in uapi=4
[?] KernelPatch/APatch unconfirmed (no superkey)
[i] Filesystem: KernelSU=yes APatch=no
```

部署到设备：

```bash
adb push ksu-detect_arm64-v8a /data/local/tmp/ksu-detect
adb shell chmod +x /data/local/tmp/ksu-detect
adb shell su -c /data/local/tmp/ksu-detect
```

## 下载

- CI 每次构建产出各 ABI 二进制：仓库 **Actions** 页面 → 对应 run → Artifacts。
- 打 `v*` tag（如 `v1.0.0`）会自动创建 Release。

## 自行编译（Android NDK + Make）

需要 NDK（建议 r26+）。

```bash
make NDK_HOME=/path/to/android-ndk                 # 默认 arm64-v8a
make NDK_HOME=/path/to/android-ndk ABI=armeabi-v7a
make all-abis NDK_HOME=/path/to/android-ndk        # 全部 ABI
make host                                          # 本机调试
```

产物在 `build/ksu-detect_<ABI>`。

## CI

`.github/workflows/build.yml`：push/PR/tag/手动触发 → 装 NDK r26d → make 编译 arm64-v8a / armeabi-v7a / x86_64 → 校验 ELF → 上传 Artifact；`v*` tag 自动发 Release。
