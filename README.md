# ksu-detect

通过 `prctl` 私有命令探测设备内核侧是否存在 **KernelSU** 或 **KernelPatch(APatch)**，并打印版本号。

## 原理

| 方案 | prctl cmd | 宏 |
| --- | --- | --- |
| KernelSU | `0x4B535500` (`KSU\0`) | `KSU_MAGIC` |
| KernelPatch / APatch | `0x4B505443` (`KPTC`) | `KPATCH_MAGIC` |

`prctl` 返回值 `>= 0` 即表示对应方案存在，返回值为版本号。

## 输出示例

```text
[+] KernelSU found, ver:10998
[-] KernelPatch(APatch) not found
```

## 下载

- CI 每次构建都会产出各 ABI 二进制，见仓库 **Actions** 页面对应的 workflow run → Artifacts。
- 打 `v*` tag（如 `v1.0.0`）会自动创建 Release 并附带全部 ABI 压缩包。

## 使用

```bash
adb push ksu-detect_arm64-v8a /data/local/tmp/ksu-detect
adb shell chmod +x /data/local/tmp/ksu-detect
adb shell /data/local/tmp/ksu-detect
```

> 探测内核接口通常需要 root。普通 shell 下可能始终显示 not found，请在 root 环境运行。

## 自行编译（Android NDK + Make）

需要 Android NDK（建议 r26+）。

```bash
# 默认 arm64-v8a
make NDK_HOME=/path/to/android-ndk

# 指定 ABI：arm64-v8a / armeabi-v7a / x86_64
make NDK_HOME=/path/to/android-ndk ABI=arm64-v8a

# 一次编译全部 ABI
make all-abis NDK_HOME=/path/to/android-ndk

# 本机调试（使用系统 cc，仅验证可编译/运行）
make host
```

产物输出到 `build/ksu-detect_<ABI>`。

## CI

`.github/workflows/build.yml`：

- push / PR / tag / 手动触发；
- 安装 NDK r26d，使用 Make 交叉编译三个 ABI；
- 校验产物为对应 ELF，上传 Artifact；
- `v*` tag 时自动打包并发布 Release。
