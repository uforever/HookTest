# HookTest

一个 Xposed 模块（兼容 LSPosed），用于 **Java 层加密算法自吐**（自动打印密钥、明文、密文）和 **Native 层 SSL 明文抓包**（hook `libssl.so` 的 `SSL_read` / `SSL_write`）。适合用于 Android 逆向分析、协议分析和安全研究。

模块描述：`Java层算法自吐 SSL抓包`

## 功能特性

### Java 层算法自吐（HookTest.java）

通过 `XposedHelpers.findAndHookMethod` / `XposedBridge.hookAllMethods` hook 以下 JCA/JCE 核心 API，在调用前后打印密钥与数据（raw / hex / base64 三种格式）：

| 类 | Hook 的方法 | 打印内容 |
|---|---|---|
| `java.security.MessageDigest` | `update()`（byte / byte[] / byte[]+off+len / ByteBuffer 四种重载）、`digest()`（两种重载） | 算法、Provider、摘要输入、摘要输出 |
| `java.security.Signature` | `initSign()`、`initVerify()`（PublicKey / Certificate 两种重载）、`update()`（三种重载）、`sign()`（两种重载）、`verify()`（两种重载） | 签名算法、私钥/公钥/证书、签名输入输出、验签结果 |
| `javax.crypto.Cipher` | `chooseProvider()`（覆盖所有 `init()` 入口，批量 hook）、`doFinal()`（七种重载） | 加解密模式、算法、密钥、IV、明文、密文 |
| `javax.crypto.Mac` | `init()`、`update()`（四种重载）、`doFinal()` | 算法、Provider、HMAC 密钥、输入输出 |

其他行为：

- **应用过滤**：跳过 `com.miui.*` 和 `com.zhang3.*` 包名的进程，其余应用全部生效。
- **加固兼容**：hook `Application.attach`，在回调中更新 `ClassLoader`，以适配带壳（加固）应用运行时切换 ClassLoader 的场景。
- **防重复 Hook**：使用 `alreadyHooked` 标志保证每个进程只执行一次 hook 注册。
- 代码中保留了若干被注释掉的 hook 示例，可按需启用：
  - `com.android.org.conscrypt.NativeCrypto.SSL_read/SSL_write`（Java 层 SSL 抓包）
  - `KeyGenerator.generateKey()` / `KeyPairGenerator.generateKeyPair()`（密钥生成）
- 内置 `testOnce()` 方法，可一次性触发 MD5/SHA/AES/RSA/HMAC 全流程，便于验证 hook 效果。

### Native 层 SSL 抓包（myposedmod.cpp）

基于 LSPosed 的 Native API（`native_init` 入口，见 `assets/native_init`），在模块 so 被加载的最早期执行：

1. 通过 `dlopen`/`dlsym` 定位系统 `libssl.so` 中的 `SSL_read`、`SSL_write`。
2. 解析 `/proc/self/maps`，分别获取 `/apex/com.android.conscrypt/lib` 与 `/system/lib` 下 `libssl.so` 的基址，**按基址差值换算出应用实际使用的 conscrypt 版 libssl 中的函数地址**（应用流量实际走 conscrypt 的 libssl，直接 hook 系统 libssl 无效）。
3. 使用 LSPosed 提供的 `hook_func`（inline hook）替换 `SSL_read` / `SSL_write`，在调用后以 `__android_log_print` 打印收发的 SSL 明文。

代码中同样保留了注释掉的示例：`fopen`/`dlopen` hook、JNI `FindClass` hook、库加载回调 `on_library_loaded` 中按库名动态 hook。

## 项目结构

```
app/src/main/
├── assets/
│   ├── xposed_init              # Xposed 入口类声明：com.zhang3.myposedmod.HookTest
│   └── native_init              # Native 模块入口声明（LSPosed native API）
├── cpp/
│   ├── CMakeLists.txt           # Native 构建脚本，编译 libmyposedmod.so
│   ├── hooknative.h             # LSPosed Native API 类型定义
│   └── myposedmod.cpp           # SSL_read/SSL_write inline hook 实现
├── java/com/zhang3/myposedmod/
│   └── HookTest.java            # Java 层加密算法 hook 实现
└── AndroidManifest.xml          # xposedmodule / xposedminversion / xposedscope 元数据
```

## 环境要求

- Android Studio + NDK（CMake 3.22.1）
- AGP 8.7.3，compileSdk 34，minSdk 24，Java 11
- 已 root 并安装 [LSPosed](https://github.com/LSPosed/LSPosed)（或其他兼容 Xposed API 82+ 的框架）的设备或模拟器

## 构建

```bash
# 直接使用 Gradle 构建
./gradlew assembleRelease
```

或在 Android Studio 中直接运行 Build。产物位于 `app/release/app-release.apk`。

## 安装与使用

1. 安装 APK 到已安装 LSPosed 框架的设备：

   ```bash
   adb install app-release.apk
   ```

2. 在 LSPosed 管理器中启用本模块，并勾选作用域应用（默认作用域为 `com.xiaojianbang.app`，可在 `app/src/main/res/values/arrays.xml` 的 `xposedscope` 数组中修改，支持填写多个包名）。

3. 强制停止并重新启动目标应用，触发加密操作或 HTTPS 请求。

4. 查看日志（所有输出统一使用 TAG `HookTest`）：

   ```bash
   adb logcat -s HookTest
   ```

## 日志输出示例

Java 层（Cipher）：

```
[*] javax.crypto.Cipher.init() onEnter
- op mode: ENCRYPT_MODE
- algorithm: AES
- key(base64): tWP0dGHq5TkOZ1mSLIMa8A==
- iv(base64): 9Xa7Lb7DmuFdRmfqlEqKdA==

[*] javax.crypto.Cipher.doFinal() onLeave
- output(base64): 3b0J...（密文）
```

Native 层（SSL）：

```
[*] libssl SSL_write called with
GET /api HTTP/1.1
Host: example.com
...

[*] libssl SSL_read called with
HTTP/1.1 200 OK
...
```

> 说明：日志中的数据同时以 raw / hex / base64 输出，二进制数据请以 base64/hex 为准。

## 工作原理

- **模块识别**：`AndroidManifest.xml` 中声明 `xposedmodule`、`xposedminversion`（53）、`xposedscope` 等元数据，LSPosed 据此识别并在作用域应用进程启动时回调 `IXposedHookLoadPackage.handleLoadPackage()`。
- **Java 层**：由于 `MessageDigest`、`Cipher`、`Mac`、`Signature` 等类挂在 boot classpath 上，hook 它们可覆盖目标应用绝大部分 Java 加密调用；`Cipher.chooseProvider` 是所有 `Cipher.init(...)` 重载的公共收敛点，因此用 `hookAllMethods` 一次覆盖。
- **Native 层**：目标应用的 TLS 流量实际由 `/apex/com.android.conscrypt/lib` 下的 `libssl.so` 处理，而非 `/system/lib` 下的副本。模块通过两个映射基址的差值，把 `dlsym` 得到的系统 libssl 符号地址换算为 conscrypt libssl 中的对应地址，再用 LSPosed 的 `hook_func` 完成 inline hook。
- **Native 加载时机**：`handleLoadPackage` 中调用 `System.loadLibrary("myposedmod")` 加载 so；so 内导出 `native_init` 符号，LSPosed 会在更早阶段（zygote spec 加载阶段）直接加载并调用它以获取 native hook 能力。

## 免责声明

本项目仅供学习与安全研究用途，请勿用于任何违法用途。使用本项目产生的一切后果由使用者自行承担。
