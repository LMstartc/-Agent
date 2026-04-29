# Game Engine Reverse & Security Analysis Agent

一个面向**游戏引擎逆向分析**与**本地静态安全审计**的 Python Agent。

该工具主要用于对游戏目录、客户端二进制、引擎资产包、脚本文件进行批量摸底分析，帮助快速识别游戏所使用的引擎、关键文件、可疑 API、反调试特征、网络通信特征、动态加载行为以及潜在的安全风险点。

> 本项目仅用于授权环境下的安全研究、逆向学习、漏洞分析和合规审计。  
> 不包含反作弊绕过、外挂注入、进程篡改、攻击利用或恶意持久化逻辑。

---

## 1. 项目定位

在游戏逆向或安全分析开始前，通常需要先回答几个问题：

- 这个游戏使用了什么引擎？
- 关键二进制文件在哪里？
- 是否是 Unity IL2CPP、Mono、Unreal Pak、Godot PCK 等结构？
- 哪些文件值得优先逆向？
- 是否存在反调试、反虚拟机、驱动通信、动态加载、网络通信等敏感特征？
- 是否存在高熵文件、加密/压缩资产包或疑似混淆内容？
- 如何快速生成一份可复查的分析报告？

本 Agent 的作用就是完成这些**前期自动化摸底工作**。

它不是反编译器，也不是调试器，而是一个用于快速归类、打标签、生成报告的静态分析入口工具。

---

## 2. 核心功能

### 2.1 文件递归扫描

支持扫描单个文件或整个游戏目录：

- 普通二进制文件
- Windows PE 文件：`.exe`、`.dll`、`.sys`
- Linux/Android ELF 文件：`.so`
- Unity 相关文件
- Unreal 相关文件
- Godot 相关文件
- Cocos2d-x 相关脚本和二进制
- APK / IPA / ZIP 类归档文件
- 配置文件、脚本文件、日志文件

默认会跳过一些大型缓存目录，例如：

- `.git`
- `node_modules`
- Unity `Library`
- Unreal `DerivedDataCache`
- Unreal `Saved`
- `Temp`
- `BuildCache`

可以通过参数关闭默认忽略规则。

---

### 2.2 游戏引擎识别

目前内置以下引擎指纹规则：

| 引擎 | 典型识别特征 |
|---|---|
| Unity | `UnityPlayer.dll`、`GameAssembly.dll`、`global-metadata.dat`、`libil2cpp.so`、`Assembly-CSharp.dll`、`.assets` |
| Unreal Engine | `.pak`、`.ucas`、`.utoc`、`AssetRegistry.bin`、`UE4Game.exe`、`/Script/Engine` |
| Godot | `project.godot`、`data.pck`、`res://`、`.gd`、`.tscn` |
| Cocos2d-x | `cocos2d`、`libcocos2dcpp.so`、`main.lua`、`.luac`、`.jsc` |
| Source-like | `engine.dll`、`client.dll`、`server.dll`、`tier0.dll`、`.vpk` |

扫描完成后会给每个引擎打分，用于判断目标游戏更可能属于哪种引擎生态。

---

### 2.3 字符串提取

支持提取：

- ASCII 字符串
- UTF-16LE 字符串

用于识别：

- API 名称
- DLL 名称
- 网络 URL
- 引擎关键字
- 调试字符串
- 反调试关键词
- 脚本路径
- 资源路径
- 可疑功能名

默认每个文件最多扫描 32 MB 字节内容，可通过参数调整。

---

### 2.4 PE 文件分析

如果安装了 `pefile`，可以对 Windows PE 文件进行解析：

- Machine 类型
- 编译时间戳
- ImageBase
- EntryPoint
- Section 信息
- Section 熵值
- Import Table
- Export Table
- 安全目录信息
- Overlay 大小
- .NET/CLR 特征判断

这对分析 Windows 游戏客户端、Unity `GameAssembly.dll`、Unreal 游戏主程序、插件 DLL 等文件很有用。

---

### 2.5 ELF 文件分析

如果安装了 `pyelftools`，可以对 ELF 文件进行解析：

- ELF 位数
- Endianness
- Machine 类型
- EntryPoint
- Section 信息
- 动态导入符号
- 动态导出符号
- 依赖库 `DT_NEEDED`

这对 Android 游戏、Linux 游戏、Unity Android `libil2cpp.so`、`libunity.so`、Native 插件分析很有用。

---

### 2.6 风险规则匹配

内置多类静态安全规则。

#### Windows 注入 / 远程内存操作

示例特征：

- `OpenProcess`
- `VirtualAllocEx`
- `WriteProcessMemory`
- `ReadProcessMemory`
- `CreateRemoteThread`
- `NtCreateThreadEx`
- `QueueUserAPC`
- `SetWindowsHookEx`

命中后不代表一定恶意，需要结合上下文判断。

---

#### 驱动 / 内核交互

示例特征：

- `DeviceIoControl`
- `CreateFileW`
- `\\.\`
- `NtLoadDriver`
- `ZwLoadDriver`
- `MmCopyVirtualMemory`
- `PsLookupProcessByProcessId`
- `ObRegisterCallbacks`
- `PsSetLoadImageNotifyRoutine`

适合发现游戏客户端、反作弊组件、保护模块中可能存在的驱动交互逻辑。

---

#### 反调试 / 反虚拟机

示例特征：

- `IsDebuggerPresent`
- `CheckRemoteDebuggerPresent`
- `NtQueryInformationProcess`
- `BeingDebugged`
- `ProcessDebugPort`
- `rdtsc`
- `cpuid`
- `VMware`
- `VirtualBox`
- `Microsoft Hv`
- `ptrace`
- `TracerPid`

适合快速定位保护逻辑、调试器检测、虚拟机检测相关代码。

---

#### 动态加载

示例特征：

- `LoadLibraryA`
- `LoadLibraryW`
- `GetProcAddress`
- `dlopen`
- `dlsym`

适合分析运行时插件加载、动态符号解析、延迟加载逻辑。

---

#### 网络通信

示例特征：

- `WinHttpOpen`
- `WinHttpSendRequest`
- `InternetOpenA`
- `HttpSendRequest`
- `WSAStartup`
- `socket`
- `connect`
- `send`
- `recv`
- `UnityWebRequest`
- `WebSocket`

适合定位登录、上报、补丁更新、遥测、反作弊通信等网络模块。

---

#### 加密 / 混淆 / 壳

示例特征：

- `AES`
- `RSA`
- `RC4`
- `SHA256`
- `BCryptEncrypt`
- `CryptEncrypt`
- `UPX`
- `Themida`
- `VMProtect`
- `Obfuscator`

适合定位资源加密、通信加密、代码保护、壳保护相关内容。

---

## 3. 安装方法

### 3.1 基础环境

要求：

```bash
python --version
```

建议使用：

```text
Python 3.9+
```

---

### 3.2 安装依赖

最小运行不强制依赖第三方库，但建议安装完整依赖：

```bash
pip install pefile pyelftools rich
```

依赖说明：

| 依赖 | 作用 |
|---|---|
| `pefile` | 解析 Windows PE 文件 |
| `pyelftools` | 解析 Linux / Android ELF 文件 |
| `rich` | 显示更好看的终端进度条和日志 |

---

## 4. 使用方法

### 4.1 扫描游戏目录

```bash
python ge_security_agent.py scan ./GameFolder --out report.md --json report.json
```

输出：

- `report.md`：Markdown 报告
- `report.json`：JSON 原始结构化报告

---

### 4.2 扫描单个文件

```bash
python ge_security_agent.py scan ./GameAssembly.dll --out gameassembly_report.md
```

适合分析：

- Unity `GameAssembly.dll`
- Unity `libil2cpp.so`
- Unreal 主程序
- Native 插件 DLL/SO
- 可疑模块

---

### 4.3 深度扫描

```bash
python ge_security_agent.py scan ./GameFolder --deep --out deep_report.md --json deep_report.json
```

`--deep` 会自动调整：

- 启用大文件分析
- 提高字符串扫描大小
- 提高最大字符串提取数量

适合对完整游戏目录做更细的摸底。

---

### 4.4 扫描大文件

默认会跳过超过 `--max-file-mb` 的文件。

如果要强制扫描大文件：

```bash
python ge_security_agent.py scan ./GameFolder --include-large --max-file-mb 1024
```

---

### 4.5 扫描所有文件类型

默认只分析常见的二进制、脚本、配置、资产包等文件。

如果要扫描所有文件：

```bash
python ge_security_agent.py scan ./GameFolder --all-files
```

---

### 4.6 多线程扫描

```bash
python ge_security_agent.py scan ./GameFolder --workers 4
```

适合文件数量较多的目录。

---

## 5. 参数说明

| 参数 | 说明 |
|---|---|
| `target` | 要扫描的文件或目录 |
| `--out` | Markdown 报告输出路径 |
| `--json` | JSON 报告输出路径 |
| `--max-file-mb` | 单文件大小限制，默认 256 MB |
| `--include-large` | 不跳过大文件 |
| `--string-scan-mb` | 每个文件用于字符串扫描的最大大小，默认 32 MB |
| `--max-strings` | 每个文件最多提取的字符串数量 |
| `--all-files` | 扫描所有后缀文件 |
| `--deep` | 深度扫描模式 |
| `--workers` | 并发扫描线程数 |
| `--ignore-dir` | 额外忽略的目录名，可重复指定 |
| `--no-ignore` | 禁用默认忽略目录 |
| `--no-progress` | 禁用进度条 |
| `--verbose` | 输出详细日志 |

---

## 6. 报告结构

生成的 Markdown 报告主要包含以下部分：

```text
Game Engine Reverse & Security Analysis Report
├── Summary
├── Engine Fingerprint Scores
├── Finding Severity Counts
├── Top Rule Hits
├── Prioritized Files
└── Review Guidance
```

---

### 6.1 Summary

包含扫描统计信息：

- 扫描根目录
- 开始时间
- 结束时间
- 发现文件数
- 实际分析文件数
- 跳过文件数
- 分析总字节数

---

### 6.2 Engine Fingerprint Scores

展示引擎识别分数，例如：

```text
Unity: 42
Unreal Engine: 8
Godot: 0
```

分数越高，代表目标越可能属于对应引擎生态。

---

### 6.3 Finding Severity Counts

按风险等级统计规则命中数量：

- `high`
- `medium`
- `low`

注意：这里的风险等级只是静态分析优先级，不代表实际漏洞等级。

---

### 6.4 Prioritized Files

报告会按优先级列出值得分析的文件。

排序依据包括：

- 是否命中高风险规则
- 是否具有明显引擎特征
- 是否是 PE / ELF 文件
- 是否是重要资产包
- 文件大小
- 熵值

---

## 7. 典型分析流程

### 7.1 Unity IL2CPP 游戏

建议流程：

1. 扫描整个游戏目录
2. 查看报告中的 Unity 分数
3. 重点关注：
   - `GameAssembly.dll`
   - `global-metadata.dat`
   - `UnityPlayer.dll`
   - `Managed/`
   - `StreamingAssets/`
4. 查看 `GameAssembly.dll` 是否命中：
   - 反调试规则
   - 网络规则
   - 动态加载规则
   - 加密/混淆规则
5. 后续再用 IL2CPP 相关工具做类型和方法恢复

---

### 7.2 Unreal Engine 游戏

建议流程：

1. 扫描整个游戏目录
2. 查看 Unreal Engine 分数
3. 重点关注：
   - `.pak`
   - `.ucas`
   - `.utoc`
   - `AssetRegistry.bin`
   - 游戏主程序 `.exe`
   - `Binaries/Win64/`
4. 查看是否存在：
   - 高熵资产包
   - 自定义 DLL
   - 网络通信模块
   - 动态加载逻辑
   - 反调试逻辑

---

### 7.3 Android 游戏

建议流程：

1. 扫描 APK 文件
2. 扫描解包后的目录
3. 重点关注：
   - `lib/arm64-v8a/*.so`
   - `libunity.so`
   - `libil2cpp.so`
   - `assets/bin/Data/Managed/`
   - `assets/bin/Data/Managed/Metadata/global-metadata.dat`
4. 查看 ELF 导入符号和字符串
5. 关注：
   - `ptrace`
   - `dlopen`
   - `dlsym`
   - `frida`
   - `xposed`
   - `zygisk`
   - 网络 API

---

## 8. 输出 JSON 结构

JSON 报告适合后续二次开发、前端展示或接入自动化平台。

大致结构：

```json
{
  "summary": {
    "root": "...",
    "files_seen": 100,
    "files_analyzed": 80,
    "engine_scores": {},
    "severity_counts": {},
    "top_findings": {}
  },
  "files": [
    {
      "path": "GameAssembly.dll",
      "size": 123456,
      "sha256": "...",
      "file_type": "PE/COFF executable",
      "entropy": 6.8,
      "engine_hints": {},
      "findings": [],
      "strings_sample": [],
      "metadata": {}
    }
  ]
}
```

---

## 9. 规则扩展方法

规则集中在代码中的 `RULES` 字典。

示例：

```python
RULES = {
    "anti_debug_or_vm": {
        "severity": "medium",
        "description": "Anti-debugging, anti-VM, or environment detection indicators",
        "patterns": [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess"
        ],
        "tags": ["anti-debug", "anti-vm"]
    }
}
```

新增规则时需要填写：

| 字段 | 说明 |
|---|---|
| `severity` | 风险等级：`high`、`medium`、`low` |
| `description` | 规则描述 |
| `patterns` | 要匹配的字符串特征 |
| `tags` | 标签分类 |

---

## 10. 引擎指纹扩展方法

引擎识别规则集中在 `ENGINE_RULES` 字典。

示例：

```python
ENGINE_RULES = {
    "Unity": {
        "filenames": [
            "UnityPlayer.dll",
            "GameAssembly.dll",
            "global-metadata.dat"
        ],
        "path_parts": [
            "Managed",
            "il2cpp_data",
            "StreamingAssets"
        ],
        "strings": [
            "UnityEngine",
            "MonoBehaviour",
            "il2cpp"
        ],
        "extensions": [
            ".assets",
            ".bundle"
        ]
    }
}
```

可以按照自己的目标游戏类型继续加入：

- CryEngine
- RE Engine
- Frostbite
- RPG Maker
- Ren'Py
- 自研引擎
- 手游厂商自定义框架

---

## 11. 注意事项

### 11.1 静态命中不等于恶意行为

例如：

- `WriteProcessMemory` 可能用于合法调试工具
- `DeviceIoControl` 可能用于合法硬件通信
- `AES` 可能只是正常资源加密
- `IsDebuggerPresent` 可能只是商业保护壳的一部分

因此报告中的 Finding 应作为**分析入口**，不能直接作为结论。

---

### 11.2 引擎指纹需要结合上下文

某些游戏可能混合使用多个组件：

- Unity 游戏内嵌第三方 native SDK
- Unreal 游戏包含自定义 Launcher
- Android 游戏同时存在 Java、Unity、Native SO
- PC 游戏包含反作弊服务或驱动组件

所以引擎分数只是辅助判断。

---

### 11.3 大型资产包扫描可能较慢

`.pak`、`.ucas`、`.assets`、`.bundle`、`.pck` 等文件可能非常大。

如果只做初步摸底，可以不启用 `--deep`。

如果要完整扫描，可以使用：

```bash
python ge_security_agent.py scan ./GameFolder --deep --workers 4
```

---

## 12. 推荐目录结构

```text
game-engine-security-agent/
├── ge_security_agent.py
├── README.md
├── reports/
│   ├── report.md
│   └── report.json
└── samples/
    └── target_game_folder/
```

---

## 13. 后续可扩展方向

可以继续扩展为更完整的 Agent 系统：

- 接入 YARA 规则
- 接入 capa 规则
- 接入 Detect It Easy / ExeinfoPE 结果
- 接入 LIEF 做更强的 PE/ELF/Mach-O 分析
- 接入 APK Manifest 解析
- 接入 Unity IL2CPP metadata 识别
- 接入 Unreal Pak 索引识别
- 输出 HTML 报告
- 做 Web UI 展示
- 做任务队列和批量样本管理
- 做风险规则配置文件化
- 做多 Agent 分析流水线

---

## 14. 示例命令合集

```bash
# 安装依赖
pip install pefile pyelftools rich

# 扫描目录并输出 Markdown
python ge_security_agent.py scan ./GameFolder --out report.md

# 同时输出 JSON
python ge_security_agent.py scan ./GameFolder --out report.md --json report.json

# 深度扫描
python ge_security_agent.py scan ./GameFolder --deep --out deep_report.md --json deep_report.json

# 扫描单个 Unity IL2CPP 文件
python ge_security_agent.py scan ./GameAssembly.dll --out GameAssembly_report.md

# 扫描 Android SO
python ge_security_agent.py scan ./libil2cpp.so --out libil2cpp_report.md

# 扫描所有文件
python ge_security_agent.py scan ./GameFolder --all-files --out full_report.md

# 多线程扫描
python ge_security_agent.py scan ./GameFolder --workers 4 --out report.md

# 不忽略默认缓存目录
python ge_security_agent.py scan ./GameFolder --no-ignore --out report.md
```

---

## 15. 适用场景

- 游戏客户端安全审计
- 游戏引擎逆向前期摸底
- Unity / Unreal / Godot 项目结构识别
- Android 游戏 Native 层分析前准备
- 反调试和保护逻辑初筛
- 可疑 API 批量定位
- 游戏资产包和脚本文件归类
- 二进制样本批量生成报告
- 安全研究报告素材整理

---

## 16. 非目标功能

本工具不提供以下能力：

- 外挂功能
- 反作弊绕过
- 注入器
- 驱动加载器
- 内存修改器
- Exploit 利用链
- 未授权攻击能力
- 自动脱壳
- 自动破解商业保护

如果需要更深入的逆向分析，应结合合法授权环境下的专业工具，例如：

- IDA Pro
- Ghidra
- Binary Ninja
- x64dbg
- WinDbg
- JADX
- apktool
- dnSpy / ILSpy
- Il2CppDumper / Il2CppInspector
- UnrealPak

---

## 17. 总结

`Game Engine Reverse & Security Analysis Agent` 是一个用于游戏逆向和安全分析前期阶段的自动化静态分析工具。

它可以帮助分析者快速完成：

- 引擎识别
- 文件优先级排序
- 二进制元信息提取
- 字符串扫描
- 风险 API 初筛
- 报告生成

适合个人研究、小团队安全审计、游戏客户端逆向学习和自动化样本归类。

