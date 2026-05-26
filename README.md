# crash-log-analyzer Skill

这是一个用于分析 C++/Qt 崩溃、平台崩溃产物、异常退出、视频渲染故障和 watchdog 重启判断的 Codex Skill。

## 这个 Skill 的作用

`crash-log-analyzer` 帮助 Codex 把不完整的崩溃线索整理成可执行的工程分析，包括事实证据、退出分类、根因假设、验证步骤和低风险修复建议。它主要适用于：

- Windows Event Viewer、WER、ProcDump、minidump/full dump 线索和 WinDbg 输出。
- Linux `systemd`、`journalctl`、`coredumpctl`、GDB 栈、signal、OOM kill 和服务重启。
- macOS `.crash`/`.ips` 报告、Binary Images、`atos` 符号化、DYLD 和 CODESIGNING termination。
- Qt 异常退出、QObject/QThread 生命周期问题、跨线程 UI 访问、queued connection 问题和 watchdog 重启。
- C++ 野指针、use-after-free、越界写、双重释放、堆破坏、死锁和数据竞争。
- FFmpeg/video-render 崩溃，包括 `AVFrame`、`AVPacket`、硬件帧、像素格式、GPU/context 生命周期和 Qt video wrapper。
- watchdog 退出判断：正常退出、崩溃、强制 kill、卡死、卡死后被 kill、系统关机/重启、请求停止或 unknown。

这个 skill 包含结构化分析流程、平台/领域参考资料、初筛脚本、采集脚本、脱敏支持、质量门槛和回归测试。

## 目录内容

```text
.agents/
  skills/
    crash-log-analyzer/
      SKILL.md
      agents/openai.yaml
      scripts/classify_crash_log.py
      scripts/redact_text.py
      scripts/collect_windows_crash_info.ps1
      scripts/collect_linux_crash_info.sh
      scripts/collect_macos_crash_info.sh
      references/
        windows.md
        linux.md
        macos.md
        qt-cpp.md
        ffmpeg-video.md
        watchdog.md
        quality-gate.md
        intake-checklist.md
        report-template.md
tests/
  run_all.py
  run_golden_tests.py
  run_manifest_tests.py
  test_redaction.py
  validate_skill.py
  REAL_SAMPLES.md
  golden/schema.json
  manifest.schema.json
  sample_manifests/
```

## 安装

把 `.agents` 目录复制到项目根目录，让 Codex 能发现这个 skill：

```text
your-project/
  .agents/
    skills/
      crash-log-analyzer/
        SKILL.md
```

## 全局安装，让所有项目都可用

如果希望所有项目都能使用这个 skill，不需要把 `.agents/skills/crash-log-analyzer` 复制到每个项目里。可以把 skill 安装到 Codex 全局 skills 目录。

在 Windows 上通常是：

```text
C:\Users\coczh\.codex\skills\
```

最终目录结构应类似：

```text
C:\Users\coczh\.codex\skills\crash-log-analyzer\SKILL.md
```

复制安装：

```powershell
$src = "C:\coczhang\GitHub\crash-log-analyzer-skill\.agents\skills\crash-log-analyzer"
$dstRoot = if ($env:CODEX_HOME) { Join-Path $env:CODEX_HOME "skills" } else { Join-Path $env:USERPROFILE ".codex\skills" }
$dst = Join-Path $dstRoot "crash-log-analyzer"

New-Item -ItemType Directory -Force -Path $dstRoot | Out-Null
Copy-Item -Path $src -Destination $dst -Recurse -Force
```

如果希望后续在这个仓库中修改 skill 后，全局版本自动同步，推荐使用 junction，而不是复制：

```powershell
$src = "C:\coczhang\GitHub\crash-log-analyzer-skill\.agents\skills\crash-log-analyzer"
$dstRoot = if ($env:CODEX_HOME) { Join-Path $env:CODEX_HOME "skills" } else { Join-Path $env:USERPROFILE ".codex\skills" }
$dst = Join-Path $dstRoot "crash-log-analyzer"

New-Item -ItemType Directory -Force -Path $dstRoot | Out-Null
New-Item -ItemType Junction -Path $dst -Target $src
```

如果目标目录已经存在同名 `crash-log-analyzer`，先确认它是否是旧版本。需要替换时，建议先备份或删除旧目录，再重新复制或创建 junction。安装完成后，重新打开 Codex 会话，新的项目中也可以触发 `crash-log-analyzer`。

## 如何使用

当你有崩溃证据，或者需要判断进程到底是正常退出、崩溃、被 kill 还是卡死时，让 Codex 使用这个 skill：

```text
Use crash-log-analyzer to analyze this Windows Event Viewer crash log.
```

```text
Use crash-log-analyzer to determine whether this Qt service exited normally, crashed, was killed, or hung.
```

```text
Use crash-log-analyzer to analyze this Linux systemd journal and core dump stack.
```

也可以在本地对文本日志做快速初筛：

```text
python .agents/skills/crash-log-analyzer/scripts/classify_crash_log.py path/to/log.txt
python .agents/skills/crash-log-analyzer/scripts/classify_crash_log.py path/to/log.txt --json
```

初筛结果会包含：可能的平台、检测到的领域、异常码、signal/status、关键字段、推荐参考资料、采集建议和初始退出分类。新版 JSON 还会输出 `confidence`、`supporting_evidence`、`missing_evidence` 和 `fault_context`，用于快速查看置信度、支撑证据、缺失证据、故障模块/偏移、第一故障帧和第一应用帧。

注意：`classify_crash_log.py` 的输出只是结构化初筛，不是最终 RCA。正式分析仍然需要结合 `references/quality-gate.md`，确认第一故障帧、第一 app-owned frame、符号完整性和可反证假设。

## 采集证据

采集脚本会生成一个目录，里面包含日志、摘要、warning 和 `manifest.json`。如果采集结果要离开本机或团队内部，建议使用脱敏和 zip 输出。

Windows：

```text
powershell -ExecutionPolicy Bypass -File .agents/skills/crash-log-analyzer/scripts/collect_windows_crash_info.ps1 -ProcessName YourApp.exe -Hours 24 -Redact -Zip
```

Linux：

```text
bash .agents/skills/crash-log-analyzer/scripts/collect_linux_crash_info.sh --service your-app.service --process YourApp --hours 24 --redact --zip
```

macOS：

```text
bash .agents/skills/crash-log-analyzer/scripts/collect_macos_crash_info.sh --process YourApp --app /Applications/YourApp.app --hours 24 --redact --zip
```

采集生成的 manifest 会记录脚本版本、平台、目标进程/服务、是否脱敏、warning、采集到的文件路径、文件大小和 SHA-256 hash。

## 脱敏文本产物

在把真实日志转成测试样本前，先用独立脱敏器处理：

```text
python .agents/skills/crash-log-analyzer/scripts/redact_text.py raw-log.txt
```

如果有明确的客户名、设备名或项目名：

```text
python .agents/skills/crash-log-analyzer/scripts/redact_text.py raw-log.txt --term CustomerName --term DeviceSerial123
```

也可以直接原地改写 fixture：

```text
python .agents/skills/crash-log-analyzer/scripts/redact_text.py --in-place tests/golden/windows-real-case-001.txt --term CustomerName
```

自动脱敏器会覆盖常见邮箱、IPv4/IPv6、Bearer/Basic token、JWT、password/token/secret/API key/license key/serial/tenant ID/client ID 字段、Windows 域账号、Windows 用户目录、Unix/macOS home 目录、主机名和额外 `--term` 指定的字面值。`--term` 匹配大小写不敏感。

自动脱敏后仍然必须人工复核。不要提交原始 dump、core 文件或其他二进制内存产物；它们可能包含文本脱敏无法移除的敏感信息。

## 验证

运行完整本地验证：

```text
python -B tests/run_all.py
```

它会检查：

- Skill metadata 和 `openai.yaml` 基本约束。
- golden crash classification 样例。
- manifest 样例结构。
- 脱敏行为。
- Python 语法。

CI 还会通过 `.github/workflows/validate.yml` 检查 bash 采集脚本语法和 PowerShell 脚本可解析性。

## 接入真实脱敏事故样本

当真实事故暴露出误判、分析路径不足或新的脱敏缺口时，按照下面流程把它沉淀成 regression case。

1. 在仓库外收集原始证据。

   例如：Event Viewer/WER 文本、WinDbg 输出、`journalctl`、`systemctl show`、`coredumpctl info`、GDB `bt full`、macOS `.crash`、watchdog 日志、Qt/FFmpeg 栈。

2. 创建脱敏后的文本 fixture。

   ```text
   python .agents/skills/crash-log-analyzer/scripts/redact_text.py raw-incident.txt --term CustomerName > tests/golden/windows-real-case-001.txt
   ```

3. 人工复核 fixture。

   移除或替换客户名、主机名、用户名、IP、邮箱、token、license key、私有路径、设备序列号、tenant ID 和项目名。

4. 保留诊断信号。

   保留 exception code、signal、Event ID、exit code、fault offset、module name、function name、栈帧顺序、systemd result、macOS termination reason、Binary UUID 和 watchdog 时间线。

5. 生成当前 classifier 输出。

   ```text
   python .agents/skills/crash-log-analyzer/scripts/classify_crash_log.py tests/golden/windows-real-case-001.txt --json
   ```

6. 添加期望结果。

   创建 `tests/golden/windows-real-case-001.expect.json`：

   ```json
   {
     "exit_classification": "crash",
     "platforms": ["windows"],
     "domains": ["qt", "memory"],
     "references": ["references/windows.md", "references/qt-cpp.md"],
     "exception_codes": ["0xc0000005"],
     "key_fields": {
       "windows_event_id": ["1000"],
       "fault_offset": ["0x0000000000123456"]
     }
   }
   ```

7. 运行验证。

   ```text
   python -B tests/run_all.py
   ```

`.expect.json` 应该描述 artifact 本身能证明什么，而不是工程师事后从私有上下文里知道的真实根因。如果 artifact 只能支持 `unknown`，就使用 `unknown`。

## 观察 CI 并沉淀 Regression Case

接入真实样本后，让 CI 在日常修改中持续运行一段时间，重点观察两类失败：

- 误判：退出分类、平台/领域识别、关键字段提取或推荐 reference 错误。
- 脱敏缺口：fixture 或采集文本中出现 redactor 没有覆盖的敏感模式。

当 CI 或人工 review 发现失败时：

1. 在 `tests/golden/` 下保留或新增一个能复现问题的最小脱敏 artifact。
2. 新增或收紧对应的 `.expect.json`。
3. 如果问题是分类错误，修改 `classify_crash_log.py`。
4. 如果问题是敏感信息泄漏，修改 `redact_text.py`，并在 `tests/test_redaction.py` 里加用例。
5. 如果问题是采集包结构，修改 `tests/manifest.schema.json`、`tests/sample_manifests/` 或采集脚本。
6. 运行 `python -B tests/run_all.py`。
7. 保留这个样本作为 regression case，防止同类失败悄悄回归。

长期来看，生产级标准应该建立在真实数据上：分类准确率可量化、`unknown` 行为足够保守、已知脱敏泄漏为零、manifest 稳定，并且 RCA 输出能通过工程 review。
