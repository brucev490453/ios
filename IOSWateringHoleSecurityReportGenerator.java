import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class IOSWateringHoleSecurityReportGenerator {
    private static final String DEFAULT_OUTPUT = "iOS水坑攻击与网页零日漏洞网络安全分析报告.md";

    private static final String REPORT = """
# iOS 水坑攻击与网页零日漏洞网络安全分析报告

| 项目 | 内容 |
|---|---|
| 报告日期 | 2026-10-03 |
| 报告范围 | iOS 水坑攻击、Safari/WebKit 网页零日漏洞、全链利用与企业防御 |
| 适用对象 | SOC、移动安全、事件响应、数字取证、企业 IT 与高风险人员安保团队 |
| 报告性质 | 防御性网络安全研究 |
| 风险等级 | 严重（Critical） |

> 本报告不包含漏洞利用代码、PoC、武器化步骤或绕过检测方法，仅用于风险识别、监测、响应与加固。
>
> 置信度标记：**[确证]** 为 Apple 或一手研究机构直接确认；**[多源]** 为多个独立来源交叉印证；**[待核]** 为公开来源存在冲突或尚缺原始证据。

---

## 1. 执行摘要

iOS 水坑攻击通过入侵目标群体经常访问的合法网站，向页面注入隐藏脚本、iframe 或重定向逻辑。受害者使用 Safari 访问页面后，攻击代码会识别设备型号、处理器架构和 iOS 版本，仅向符合条件的设备投递相应的 WebKit 或 JavaScriptCore 漏洞链。

与传统钓鱼不同，水坑攻击可能发生在具有有效 TLS 证书、长期信誉和正常内容的合法站点上。用户即使认真检查域名，也难以发现页面中的动态恶意内容。

关键结论：

1. **Safari/WebKit 是远程入口。** WebKit、JavaScriptCore、ANGLE/WebGPU 等组件负责处理攻击者控制的网页内容，类型混淆、释放后使用和越界写是主要漏洞类别。
2. **单个网页漏洞通常不足以完全控制设备。** 现代 iOS 攻击需要组合浏览器代码执行、沙箱逃逸、缓解绕过和内核提权。
3. **DarkSword 是典型案例。** 公开分析称其组合多个 CVE，从恶意网页访问逐步实现 WebContent 代码执行、GPU/媒体进程横向移动、内核权限和敏感数据访问。**[多源]**
4. **网页零日攻击不一定是零点击。** 多数水坑场景要求用户访问或被重定向至页面，加载后无需继续操作，准确表述应为 one-click 或 drive-by。
5. **无持久化使检测更加困难。** 攻击可在内存中运行，完成数据窃取后删除暂存文件，传统基于恶意 App、描述文件和文件哈希的检测可能失效。
6. **快速更新是最有效的控制。** 公开全链中常混合 0-day 与已修补的 n-day；未及时升级会让攻击者继续利用已有工具链。
7. **高风险人员应启用 Lockdown Mode。** 该模式通过限制复杂 Web 技术、消息附件和部分连接能力显著收缩攻击面。

---

## 2. 概念与攻击模型

### 2.1 水坑攻击

水坑攻击通常包含以下阶段：

```text
识别目标群体常访问的网站
        ↓
入侵网站、广告链、统计脚本或第三方资源
        ↓
注入隐藏 iframe / JavaScript / 重定向
        ↓
识别访问设备与 iOS 构建版本
        ↓
命中条件时投递 WebKit/JavaScriptCore 漏洞链
        ↓
沙箱逃逸与内核提权
        ↓
数据访问、外传与痕迹清理
```

### 2.2 网页零日漏洞

“网页零日漏洞”通常指在厂商发布修复之前，攻击者已经掌握并使用的浏览器或网页渲染组件漏洞。iOS 上相关组件包括：

- **WebKit**：Safari 与多数系统 WebView 的核心渲染引擎；
- **JavaScriptCore**：JavaScript 解析、执行与 JIT 编译；
- **ANGLE / WebGPU / GPU Process**：图形接口转换与 GPU 隔离进程；
- **媒体与字体解析器**：网页中的图片、字体、视频和音频内容可触发底层解析路径；
- **dyld**：动态链接器，可成为已有内存写能力后的缓解绕过目标；
- **XNU Kernel**：完整控制设备通常需要进一步获得内核权限。

### 2.3 0-day 与 n-day

| 类型 | 定义 | 防御重点 |
|---|---|---|
| 0-day | 漏洞被利用时厂商尚未发布修复 | Lockdown Mode、网络隔离、行为检测与快速响应 |
| n-day | 厂商已有补丁，但设备仍未更新 | 补丁管理、MDM 合规与淘汰不受支持设备 |

---

## 3. 典型完整利用链

### 3.1 初始访问：WebKit / JavaScriptCore

攻击者通过恶意 JavaScript 或网页资源触发浏览器引擎内存安全漏洞。常见类型包括：

- 类型混淆；
- 释放后使用；
- 越界读写；
- JIT 优化阶段逻辑错误；
- 对象生命周期或垃圾回收错误。

成功后，攻击代码通常仍被限制在 WebContent 沙箱中，无法直接读取 Keychain、消息数据库或其他应用数据。

### 3.2 沙箱逃逸

攻击链随后利用 GPU、媒体或 XPC 服务中的漏洞，从 WebContent 进程移动至权限更高的系统进程。GPU Process 和媒体守护进程需要处理复杂、不可信内容，同时与多个系统服务通信，因此是重要信任边界。

### 3.3 缓解绕过

现代 iPhone 使用 PAC、代码签名、页表保护和内核只读区等机制阻止控制流劫持。高级链路会利用 dyld、内核或硬件边界缺陷扩大已有内存原语，绕过这些缓解措施。

### 3.4 内核提权

内核漏洞可使攻击者突破应用沙箱、访问其他进程内存或已解密数据。常见类型包括：

- 内核对象释放后使用；
- 整数溢出导致越界访问；
- 内存映射与页表验证缺陷；
- 锁与引用计数错误；
- 驱动或协处理器接口中的输入验证缺陷。

### 3.5 后利用与数据外传

获得高权限后，攻击者可能访问：

- Keychain 中可用的凭据与令牌；
- Apple ID、iCloud 和企业 SSO 会话；
- SMS、iMessage 与即时通信数据；
- 联系人、照片、备忘录、日历和位置；
- Safari Cookie 与浏览会话；
- 加密钱包应用与数字资产相关数据；
- 企业邮件、文档、VPN 与云服务令牌。

---

## 4. DarkSword 案例

DarkSword 被公开描述为 JavaScript 投递、内存态运行的 iOS 全链利用工具包。研究人员报告其通过被入侵合法网站或仿冒页面进行投递，并根据设备版本选择漏洞链。**[多源]**

### 4.1 公开漏洞链

| 阶段 | CVE / 组件 | 公开描述的作用 | 置信度 |
|---|---|---|---|
| WebContent 代码执行 | CVE-2025-31277 / JavaScriptCore | JIT 或正则处理相关内存问题 | [多源·待核精确类别] |
| 替代 WebContent 入口 | CVE-2025-43529 / WebKit JIT | 释放后使用或类型混淆类内存破坏 | [多源] |
| 缓解绕过 | CVE-2026-20700 / dyld | 扩大内存写能力并绕过 PAC/TRO 相关约束 | [确证已被极复杂攻击利用] |
| GPU 沙箱逃逸 | CVE-2025-14174 / ANGLE、WebGPU | 越界写或内存破坏 | [多源] |
| 系统服务移动 | GPU → mediaplaybackd | 借助系统守护进程信任关系提高权限 | [多源] |
| 内核提权 | CVE-2025-43510 / Kernel | 内存管理或锁验证缺陷 | [多源·待核] |
| 内核提权 | CVE-2025-43520 / Kernel | 内存破坏并形成高权限写能力 | [多源·待核] |

### 4.2 修复版本

| CVE | 公开分析分类 | 主要修复版本 | 日期 |
|---|---|---|---|
| CVE-2025-43529 | 0-day | iOS/iPadOS 26.2、18.7.3 | 2025-12-12 |
| CVE-2025-14174 | 0-day | iOS/iPadOS 26.2、18.7.3 | 2025-12-12 |
| CVE-2026-20700 | 0-day | iOS/iPadOS 26.3 | 2026-02-11 |
| CVE-2025-31277 | n-day | iOS 18.6 时期 | 2025-07 |
| CVE-2025-43510 | n-day | iOS 26.1、18.7.2 回移植 | 2025-11-03 |
| CVE-2025-43520 | n-day | iOS 26.1、18.7.2 回移植 | 2025-11-03 |

公开来源对 CVE-2025-43529 的早期回移植版本及完整受影响范围存在分歧，应以 Apple 最新公告原文为准。

### 4.3 受影响版本争议

- iVerify、Zimperium 等来源主要指向 iOS 18.4–18.7；
- runZero 等来源扩大到 iOS 18.0–18.7.2 与 26.0–26.2；
- 部分报道提出更宽的 iOS 13+ 范围，但缺少完整逐版本证据。

企业应重点排查 iOS 18.4–18.7.2 与 26.0–26.2，同时把所有未达到 Apple 当前安全更新水位的设备视为潜在暴露。

---

## 5. 水坑攻击的网络特征

### 5.1 可观测行为

- 合法网站页面突然加载新出现的第三方 JavaScript 或隐藏 iframe；
- 页面根据 User-Agent、屏幕尺寸、GPU、系统构建版本进行高强度指纹识别；
- 正常网页会话后立即出现跨域连接与短时 HTTPS 突发外联；
- 移动设备访问低信誉、新注册或与业务无关的 CDN 域名；
- 浏览会话与 Safari、WebKit、GPU 或媒体进程崩溃在时间上高度相关；
- 同一网页对不同设备返回明显不同的资源。

### 5.2 已公开 DarkSword IOC

| 类型 | 指标 | 处置建议 |
|---|---|---|
| 域名 | `static.cdncounter[.]net` | 历史回溯并结合访问时间告警 |
| 域名 | `cdncounter[.]net` | 评估业务关联后监控或阻断 |
| 域名 | `sqwas.shapelie[.]com` | 排查 8881/8882 端口连接 |
| 域名 | `snapshare[.]chat` | 按仿冒或投递基础设施处理 |
| IP | `141.105.130[.]237` | 回溯 DNS、代理、VPN 和防火墙日志 |
| IP | `62.72.21[.]10` | 回溯 DNS、代理、VPN 和防火墙日志 |
| 被入侵合法站点 | `novosti[.]dn[.]ua` | 监控与时间关联，不建议永久封禁 |
| 被入侵合法站点 | `7aac[.]gov[.]ua` | 监控与时间关联，不建议永久封禁 |

IOC 时效性较短，不能作为唯一判定依据。被入侵合法站点应采用“告警、时间关联和通知所有方”策略，避免因永久封禁造成业务误伤。

---

## 6. 设备与日志检测

### 6.1 重点日志

- Safari、WebKit 与 GPU Process 崩溃报告；
- `mediaplaybackd` 异常启动、崩溃和资源活动；
- `Springboard` 异常行为；
- Unified Log 中浏览、GPU、媒体与网络事件的时间关联；
- sysdiagnose 中的系统构建版本、崩溃记录和网络状态；
- MDM/MTD 中的版本不合规、完整性变化和网络告警。

### 6.2 公开研究提及的线索

- `GPUProcessProxy::childConnectionDidBecomeUnresponsive` 反复出现；
- `mediaplaybackd` 日志包含与攻击链或 Wi-Fi 数据导出相关的异常字符串；
- `/tmp/` 或 `/private/var/tmp/` 出现短暂的凭据、钱包或数据库导出文件；
- 对 `com.bitcoin.*`、`io.metamask.*` 等钱包标识进行异常访问；
- 页面访问后出现高频进程崩溃、内存压力与异常外联。

这些信号可能存在正常软件故障导致的误报，必须结合设备版本、网络 IOC、用户活动和身份日志进行综合判断。

### 6.3 SOC 关联逻辑

```text
高风险设备版本
  + Safari 访问低信誉或已知基础设施
  + WebKit/GPU/mediaplaybackd 连续崩溃
  + 浏览后出现异常 HTTPS 外联
  = 高优先级移动端安全事件
```

---

## 7. 事件响应流程

1. 记录设备、用户、iOS 版本、异常时间与当时访问的网站；
2. 断开 Wi-Fi 与蜂窝网络，阻止继续外传；
3. 高价值目标不要立即重启，优先采集 sysdiagnose、Unified Log 与崩溃报告；
4. 导出 DNS、代理、VPN、防火墙和身份认证日志；
5. 核对 Apple Threat Notification、Apple ID、企业 SSO、邮件和 VPN 登录活动；
6. 从干净设备轮换 Apple ID、企业账户、邮箱、VPN 与关键应用凭据；
7. 若涉及加密钱包，按私钥或会话已泄露处理并迁移资产；
8. 完成取证后擦除设备，安装最新 iOS，再重新注册 MDM；
9. 不直接恢复未经审查的完整设备状态；
10. 根据数据类型和受害者身份启动法务、隐私与人员安全流程。

### 7.1 重启决策

重启可能终止无持久化载荷，但也会销毁运行态证据。若持续资金损失或人员安全风险高于取证价值，应立即断网并重启；若设备属于高价值调查对象，应先隔离和采证，再执行擦除重装。

---

## 8. 加固基线

### 8.1 补丁管理

| 漏洞情况 | 建议 SLA |
|---|---|
| Apple 标注在野利用的 WebKit、JavaScriptCore、内核或 dyld 漏洞 | 72 小时内完成关键岗位升级 |
| Rapid Security Response | 24 小时内验证与部署 |
| 其他严重远程代码执行漏洞 | 7 天内 |
| 常规安全更新 | 30 天内 |
| 无法更新设备 | 立即限制企业访问并安排退役 |

### 8.2 高风险人员

- 强制开启 Lockdown Mode；
- 工作设备与个人加密资产设备分离；
- 使用独立 Apple ID 与硬件安全密钥；
- 禁止安装来源不明的描述文件和企业证书；
- 缩短自动锁定时间，启用 USB 配件访问限制；
- 开启 iCloud 高级数据保护；
- 避免在主工作设备打开陌生短链接和二维码；
- 收到 Apple Threat Notification 后立即上报安全团队。

### 8.3 MDM 能力边界

MDM 可以强制版本基线、配置策略和限制企业资源访问，但无法提供传统桌面 EDR 的完整进程与内核遥测。无恶意 App、无异常描述文件不代表设备未受攻击。企业需要结合 MTD、网络日志、身份日志和离线取证。

---

## 9. 风险矩阵

| 风险场景 | 可能性 | 影响 | 综合等级 |
|---|---|---|---|
| 未更新设备访问被入侵网站 | 高 | 严重 | 严重 |
| 高风险人员遭定向水坑攻击 | 中至高 | 严重 | 严重 |
| 普通员工遭网页 n-day 攻击 | 中 | 高 | 高 |
| 仅依赖 MDM 判定设备安全 | 高 | 高 | 高 |
| IOC 已失效导致漏报 | 高 | 中至高 | 高 |
| 被入侵合法站点被误封 | 中 | 中 | 中 |

---

## 10. 情报冲突与限制

| 争议 | 报告立场 |
|---|---|
| DarkSword 是否零点击 | 按 one-click / drive-by 管理；未发现 iMessage 式自动触发证据 |
| 受影响 iOS 范围 | 重点排查 18.4–18.7.2 与 26.0–26.2；其他未更新版本仍不可豁免 |
| 0-day 数量 | 采用“3 个 0-day + 3 个 n-day”的多源口径，以 Apple 公告为最终依据 |
| CVSS | 不自行推算缺少统一官方口径的 CVSS，采用完整链影响评级 |
| 攻击归因 | 归因基于公开研究，不能仅凭单一 IOC 确认攻击者 |
| IOC 时效 | 域名和 IP 可快速更换，应与行为和时间线结合 |

---

## 11. 参考来源

### Apple 官方

- [Apple Security Releases](https://support.apple.com/en-us/100100)
- [About the security content of iOS 26.2 and iPadOS 26.2](https://support.apple.com/en-us/125884)
- [About the security content of iOS 26.3 and iPadOS 26.3](https://support.apple.com/en-us/126346)
- [Apple Platform Security Guide](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)

### 威胁情报与技术分析

- [Google Threat Intelligence — The Proliferation of DarkSword](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain)
- [Google Threat Intelligence — Coruna iOS exploit kit](https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit)
- [Cloud Security Alliance — DarkSword Full-Chain iOS Zero-Day Exploitation](https://labs.cloudsecurityalliance.org/research/csa-research-note-darksword-ios-fullchain-zeroday-multiactor/)
- [iVerify — Inside DarkSword](https://www.iverify.com/blog/darksword-ios-exploit-kit-explained)
- [Zimperium — DarkSword: The Hit-and-Run Successor to Coruna](https://zimperium.com/blog/darksword-the-hit-and-run-successor-to-the-coruna-ios-exploit-kit)
- [Kaspersky — DarkSword and Coruna in mass attacks](https://www.kaspersky.com/blog/ios-exploits-darksword-and-coruna-in-mass-attacks/55622/)
- [安全内参 — 通过攻陷合法网站传播的新型 iOS 漏洞利用工具包 DarkSword](https://www.secrss.com/articles/88644)

---

*本报告基于公开情报编制。漏洞状态、IOC 与受影响版本会持续变化，处置前应再次核对 Apple 最新安全公告和一手研究资料。*

咨询ios系统请咨询  telegram：@DZHT333333
""";

    private IOSWateringHoleSecurityReportGenerator() {
    }

    public static void main(String[] args) {
        Path output = args.length == 0 ? Path.of(DEFAULT_OUTPUT) : Path.of(args[0]);
        try {
            Files.writeString(output, REPORT, StandardCharsets.UTF_8);
            System.out.println("报告已生成：" + output.toAbsolutePath());
        } catch (IOException exception) {
            System.err.println("报告生成失败：" + exception.getMessage());
            System.exit(1);
        }
    }
}
