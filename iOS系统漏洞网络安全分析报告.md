# iOS 系统漏洞网络安全分析报告

| 项目 | 内容 |
|---|---|
| 报告标题 | iOS 系统在野利用漏洞深度分析与防御建议 |
| 报告日期 | 2026-10-03 |
| 情报截止 | 2026-10-03（公开来源） |
| 适用读者 | 企业安全工程师、移动端威胁分析、IT 安全合规、高风险人群安保团队 |
| 报告性质 | 防御性安全研究（Defensive / Threat Intelligence） |
| 密级建议 | 内部 — 可跨安全团队分发 |

> **使用说明**：本报告不含任何可直接使用的攻击代码或利用载荷，仅描述公开披露漏洞的机理、影响与检测方法。文中所有事实性结论均标注置信度：
> - **[确证]** = Apple 官方安全公告或一手研究团队（Google TAG / Citizen Lab / Kaspersky GReAT）直接声明
> - **[多源]** = 两家及以上独立安全厂商交叉印证
> - **[单源·待核]** = 仅单一来源或存在来源冲突，采纳前需二次验证
>
> 第 9 章「情报冲突与不确定性登记」列出所有已识别的来源矛盾，请在据此做处置决策前先行阅读。

---

## 1. 执行摘要

1. **iOS 在野利用漏洞总量持续高位。** 2023 年至 2026 年 10 月，Apple 官方标注「可能已被在野利用」的 iOS/iPadOS 漏洞约 **20–21 个**，年度分布为 2023 年 5 个、2024 年 5 个、2025 年 9 个、2026 年至今 1 个。**[多源]** 2025 年是近四年峰值，说明攻防投入均在上升，而非平台趋于安全。

2. **WebKit / JavaScriptCore 是绝对主导攻击面。** 约 21 个在野漏洞中有 **10 个**位于浏览器引擎家族。任何「用户会点开链接」的场景都构成完整远程攻击面，这是移动端与桌面端威胁模型的根本差异。第二梯队是**媒体/文件解析**（ImageIO、CoreMedia、FontParser）与**物理接触类锁屏绕过**（USB Restricted Mode、Accessibility、RTKit）。

3. **2025 年底至 2026 年最重要的事件是 DarkSword 全链利用工具包。** 它由 JavaScript 投递、内存态执行、覆盖 iOS 18.4–26.2，使用 **6 个漏洞（其中 3 个为 0-day）**完成「WebKit RCE → 缓解绕过 → 沙箱逃逸 → 内核提权 → 数据窃取」的完整链路，且**不留持久化后门**（打完即走）。**[多源]**

4. **能力正在扩散，而非集中。** Google Threat Intelligence 于 2026 年 3 月确认，**至少三个互不隶属的主体**（疑似俄罗斯国家背景的 UNC6353、面向沙特的 UNC6748、土耳其商业监控厂商 PARS Defense）在使用同一套工具包；随后 Proofpoint 报告 FSB 关联的 TA446/Star Blizzard 使用的是**从他人基础设施泄露的副本**。**[多源]** 这是 iOS 攻击能力商品化与失控扩散的标志性信号——过去此类全链能力仅掌握在极少数主体手中。

5. **谍报工具正被复用于大规模经济犯罪。** DarkSword 载荷窃取范围包含加密钱包、Keychain、iCloud 凭据、即时通讯会话。**[多源]** 威胁模型已从「定向监控少数高价值目标」扩展为「批量收割加密资产」，意味着**普通企业员工也在射程内**，不再是「我不是目标所以与我无关」。

6. **Apple 的纵深防御仍然有效，但被逐层击穿。** PPL/SPTM+TXM、PAC、KTRR、BlastDoor 等机制大幅抬高了攻击成本，但 CVE-2023-38606（利用**未文档化 MMIO 硬件寄存器**绕过内存保护）与 CVE-2026-20700（**dyld 内存破坏绕过 PAC**）证明：缓解措施本身即是攻击面，且绕过点常出现在防御体系的边缘与历史遗留代码中。

7. **传统检测手段基本失效。** iOS 无第三方内核驱动、无可安装的 EDR Agent，加之 DarkSword 类攻击内存态执行且自清理，**重启即销毁证据**。可行的检测路径只剩三条：统一日志/崩溃日志离线分析、网络侧 IOC 与流量行为分析、以及 Apple 自身的 Threat Notifications。**[确证机制，多源实践]**

8. **当前处置底线（截至 2026-10-03）：** 全员升级至 **iOS/iPadOS 26.3 及以上**（无法升级 26.x 的设备至少到 **18.7.3+**）；高风险人群强制开启 **Lockdown Mode（锁定模式）**；企业 MDM 基线中把「WebKit 类在野漏洞」的补丁 SLA 定为 **72 小时内**。**[确证版本]** Apple 于 2026 年 9 月发布 **iOS 26.6**，修复 78 个漏洞且未标注任何在野利用，是目前已知最新的安全更新水位。

---

## 2. 威胁态势概览

### 2.1 年度在野利用趋势

| 年份 | Apple 标注在野利用的 iOS CVE 数 | 代表事件 | 特征 |
|---|---|---|---|
| 2023 | 5 | Operation Triangulation（Kaspersky 披露） | 硬件级绕过，攻击链技术复杂度历史峰值 |
| 2024 | 5（+1 存疑） | 18.1.1 紧急修复 JavaScriptCore + WebKit 组合 | 商业间谍软件（Predator/Paragon）活跃期 |
| 2025 | 9 | 物理接触类三连（CoreMedia/VoiceOver/USB RM）、ImageIO 双弹、WebKit 年末双 0-day | 数量峰值；攻击面从纯远程扩展到物理接触 |
| 2026（至 10 月） | 1 | CVE-2026-20700（dyld，PAC 绕过）；DarkSword 多主体扩散被公开 | 缓解机制本身成为攻击目标 |

**[多源]** 需要注意，「Apple 标注数」是**下限**而非全量：Apple 对未确认在野利用的漏洞不会加注，商业间谍软件厂商使用的部分漏洞可能从未被公开归因。

### 2.2 攻击面分布（按组件家族）

```
WebKit / JavaScriptCore   ██████████ 10   ← 远程攻击主入口
媒体与文件解析            ████        4   (ImageIO ×2, CoreMedia, FontParser)
物理接触 / 锁屏绕过       ███         3   (Accessibility, USB RM, RTKit)
内核 (XNU)                █           1   (CVE-2023-32434)
硬件未文档化特性          █           1   (CVE-2023-38606)
动态链接器 (dyld)         █           1   (CVE-2026-20700)
消息 / iCloud 链路        █           1   (CVE-2025-43200)
```

**结论**：远程可达的攻击面高度集中在**解析不可信输入**的组件上。这类组件的共同特征是——必须处理攻击者完全控制的数据，且为了性能普遍使用 JIT 或手写 C/C++ 解析器，内存安全缺陷难以根除。

### 2.3 攻击者画像演变

| 阶段 | 代表 | 能力持有者 | 目标 | 商业模式 |
|---|---|---|---|---|
| 2016–2021 | Pegasus（NSO）、Trident | 极少数商业厂商 + 国家 | 记者、政要、异见人士 | 按目标授权收费 |
| 2022–2024 | Predator（Intellexa）、Paragon Graphite、Operation Triangulation | 商业厂商 + 国家 APT | 定向监控 | 按目标 / 按链路 |
| 2025–2026 | **Coruna**（iOS 13–17.2.1，5 条全链、23 个利用）→ **DarkSword** | **多主体并存**：国家 APT + 商业监控厂商 + 犯罪组织 | 定向监控 **+ 批量加密资产窃取** | **工具包租赁 / 中介撮合，能力可泄露** |

**[多源]** 2026 年的关键变化不是「出现了新漏洞」，而是**能力持有者数量增加、门槛降低**。有来源提及攻击者在适配工具包时使用了生成式 AI 辅助移植代码 **[单源·待核]**，若属实，将进一步压缩攻击开发周期。

---

## 3. 重点事件深度分析：DarkSword 全链 iOS 利用工具包

### 3.1 概述

DarkSword 是 2025 年 11 月前后开始被观测、2026 年 3 月由 Google Threat Intelligence 公开命名的**JavaScript 投递型、内存态全链 iOS 利用工具包**，附带信息窃取载荷。其前身/近亲为 **Coruna**（Google Threat Intelligence 与 iVerify 于 2026 年 3 月 3 日披露，覆盖 iOS 13–17.2.1，含 5 条完整利用链、23 个利用）。**[多源]**

**投递方式：水坑攻击（Watering Hole）**
- 攻击者入侵**合法网站**并注入隐藏恶意 iframe，已确证的被入侵站点包括乌克兰新闻与政府门户（如 `novosti[.]dn[.]ua`、`7aac[.]gov[.]ua`），后续出现伪装成 Snapchat 主题的门户。**[多源]**
- Safari 加载该 iframe 后，先运行 **JavaScript 指纹探测**（设备型号、iOS 构建号），仅在满足条件的目标上触发后续链路，整个执行过程在数秒内完成。**[多源]**

**是否需要用户交互？**
主流判断为 **one-click**：受害者需访问或被重定向至投毒页面，此后无需任何交互。**[多源]** Kaspersky 的表述中出现过 "zero-click" 措辞，但无任何来源描述 iMessage/BLASTPASS 式的真正零点击投递，本报告按 one-click 处理。**[单源·待核]**

**受影响版本（来源存在冲突，见第 9 章）**
- iVerify / Zimperium / Holland & Knight：**iOS 18.4 – 18.7**
- runZero：18.0 – 18.7.2 与 26.0 – 26.2 暴露
- Help Net Security 引述研究者：合并攻击波及「iOS 13 至 18.6.2 的数亿台未修补设备」
- **企业可辩护区间建议采用：iOS 18.4–18.7.2 与 26.0–26.2**；「iOS 13+」的影响面数字视为未经证实的上限宣传。

### 3.2 完整利用链（六阶段）

```
┌─────────────────────────────────────────────────────────────────────┐
│  阶段 0：水坑投递                                                    │
│  合法站点被注入隐藏 iframe → Safari 加载 → JS 指纹探测（型号/版本）  │
│  ※ 非命中目标直接放弃，降低暴露概率                                  │
└──────────────────────────┬──────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────────┐
│  阶段 1：WebContent 进程 RCE                                         │
│  CVE-2025-31277（JavaScriptCore，缓冲区溢出 / JIT RegExp 类型混淆）  │
│  或 CVE-2025-43529（WebKit JIT，StoreBarrierInsertionPhase UAF）     │
│  → 获得 WebContent 沙箱内代码执行                                    │
└──────────────────────────┬──────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────────┐
│  阶段 2：缓解绕过                                                    │
│  CVE-2026-20700（dyld 内存破坏）→ 绕过 PAC / TRO                     │
│  → 用户态任意代码执行（不再受指针认证约束）                          │
└──────────────────────────┬──────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────────┐
│  阶段 3：沙箱逃逸 #1（WebContent → GPU 进程）                        │
│  CVE-2025-14174（WebKit ANGLE / WebGPU 越界写）                      │
└──────────────────────────┬──────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────────┐
│  阶段 4：沙箱逃逸 #2（GPU 进程 → mediaplaybackd 守护进程）           │
│  利用媒体播放守护进程的 XPC 信任关系横向移动                         │
└──────────────────────────┬──────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────────┐
│  阶段 5：内核提权（双路径）                                          │
│  CVE-2025-43510（内核内存管理 / 锁校验缺陷，经 mediaplaybackd）      │
│  CVE-2025-43520（内核内存破坏 → 任意内核写）                         │
│  → 内核态任意读写，绕过沙箱与数据保护                                │
└──────────────────────────┬──────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────────┐
│  阶段 6：载荷执行与数据窃取（内存态，无落盘持久化）                  │
│  将 JavaScript 注入原生守护进程（如 Springboard）而非投放独立二进制  │
│  窃取：Keychain、加密钱包、iCloud 凭据、通讯录、SMS/iMessage、       │
│        Telegram/WhatsApp、Cookie、照片、Wi-Fi 配置、位置、SIM、      │
│        备忘录、健康数据                                              │
│  完成后立即删除暂存文件（"hit-and-run"），无持久化驻留               │
└─────────────────────────────────────────────────────────────────────┘
```

**[多源]** 阶段顺序依据 iVerify，由 ipinsights 与 secrss 交叉印证。

### 3.3 0-day 与 n-day 构成

Apple 对以下三个漏洞均加注「may have been exploited in an extremely sophisticated attack against specific targeted individuals」：

| CVE | 组件 | 性质 | 修复版本 | 修复日期 | 置信度 |
|---|---|---|---|---|---|
| CVE-2025-43529 | WebKit（JIT UAF） | **0-day** | iOS/iPadOS **26.2**、**18.7.3** | 2025-12-12 | [确证] |
| CVE-2025-14174 | WebKit / ANGLE（越界写） | **0-day** | iOS/iPadOS **26.2**、**18.7.3**（同期 macOS Tahoe 26.2、Safari 26.2、tvOS/watchOS/visionOS 26.2） | 2025-12-12 | [确证] |
| CVE-2026-20700 | dyld（内存破坏 → PAC 绕过） | **0-day** | iOS/iPadOS **26.3**（同期 macOS/tvOS/watchOS/visionOS 26.3 及旧分支） | 2026-02-11 | [确证] |

工具包运行时已属 n-day（已修补但设备未更新）的三个：

| CVE | 组件 | 修复版本 | 说明 | 置信度 |
|---|---|---|---|---|
| CVE-2025-31277 | JavaScriptCore | iOS 18.6（2025-07-29 报告） | 自身亦曾被在野利用，但 DarkSword 于 2025-11 起被观测时已属 n-day | [多源] ⚠ 组件/版本映射待与 Apple 公告逐条核对 |
| CVE-2025-43510 | 内核 | iOS **26.1**（2025-11-03）+ 18.7.2 回移植 | Apple 公告**未**标注在野利用 | [多源] ⚠ |
| CVE-2025-43520 | 内核 | iOS **26.1**（2025-11-03）+ 18.7.2 回移植 | Apple 公告**未**标注在野利用 | [多源] ⚠ |

**关键洞察**：DarkSword 中**一半的漏洞是已修补的 n-day**。这意味着**单纯的补丁管理就能切断该利用链**——攻击之所以成功，主要归因于设备未及时更新，而非 Apple 无修复可用。这对企业是好消息，也是最应投入的控制点。

> 关于 0-day 数量的来源分歧：Help Net Security 称仅 dyld 一个为确证 0-day；某个人博客称六个全为 0-day。二者均与 Apple 公告不符，**「3 个 0-day + 3 个 n-day」（CSA、ipinsights 口径）为准确表述**。

### 3.4 载荷行为特征

**载荷命名**：GHOSTBLADE（UNC6353）、GHOSTKNIFE（UNC6748）、GHOSTSABER（PARS Defense）。**[单源·待核]** 该命名仅见于 ipinsights 与一个个人博客，未获一线厂商 corroborate，引用时应注明来源局限。

**行为特征与检测含义**：
- **无持久化**：不安装描述文件、不投放独立二进制、不驻留启动项。窃取完成后立即删除暂存文件。
- **注入式执行**：将 JavaScript 注入 `Springboard` 等原生守护进程，借用合法进程身份，规避「异常可执行文件」类检测。
- **检测后果**：传统基于植入物（implant）的狩猎方法**完全失效**；同时，设备重启会终止攻击，但也会**销毁全部运行时证据**。这是取证上的两难（见 7.4）。

### 3.5 多主体扩散

| 主体 | 归属判断 | 目标地区 |  lure / 场景 | 载荷 | 置信度 |
|---|---|---|---|---|---|
| **UNC6353** | 疑似俄罗斯国家背景；与 Coruna 有关联；兼有加密资产窃取动机 | 乌克兰 | 被入侵的新闻/政府门户 | GHOSTBLADE | [多源] |
| **UNC6748** | 未明确归属（国家或国家关联） | 沙特阿拉伯 | 伪装 Snapchat 主题门户 | GHOSTKNIFE | [多源] |
| **PARS Defense** | 土耳其**商业监控厂商**，2025-11 起活跃 | 土耳其、马来西亚 | 商业监控订单 | GHOSTSABER | [多源] |
| **TA446 / Star Blizzard** | FSB 关联（Proofpoint 归因） | 政府、智库、高校、金融、法律 | 鱼叉式钓鱼 | 使用**从他人基础设施泄露的副本** | [多源] |

**受害者画像**：乌克兰、沙特、土耳其、马来西亚；律师、记者、企业高管、政府与媒体人员。**[多源]**

**商业模式**：一致描述为**中介撮合 / 能力租赁**，而非各主体自研；各主体仅做轻度定制。**[多源]** Help Net Security 提及中介名为 "Matrix LLC / Operation Zero"，**[单源·待核]**。

> **TA446 使用泄露副本**这一点是本报告最重要的战略结论：iOS 全链能力已经发生**外泄与二次扩散**，能力边界不再可预测。防御方不能再假设「只有国家级对手才具备此能力」。

### 3.6 与历史全链行动的对比

| 维度 | Operation Triangulation (2023) | Coruna (2025 披露) | **DarkSword (2025–2026)** |
|---|---|---|---|
| 投递 | iMessage 零点击（附件触发） | 多链路 | **水坑 + JS 指纹筛选（one-click）** |
| 目标版本 | iOS 14.7–16.4 时代 | iOS 13 – 17.2.1 | **iOS 18.4 – 26.2（当代版本）** |
| 漏洞规模 | 4 个（含未文档化 MMIO） | 5 条链 / 23 个利用 | 6 个（3 × 0-day） |
| 持久化 | 有（重启后需重感染） | 有 | **无（打完即走）** |
| 使用主体 | 单一国家背景 | 商业买家 → UNC6353 → UNC6691 | **≥4 个独立主体，含泄露副本使用者** |
| 目的 | 情报监控 | 监控 + 加密窃取 | 监控 + **大规模加密窃取** |

**[多源]** 需要纠正的常见误传：**未发现任何来源将 Coruna 与 Graphite 关联**；Kaspersky 称 DarkSword 相关工具包之一源自 Operation Triangulation 架构，此为**单源**主张，无其他来源印证。**Kismet、Pegasus、Predator 在所有 DarkSword 报道中均未被提及**，任何此类对比都属于分析推测而非既有事实。

**真正的新意在于四点**：(a) 同一工具包被多主体采用，含国家 APT、商业厂商与使用泄露副本的犯罪组织——是**能力扩散**而非单一主体的技术进步；(b) **瞄准当代 iOS 版本**，而非历史版本；(c) **无植入物、无持久化**的纯内存态 JS 注入，直接击穿以植入物为中心的检测范式；(d) 谍报工具被复用于**大规模经济犯罪**，受害者基数从「数百人」变为「潜在数亿人」。

---

## 4. 在野利用 CVE 证据表（2023 – 2026.10）

> 说明：下表「Apple 在野利用声明」列为 Apple 公告措辞的转述，非逐字引用（本次研究未能重新抓取全部 Apple 单页公告）。⚠ 标记表示对原始假设有修正或存在未核实项。

| CVE | 组件 | 漏洞类型 | 修复 iOS/iPadOS | 修复日期 | Apple 在野利用声明 | 归功者 |
|---|---|---|---|---|---|---|
| CVE-2023-23529 | WebKit | 类型混淆 | 16.3.1 | 2023-02-13 | 可能已被主动利用 | 匿名 |
| CVE-2023-32434 | XNU 内核 | 越界写 | 16.5（另 15.7.6 / 16.4.1） | 2023-05-18 | 极复杂定向攻击 | Kaspersky（Operation Triangulation） |
| CVE-2023-38606 | **未文档化硬件特性（MMIO 寄存器）** | 逻辑 / 权限绕过 | 16.6 | 2023-07-24 | 极复杂定向攻击 | Kaspersky（Operation Triangulation） |
| CVE-2023-41990 | Fonts / FontParser | 逻辑 / 提权 | 17.0.3、16.7.1 | 2023-10-10/11 | 已针对 iOS 16.7 之前版本利用 | Bill Marczak & Maddie Stone，Google TAG |
| CVE-2023-42917 | WebKit | 内存破坏 | 17.1.2、16.7.3 | 2023-11-30 | 极复杂定向攻击 | Google TAG |
| CVE-2024-23222 | WebKit | 类型混淆 | 17.3（另 16.7.5 / 15.8.1） | 2024-01-22 | 可能已被主动利用 | 匿名 |
| CVE-2024-23296 | RTKit（实时 OS） | 释放后使用 | 17.4 | 2024-03-05 | 极复杂定向攻击（各版本表述略有差异） | 匿名 |
| CVE-2024-27804 | JavaScriptCore | 越界写 | 17.5 | 2024-05-13 | 极复杂定向攻击 | 匿名 |
| CVE-2024-44131 ⚠ | JavaScriptCore | 越界写 | 17.7.2 / 18.1.1 时段（静默修复） | ~2024-11/12 | **Apple 未标注在野利用** — 该主张来自 Qualys ThreatProtect | 未具名 |
| CVE-2024-44308 | JavaScriptCore | 越界写 | 18.1.1、17.7.2 | 2024-11-19 | 主动利用，极复杂定向攻击（针对 Intel Mac 系统） | Google TAG（Lecorne、Sevens） |
| CVE-2024-44309 | WebKit（Cookie 管理） | 逻辑 / 跨站脚本 | 18.1.1、17.7.2 | 2024-11-19 | 同上 | Google TAG |
| CVE-2025-24085 | CoreMedia | 释放后使用 | 18.3 | 2025-01-27 | 极复杂定向攻击（iOS 17.2 之前） | Bill Marczak（Citizen Lab）& Google TAG |
| CVE-2025-24200 | Accessibility（VoiceOver） | 逻辑 / secure-port-lock 绕过 | 18.3 | 2025-01-27 | 极复杂定向攻击；需物理接触 | Bill Marczak，Citizen Lab |
| CVE-2025-24201 | USB Restricted Mode | 逻辑 / 权限绕过 | 18.3.1 | 2025-03-11 | 需物理接触利用 | Bill Marczak，Citizen Lab |
| CVE-2025-30431 | ImageIO | 越界写 | 18.3.2 | 2025-03-31 | 极复杂定向攻击（iOS 17.2 之前） | 匿名 |
| CVE-2025-31200 | ImageIO | 越界写 | 18.4.1 | 2025-04-16 | 主动利用，极复杂定向攻击 | Apple + Google TAG |
| CVE-2025-31201 | WebKit | 释放后使用 | 18.4.1 | 2025-04-16 | 主动利用，极复杂定向攻击 | Apple + Google TAG |
| CVE-2025-43200 ⚠ | Messages（iCloud Link 照片/视频处理） | 逻辑缺陷 | 18.3.1、16.7.11、15.8.4（**公告追溯补充**） | 追溯记录于 2025-06-12/16 | 可能已被利用，极复杂定向攻击 | 未公布；媒体关联至 Paragon **Graphite** 间谍软件 |
| CVE-2025-43529 | WebKit | 释放后使用（恶意图片触发内存破坏） | 26.2、18.7.3（另有 18.6.2 早期回移植之说，见第 9 章） | 2025-12-12 | 主动利用，极复杂定向攻击 | Google TAG |
| CVE-2025-14174 | WebKit（ANGLE Metal 渲染器越界访问） | 内存破坏 | 26.2、18.7.3 | 2025-12-12 | 极复杂定向攻击 | Google TAG + Apple |
| CVE-2026-20700 | **dyld** | 内存破坏（内存写 → 任意代码执行，绕过 PAC） | 26.3（+ macOS/tvOS/watchOS/visionOS 26.3 及旧分支） | 2026-02-11 | 已知有报告称其被用于极复杂攻击 | Google TAG |
| CVE-2026-20636 ⚠ | WebKit | 内存管理 → 进程崩溃（DoS） | 26.3 | 2026-02-11 | **Apple 未标注在野利用** — 不符合本表纳入标准，仅列作参考 | 未具名 |

**关于 CVE-2026-20700 的补充**：确认为 **dyld（动态链接器）** 中的内存破坏缺陷，具备内存写能力的攻击者可借此实现任意代码执行。修复于 iOS/iPadOS **26.3**（2026-02-11），Apple 加注「已知有报告称此问题可能已被用于极复杂攻击」，归功 **Google TAG**。「存在约十年的老漏洞」这一说法源自 The Register 的标题表述，**并非 Apple 官方结论**。**[确证组件与版本 / 单源·待核「十年」]**

---

## 5. 典型漏洞类型技术分析

### 5.1 WebKit / JavaScriptCore：类型混淆与释放后使用

**机理**：JIT 编译器（DFG/FTL）为性能对 JavaScript 类型做激进推断与优化。当推断与实际运行时类型不一致（type confusion），或在优化阶段（如 `StoreBarrierInsertionPhase`）对对象生命周期判断错误（UAF），即可产生越界读写原语。攻击者随后通过经典的堆布局（heap grooming）将其转化为 `addrof` / `fakeobj` 原语，最终获得 WebContent 进程内任意代码执行。

**为何反复出现**：JavaScriptCore 是数百万行级别的 C++ 代码，JIT 优化 pass 数量庞大，每个 pass 都是独立的可攻击逻辑面。这也是欧盟 DMA 强制开放第三方浏览器引擎后，攻击面将进一步扩大的原因。

**缓解现状**：WebKit 进程运行在强沙箱内，单独的 WebKit RCE **不等于**设备沦陷——它只是攻击链的第一环。DarkSword 必须再叠加 dyld PAC 绕过、ANGLE 沙箱逃逸与两个内核漏洞才能达成完整控制，这正说明分层防御在起作用。

### 5.2 媒体与文件解析：ImageIO / CoreMedia / FontParser / CoreAudio

**机理**：图像、音视频、字体格式规范极其复杂（HEIC、TIFF、PDF、TrueType 指令集），解析器需处理攻击者完全可控的二进制输入。越界写（CVE-2025-30431、CVE-2025-31200）与释放后使用（CVE-2025-24085）是主要缺陷形态。

**危险性**：这类漏洞常可达成**零点击或近零点击**触发——iMessage 收到附件即预渲染（CVE-2025-43200 即为 iCloud Link 图片/视频处理路径），FaceTime 来电即解码，无需用户点开。CVE-2023-41990 更是通过字体解析达成提权。

**防御要点**：BlastDoor（iOS 14+ 引入的 iMessage 附件沙箱解析服务）显著抬高了该路径的攻击成本；Lockdown Mode 会**直接禁用大多数消息附件类型**，从根本上收缩此攻击面。

### 5.3 内核提权：XNU 与守护进程信任路径

**机理**：CVE-2023-32434 为 XNU 整数溢出导致的越界写（KFD 利用体系的核心）。DarkSword 采用**双内核漏洞**（CVE-2025-43510 内存管理/锁校验缺陷、CVE-2025-43520 内存破坏→任意内核写）以冗余保证成功率。

**值得关注的攻击路径**：DarkSword 并非直接从 WebContent 打内核，而是先横向移动到 **`mediaplaybackd`** 守护进程，再从该进程的上下文发起内核利用。**守护进程之间的 XPC 信任关系本身构成一条隐蔽的横向移动通道**——这是移动端攻击链设计中容易被防御方忽视的一环。

### 5.4 物理接触与锁屏绕过

**机理**：CVE-2025-24200（Accessibility/VoiceOver 逻辑缺陷）可被用于在**设备锁定状态**下禁用 USB Restricted Mode；CVE-2025-24201 是 USB Restricted Mode 自身的绕过；CVE-2024-23296（RTKit UAF）同属此类。

**现实威胁**：这三个漏洞的组合直接服务于**取证设备与边境检查场景**——Citizen Lab 的 Bill Marczak 是主要归功者，反映其研究焦点正是「设备被物理扣押后能否被解锁提取」。

**防御要点**：USB Restricted Mode 是抵抗物理提取的关键控制，但**它自身可被漏洞关闭**。因此物理安全不能仅依赖该机制：应启用「需要密码才能访问配件」、缩短自动锁定时间、并优先采用高级数据保护（iCloud Advanced Data Protection）使数据在设备失守时仍不可读。

### 5.5 dyld 与 PAC 缓解绕过（CVE-2026-20700）

**机理**：dyld 是每台 iOS 设备上每个进程启动都必须经过的动态链接器，位置极为基础。其中的内存破坏缺陷允许已具备内存写原语的攻击者实现任意代码执行，并**绕过指针认证（PAC）与 TRO 相关约束**。

**战略含义**：这是本报告中最具警示性的案例——**PAC 是 Apple 对抗 ROP/JOP 的核心硬件缓解，而绕过它的漏洞出现在负责加载与重定位二进制的基础组件中**。缓解机制的信任根（dyld 负责写入指针、参与 PAC 签名流程）一旦存在缺陷，整层防御随之失效。

### 5.6 未文档化硬件特性（CVE-2023-38606）

**机理**：Operation Triangulation 利用了一组**未在任何 Apple 文档中出现的 MMIO 硬件寄存器**，借此绕过 KTRR/PPL 等内存保护，实现内核内存的隐蔽读写。该漏洞由 Kaspersky GReAT 发现，Apple 通过移除对这些寄存器的访问权限修复。

**战略含义**：这是 iOS 安全史上最深刻的教训之一——**攻击面包含供应商自身未公开、甚至可能未纳入威胁建模的硬件行为**。防御方无法通过阅读文档得知此类风险的存在，只能通过异常行为检测（Kaspersky 正是通过崩溃日志与字体缓存文件的异常发现的）间接暴露。

---

## 6. iOS 纵深防御机制与其失效点

| 防御层 | 设计目标 | 已知的失效/绕过实例 | 残余风险评估 |
|---|---|---|---|
| **代码签名 / AMFI / APRR** | 只运行 Apple 或已签名代码 | 攻击者不投放二进制，改为**注入合法进程**（DarkSword 注入 Springboard） | **高**：注入式执行完全规避签名检查 |
| **应用沙箱（Seatbelt / TrustedBSD MAC）** | 限制进程权限与文件访问 | CVE-2025-14174（ANGLE/WebGPU 越界写）实现 WebContent→GPU 逃逸；再经 `mediaplaybackd` 二次逃逸 | **高**：XPC 信任关系是薄弱面 |
| **KTRR / CTRR** | 硬件锁定内核只读内存 | CVE-2023-38606 借未文档化 MMIO 寄存器绕过 | **中**：修复后无公开重现，但同类硬件盲区风险不可排除 |
| **PPL → SPTM + TXM（iOS 17+）** | 页表与执行监控移出内核，独立特权域 | DarkSword 采用**双内核漏洞**（43510 + 43520）达成任意内核写 | **中**：架构显著抬高成本，但内核内存破坏仍是主战场 |
| **PAC（指针认证，A12+）** | 硬件签名指针，阻断 ROP/JOP | **CVE-2026-20700（dyld）绕过 PAC/TRO** | **高**：缓解自身成为攻击目标 |
| **BlastDoor（iMessage 附件沙箱）** | 隔离解析不可信消息内容 | CVE-2025-43200（iCloud Link 图片/视频处理逻辑缺陷）被用于定向攻击 | **中**：仍是最有效的消息侧防线之一 |
| **数据保护（NSFileProtection + SEP）** | 文件级加密，密钥由 Secure Enclave 管理 | 内核任意读写 + 设备已解锁状态下，可读取已解密数据与 Keychain | **中**：锁屏状态下保护强，解锁后显著削弱 |
| **USB Restricted Mode** | 锁定后禁用有线数据连接 | CVE-2025-24200 / 24201 可在锁定状态禁用之 | **高（物理接触场景）** |
| **Lockdown Mode（iOS 16+）** | 极端收缩攻击面：禁用 JIT 相关能力、绝大多数字体与消息附件类型、有线连接、部分 Web 技术 | 截至目前**无公开的 Lockdown Mode 全链绕过**报道 | **低**：目前最有效的单项控制，代价是功能受损 |
| **Rapid Security Response（RSR）** | 在不发布完整版本的情况下快速推送关键 WebKit 修复 | 依赖用户/MDM 主动启用与推送 | **低-中**：机制有效，落地率是瓶颈 |
| **Apple Threat Notifications** | Apple 主动通知疑似雇佣间谍软件攻击的目标 | 覆盖面有限，且攻击者会试图规避 | **中**：有价值但不可依赖 |

**核心判断**：iOS 的安全架构在业界仍属最强，其价值不在于「无法被攻破」，而在于**迫使攻击者必须组合 4–6 个漏洞才能达成完整控制**——这直接推高了攻击成本、拉长了开发周期、增加了暴露概率（DarkSword 泄露给 TA446 即是暴露的产物）。但**没有任何单层可以独立依赖**，且缓解机制自身（PAC via dyld、KTRR via MMIO）已被证明是可攻击的。

---

## 7. 检测与响应（企业视角）

### 7.1 主机侧信号

DarkSword 相关的可观测痕迹 **[多源，主要来自 Zimperium 与 iVerify]**：

**统一日志（Unified Log）中的强特征：**
- `mediaplaybackd` 相关日志序列出现 `[CHAIN] .. [MAIN] .. [DarkSword-WIFI-DUMP]` 形式的标记——这是**最高置信度的单一指标**，几乎不存在误报
- Safari / GPU 进程日志中反复出现 `GPUProcessProxy::childConnectionDidBecomeUnresponsive`——利用失败后的恢复循环，代表**尝试性攻击**（含未遂）

**文件系统瞬态痕迹（存活时间极短）：**
- `/tmp/` 与 `/private/var/tmp/` 下出现被导出的 Keychain 数据库、钱包抓取结果、凭据导出文件
- 对 `com.bitcoin.*`、`io.metamask.*` 等标识符的异常读取行为

**行为侧信号：**
- 浏览会话结束后立即出现异常的出站 HTTPS 突发流量
- `Springboard` 或 `mediaplaybackd` 行为异常（可经 MDM 侧观测）
- 进程崩溃增多与内存压力异常升高

> **重要**：由于载荷自清理，**崩溃日志与守护进程日志往往是唯一存活的证据**。这意味着检测策略必须从「找植入物」转向「找异常日志序列」。

### 7.2 网络侧 IOC

| 类型 | 指标 |
|---|---|
| 域名 | `static.cdncounter[.]net`、`cdncounter[.]net`、`sqwas.shapelie[.]com`、`snapshare[.]chat`、`novosti[.]dn[.]ua`、`7aac[.]gov[.]ua` |
| 端口 | 8881 / 8882（`sqwas.shapelie[.]com`） |
| IP | `141.105.130[.]237`、`62.72.21.10` |

**[多源]** 注意 `novosti[.]dn[.]ua` 与 `7aac[.]gov[.]ua` 属**被入侵的合法站点**，不应直接封禁（会阻断正常业务与政府信息访问），正确做法是**监控对它们的访问并告警**，同时通知站点所有方。CDN 类域名（`cdncounter[.]net`）伪装性强，封禁前应评估业务影响。

IOC 时效性短，建议同步至内部威胁情报平台并设置 90 天复核。

### 7.3 MDM 的能力边界

**MDM 能做的：**
- 强制版本基线与补丁合规（**这是当前最有效的单一控制**，理由见 3.3：DarkSword 一半漏洞是 n-day）
- 配置 Lockdown Mode、USB Restricted Mode、iCloud 高级数据保护
- 采集设备清单、上报异常配置与描述文件
- 集成 Mobile Threat Defense（Zimperium / Lookout / iVerify 等）获取行为侧告警

**MDM 做不到的（必须向管理层明确说明）：**
- **无法阻止或检测内核态内存利用**：iOS 不允许第三方内核扩展或驱动级 Agent，MDM 运行在管理平面而非执行平面
- **无法发现内存态、无持久化的载荷**：DarkSword 不落盘、不安装描述文件，MDM 的合规检查项全部通过
- **无法在设备解锁后被攻陷时保护数据**：内核任意读写意味着数据保护被绕过
- **无法提供传统 EDR 级别的进程行为遥测**

**结论**：把 iOS 安全完全托付给 MDM 是**错误的控制假设**。MDM 的价值在于**补丁合规与配置基线**，检测必须依赖网络侧、日志离线分析与 MTD 产品的组合。

### 7.4 取证注意事项

**核心困境**：DarkSword 类攻击无持久化 → 设备重启会终止攻击，但**同时销毁全部运行时证据**。

**建议处置流程：**

1. **不要立即重启或恢复出厂设置。** 这是最常见的错误响应，会永久失去取证机会。
2. **先采集易失性证据**：触发 sysdiagnose（音量上+音量下+电源键组合，或经 MDM 下发）获取统一日志、崩溃报告、当前进程与网络状态快照。
3. **同步保全云端证据**：iCloud 备份、iMessage 云端副本、Web 浏览历史（若开启同步）——在设备侧证据被清理后，云端可能是唯一来源。
4. **应用 Kaspersky 的 Operation Triangulation 检测方法论**：离线分析 sysdiagnose 中的崩溃日志与字体缓存文件（`/var/mobile/Library/Caches`），寻找与已知利用行为匹配的异常记录。该方法对**历史感染**（已重启、运行时证据已消失）仍有效，因为它依赖的是持久化的日志与缓存残留。**[确证方法论]**
5. **判定为高危感染后**：完成取证 → 设备**擦除并重装最新版 iOS**（不要在旧版本上恢复）→ 全部凭据轮换（Apple ID、Keychain 中的服务密码、加密钱包私钥视为已泄露并从干净设备重建）→ 检查是否需从备份恢复（**备份可能已含被窃取数据的痕迹，谨慎使用**）。
6. **同步人员安全措施**：高价值目标应假设其通信在感染窗口内已被完整读取，通知相关方并评估披露义务。

---

## 8. 加固建议与合规基线

### 8.1 分层控制建议

| 人群 | 版本要求 | Lockdown Mode | 附加措施 |
|---|---|---|---|
| **全员（企业标准）** | iOS/iPadOS **26.3+**（无法升 26.x 者至少 **18.7.3+**） | 不强制 | 自动更新开启；MDM 合规监控；禁止侧载描述文件；iCloud 高级数据保护 |
| **接触敏感数据的岗位**（财务、法务、研发、HR、IT 管理员） | **26.6**（当前最新安全水位） | 建议开启 | 独立设备用于高风险浏览；禁用非必要的 iMessage 附件类型；MTD 客户端 |
| **高风险人群**（高管、记者、涉政府/国防/并购交易人员、异见人士、加密资产大额持有者） | 最新版 + 72 小时内响应任何 WebKit 类在野漏洞 | **强制开启** | 专用设备与专用 Apple ID；避免在主力设备访问不熟悉链接；定期（建议每季度）擦除重装；行程前后设备管控；使用 Apple Threat Notifications 注册渠道 |

### 8.2 补丁 SLA 基线（建议纳入企业安全策略）

| 漏洞类别 | 响应时限 | 依据 |
|---|---|---|
| Apple 标注「已被主动利用」的 WebKit/JavaScriptCore 漏洞 | **72 小时** | 该家族占在野漏洞近半数，且利用代码在披露后数日内即出现 |
| Apple 标注在野利用的内核 / dyld / 沙箱相关漏洞 | **72 小时** | 直接构成完整链路的一环 |
| Rapid Security Response（RSR）推送 | **24 小时** | RSR 本身即为紧急 WebKit 修复通道，延迟无正当性 |
| 其他在野利用漏洞（媒体解析、物理接触类） | **7 天** | 需评估触发条件与暴露面 |
| 常规月度安全更新 | **30 天** | 标准基线 |

**为什么 DarkSword 的一半漏洞是 n-day 这件事如此重要**：它把「补丁管理」从一项日常运维工作，提升为**能直接切断已知在野全链攻击的控制措施**。在上述 SLA 下，DarkSword 的六个环节中有三个（CVE-2025-31277、43510、43520）在攻击发生时就已不可用。

### 8.3 Lockdown Mode 的部署建议与代价

**收益**：截至目前**无公开的 Lockdown Mode 全链绕过**。它禁用 JIT 相关能力、绝大多数字体与消息附件类型、有线连接与部分 Web 技术，直接消灭了本报告第 5 章中 5.1、5.2 两类最主要的攻击面。

**代价（必须提前告知用户，否则会被绕过或关闭）：**
- 大多数消息附件类型无法查看（仅保留图片等少数类型）
- 部分网站功能异常（Web 字体、部分 JIT 依赖的复杂应用、视频会议类 Web 应用）
- 有线连接受限（部分配件、开发调试受影响）
- 无法加入 iMessage 部分高级功能

**建议**：对高风险人群强制开启并接受功能损失；对普通员工提供**自助开启入口 + 明确的收益说明**，而非一刀切强制（一刀切会导致用户因功能受阻而私自关闭，反而降低整体安全水位）。

### 8.4 其他建议

- **启用 iCloud 高级数据保护（Advanced Data Protection）**：端到端加密扩展到绝大多数 iCloud 数据类型，在设备失守时保护云端数据。
- **缩短自动锁定时间至 30 秒–2 分钟**，并启用「访问配件需密码」，压缩物理接触窗口。
- **禁止用户安装来源不明的配置描述文件**（MDM 策略），这是商业间谍软件常见的持久化入口。
- **对高风险人群实施定期擦除重装（建议每季度）**：在无持久化攻击普及的背景下，擦除重装是最可靠的「清除未知状态」手段。
- **建立 Apple 安全公告的自动化订阅与内部告警流水线**：抓取 `support.apple.com/en-us/100100`，对含 "exploited" / "actively exploited" 字样的条目自动触发应急流程。
- **将本报告 7.2 的 IOC 纳入网络检测**，并对被入侵的合法站点采取「监控告警」而非「直接封禁」策略。

---

## 9. 情报冲突与不确定性登记

在依据本报告做处置决策前，请注意以下已识别的来源矛盾。**这是本报告最重要的诚实性声明部分。**

| # | 争议点 | 冲突来源 | 本报告采用立场 | 建议验证方式 |
|---|---|---|---|---|
| 1 | DarkSword 受影响版本范围 | iVerify/Zimperium/H&K：18.4–18.7；runZero：18.0–18.7.2 + 26.0–26.2；Help Net Security：iOS 13–18.6.2「数亿台」 | 采用 18.4–18.7.2 + 26.0–26.2 为企业可辩护区间；「iOS 13+」视为未证实的影响面宣传 | 查阅各利用对应 CVE 的 Apple 公告影响版本列表 |
| 2 | 是否为零点击 | Kaspersky 措辞含 "zero-click"；其余全部来源为 one-click（需访问投毒页） | **one-click** | 无任何来源描述 iMessage 投递路径 |
| 3 | 0-day 数量 | Apple 公告：3 个（43529、14174、2026-20700）；Help Net Security：仅 1 个；某个人博客：6 个 | **3 个**（以 Apple 公告为准） | 逐条核对 Apple 26.2 / 26.3 公告加注 |
| 4 | CVE-2025-43529 是否存在 18.6.2 早期回移植 | 一来源称 2025-08-20 于 iOS 18.6.2 修复；多源称 2025-12-12 于 26.2 / 18.7.3 修复 | 以 **26.2 / 18.7.3（2025-12-12）** 为准，18.6.2 之说存疑 | 抓取 Apple「About the security content of iOS 18.6.2」原文比对 CVE 列表 |
| 5 | 载荷命名 GHOSTBLADE / GHOSTKNIFE / GHOSTSABER | 仅 ipinsights 与一个个人博客；无一线厂商印证 | 标注为**可能但未确证** | 等待 Google/Mandiant 原始报告全文或二次印证 |
| 6 | 中介商 "Matrix LLC / Operation Zero" | 仅 Help Net Security 单一来源 | 标注为**单源·待核**，不作为决策依据 | 需第二个独立来源 |
| 7 | DarkSword 源自 Operation Triangulation 架构 | 仅 Kaspersky 主张 | 标注为**单源**，不纳入结论 | 需代码级比对证据 |
| 8 | Coruna 与 Graphite 的关联 | **无任何来源支持**该关联 | **明确否定**该常见误传 | — |
| 9 | CVE-2024-44131 是否在野利用 | Qualys ThreatProtect 称是；**Apple 公告未加注** | 不计入 Apple 在野利用统计，仅列作参考 | 核对 Apple 17.7.2 / 18.1.1 公告原文 |
| 10 | CVE-2026-20636 是否在野利用 | 部分中文来源暗示；**Apple 公告未加注**，性质为 DoS | **排除**在野利用清单 | 核对 Apple iOS 26.3 公告原文 |
| 11 | 「CVE-2026-20700 是存在十年的老漏洞」 | The Register 标题表述；非 Apple 结论 | 标注为媒体说法，**非官方** | Apple 公告无漏洞引入时间信息 |
| 12 | 生成式 AI 辅助移植攻击代码 | CSA / Holland & Knight / secrss 提及，但无技术证据 | 标注为**报道性主张**，不纳入技术结论 | 需代码层面的实证 |
| 13 | 2026 年 9–10 月是否有新的在野利用公告 | 新加坡 CSA 发布 AL-2026-130「High-Severity Vulnerability in Apple Products」（约 2026-09-30），但本次研究**未能获取其正文与 CVE 编号** | 报告结论截止至 iOS 26.6（2026 年 9 月，78 个漏洞，**未标注在野利用**） | **上线前请核实该公告**：https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-130/ |

**方法论局限**：本次研究未能成功抓取 Apple 官方安全公告索引页（`support.apple.com/en-us/100100`）的完整历史条目，部分早期条目的修复版本与措辞系依据已被广泛记录的公告内容转述，标注为「转述，非逐字引用」。第 4 章表格中 2023 年至 2025 年初的条目为高置信度，但建议在正式对外发布前对 Apple 原始公告做一轮逐条核对。

---

## 10. 残余风险与展望

**未解决的风险：**

1. **补丁落地率是最大缺口。** DarkSword 成功的主因不是漏洞先进，而是设备未更新。企业环境中长尾的老旧设备（尤其无法升级至 26.x 的机型）构成持续暴露面。
2. **能力扩散不可逆。** TA446 使用泄露副本这一事实意味着 iOS 全链工具的持有者集合已无法枚举。防御方必须假设「具备此能力的对手数量在持续增加」。
3. **无持久化攻击使检测窗口极短。** 攻击在数秒内完成并自清理，实时检测几乎不可能；事后取证依赖日志残留，而日志在 iOS 上的可获取性与保留期均有限。
4. **缓解机制自身成为攻击目标。** PAC 绕过（dyld）、KTRR 绕过（未文档化 MMIO）表明：Apple 每引入一层新防御，就为攻击者提供了一个新的研究目标。SPTM/TXM 作为 iOS 17+ 的新架构，**尚未经受同等强度的公开检验**，应视为未来的高风险研究对象。
5. **DMA 驱动的第三方浏览器引擎开放**将扩大 WebKit 之外的远程攻击面（欧盟市场设备）。
6. **物理接触类漏洞服务于取证设备市场**，其需求方稳定存在，此类漏洞的挖掘动力不会下降。

**趋势判断（12–18 个月）：**
- 商业间谍软件与犯罪组织的工具复用将进一步模糊「定向攻击」与「大规模攻击」的边界
- 内存态、无持久化将成为 iOS 攻击载荷的默认设计（因为它是唯一能规避现有检测的形态）
- Apple 预计将继续加码 SPTM/TXM、Exclaves 等硬件级隔离，并可能扩展 Lockdown Mode 的默认适用范围
- 检测市场将向「日志离线分析 + 云端行为关联 + MTD」的组合演进，因为主机侧实时检测在 iOS 上无技术可行性

---

## 附录 A：术语表

| 术语 | 说明 |
|---|---|
| **0-day / n-day** | 0-day 指厂商尚未发布修复即被利用；n-day 指已有修复但目标设备未更新 |
| **ESATI** | Apple 公告措辞 "extremely sophisticated attack against specific targeted individuals"，针对特定个人的极复杂攻击 |
| **全链（Full-chain）** | 从远程初始访问到内核控制的完整漏洞组合，无需用户预先越狱或安装软件 |
| **水坑攻击（Watering Hole）** | 入侵目标群体会访问的合法网站，等待受害者上门 |
| **PAC** | Pointer Authentication Codes，A12+ 芯片的指针签名机制 |
| **PPL / SPTM / TXM** | Page Protection Layer；iOS 17+ 由 Secure Page Table Monitor 与 Trusted Execution Monitor 取代，将页表与执行监控移出内核 |
| **KTRR / CTRR** | Kernel Text Readonly Region，硬件锁定内核只读内存 |
| **BlastDoor** | iOS 14+ 的 iMessage 附件沙箱解析服务 |
| **Lockdown Mode** | iOS 16+ 的极端防护模式，大幅收缩攻击面 |
| **RSR** | Rapid Security Response，无需完整版本即可推送的关键修复 |
| **Google TAG** | Threat Analysis Group，长期追踪雇佣间谍软件与定向攻击 |
| **MDM / MTD** | Mobile Device Management（设备管理）/ Mobile Threat Defense（威胁检测） |

## 附录 B：参考来源

**Apple 官方**
- [Apple security releases（安全公告索引）](https://support.apple.com/en-us/100100)
- [About the security content of iOS 26.2 and iPadOS 26.2](https://support.apple.com/en-us/125884)
- [About the security content of iOS 26.3 and iPadOS 26.3](https://support.apple.com/en-us/126346)
- [About the security content of iOS 26.1 and iPadOS 26.1](https://support.apple.com/en-il/125632)
- [About the security content of iOS 18.7.2 and iPadOS 18.7.2](https://support.apple.com/en-us/125633)
- [About the security content of iOS 18.6.2](https://support.apple.com/en-us/124925)
- [About the security content of iOS 18.3.1](https://support.apple.com/en-us/122174)
- [About the security content of iOS 15.8.4](https://support.apple.com/en-mn/122345)
- [About the security content of iOS 26.6 and iPadOS 26.6](https://support.apple.com/en-us/128066)
- [Apple Platform Security Guide（PDF）](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)

**一线威胁情报研究**
- [Google Threat Intelligence — The Proliferation of DarkSword: iOS Exploit Chain Adopted by Multiple Actors](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain)
- [Google Threat Intelligence — Coruna: a powerful iOS exploit kit](https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit)
- [Cloud Security Alliance — DarkSword: Full-Chain iOS Zero-Day Exploitation by State Actors](https://labs.cloudsecurityalliance.org/research/csa-research-note-darksword-ios-fullchain-zeroday-multiactor/)
- [iVerify — Inside DarkSword](https://www.iverify.com/blog/darksword-ios-exploit-kit-explained)
- [Zimperium — DarkSword: The Hit-and-Run Successor to Coruna](https://zimperium.com/blog/darksword-the-hit-and-run-successor-to-the-coruna-ios-exploit-kit)
- [Kaspersky — Invincible no more: DarkSword and Coruna in mass attacks](https://www.kaspersky.com/blog/ios-exploits-darksword-and-coruna-in-mass-attacks/55622/)
- [Paubox — Russian FSB-linked group deploys leaked iOS exploit kit](https://www.paubox.com/blog/russian-fsb-linked-group-deploys-leaked-ios-exploit-kit)
- [ipinsights — DarkSword iOS Exploit Kit: Six Vulnerabilities, Three Zero-Days](https://www.ipinsights.io/blog-post.php?slug=darksword-ios-exploit-kit-six-vulnerabilities-three-zero-days-and-full-device-takeover)
- [Holland & Knight — New iOS Exploit "DarkSword" and a New Era of Mobile Security](https://www.hklaw.com/en/insights/publications/2026/03/new-ios-exploit-darksword-and-a-new-era-of-mobile-security)

**技术研究与漏洞细节**
- [Modern iOS Security Features — A Deep Dive into SPTM, TXM, and Exclaves (arXiv:2510.09272)](https://arxiv.org/abs/2510.09272)
- [runZero — Apple iOS vulnerabilities (DarkSword 暴露面分析)](https://www.runzero.com/blog/apple-devices/)
- [Wikipedia — Coruna (exploit kit)](https://en.wikipedia.org/wiki/Coruna_(exploit_kit))

**新闻与公告转载**
- [The Hacker News — Apple Fixes Exploited Zero-Day Affecting iOS, macOS](https://thehackernews.com/2026/02/apple-fixes-exploited-zero-day.html)
- [The Hacker News — Apple Issues Security Updates After Two WebKit Flaws](https://thehackernews.com/2025/12/apple-issues-security-updates-after-two.html)
- [The Register — Apple patches decade-old iOS zero-day exploited in the wild](https://www.theregister.com/security/2026-02-12/apple-patches-decade-old-ios-zero-day-exploited-in-the-wild/4315395)
- [SecurityWeek — Apple Patches iOS Zero-Day Exploited in 'Extremely Sophisticated' Attack](https://www.securityweek.com/apple-patches-ios-zero-day-exploited-in-extremely-sophisticated-attack/)
- [Security Affairs — Apple fixed first actively exploited zero-day in 2026](https://securityaffairs.com/187890/security/apple-fixed-first-actively-exploited-zero-day-in-2026.html)
- [Help Net Security — DarkSword: Researchers uncover another iOS exploit kit](https://www.helpnetsecurity.com/2026-03-19/darksword-ios-exploit-iphone/)
- [Help Net Security — Apple fixes actively exploited CVE-2025-14174 / CVE-2025-43529](https://www.helpnetsecurity.com/2025-12-15/ios-macos-cve-2025-14174-cve-2025-43529/)
- [Help Net Security — Apple fixes zero-day CVE-2026-20700](https://www.helpnetsecurity.com/2026-02-12/apple-zero-day-fixed-cve-2026-20700/)
- [SOC Prime — CVE-2026-20700](https://socprime.com/blog/cve-2026-20700-vulnerability/) · [CVE-2025-14174](https://socprime.com/blog/cve-2025-14174-vulnerability/)
- [Qualys ThreatProtect — CVE-2026-20700](https://threatprotect.qualys.com/2026-02-12/apple-ios-zero-day-vulnerability-exploited-in-attacks-cve-2026-20700/) · [CVE-2025-43529](https://threatprotect.qualys.com/2025-12-16/apple-warns-of-zero-day-vulnerability-exploited-in-attack-cve-2025-43529/)
- [Forbes — iOS 26.2: Update Now Warning Issued To All iPhone Users](https://www.forbes.com/sites/kateoflahertyuk/2025-12-14/ios-262-update-now-waning-issued-to-all-iphone-users/)
- [Bitdefender — Update iOS 26.2: Apple flags WebKit flaws exploited by hackers](https://www.bitdefender.com/en-us/blog/hotforsecurity/update-ios-26-2-apple-flags-webkit-flaws-exploited-hackers)
- [Security Online — Paragon's Graphite spyware exploits iOS flaw targeting journalists](https://securityonline.info/zero-click-imessage-alert-paragons-graphite-spyware-exploits-ios-flaw-targets-journalists/)
- [CISA — Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

**国家/地区 CERT 公告**
- [CSA Singapore — AL-2025-117: Zero-Day Vulnerabilities in Apple WebKit](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2025-117/)
- [CSA Singapore — AL-2026-130: High-Severity Vulnerability in Apple Products（**待核实，见第 9 章第 13 项**）](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-130/)
- [HKCERT — Apple Products Multiple Vulnerabilities (2025-12-15)](https://www.hkcert.org/security-bulletin/apple-products-multiple-vulnerabilities_20251215)
- [HKCERT — Apple Products Multiple Vulnerabilities (2026-02-13)](https://www.hkcert.org/security-bulletin/apple-products-multiple-vulnerabilities_20260213)

**中文来源**
- [安全内参 — 通过攻陷合法网站传播的新型 iOS 漏洞利用工具包 DarkSword](https://www.secrss.com/articles/88644)
- [Spicity Enterprise — Apple security updates, September 2026](https://www.spirityenterprise.com/cve/apple-security-updates-september-2026-3/)

**低置信度来源（已识别矛盾，仅作对照，不作为决策依据）**
- [Austin Larsen 个人博客 — DarkSword six zero-day 主张（与 Apple 公告冲突）](https://austinlarsen.me/blog/darksword-ios-zero-day/)

---

*本报告基于截至 2026-10-03 的公开情报编制。iOS 威胁态势变化迅速，建议每季度复核第 4 章 CVE 表与第 8.1 版本基线，并在 Apple 发布含 "actively exploited" 字样的公告时触发即时复核流程。*

咨询 iOS 系统请咨询 Telegram：[@DZHT333333](https://t.me/DZHT333333)
