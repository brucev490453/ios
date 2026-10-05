# iOS DarkSword 漏洞网络安全分析报告

| 项目 | 内容 |
|---|---|
| 报告主题 | DarkSword iOS 全链漏洞利用工具包与防御分析 |
| 报告日期 | 2026-10-05 |
| 情报截止 | 2026-10-05（公开来源） |
| 适用对象 | 企业安全团队、移动端安全、SOC、事件响应、数字取证、高风险人员安保团队 |
| 报告性质 | 防御性威胁情报与风险分析 |
| 建议密级 | 内部 / 受控分发 |

> **安全说明**：本报告不提供攻击代码、PoC、漏洞武器化方法或可操作的利用步骤，仅用于风险识别、检测、响应与加固。
>
> **置信度标记**：
> - **[确证]**：Apple 官方公告或 Google Threat Intelligence 等一手研究来源直接确认；
> - **[多源]**：至少两个独立安全来源相互印证；
> - **[单源·待核]**：仅单一来源披露，尚缺独立验证；
> - **[冲突]**：不同来源存在明显矛盾，报告给出保守结论。

---

## 1. 执行摘要

DarkSword 是一套针对现代 iOS 的浏览器投递型全链漏洞利用工具包。公开研究将其描述为由 JavaScript 驱动、以内存态方式运行、能够从 Safari/WebContent 初始代码执行逐步完成缓解绕过、沙箱逃逸、内核提权和数据窃取的攻击框架。**[多源]**

本报告的核心判断如下：

1. **总体风险等级：严重（Critical）。** DarkSword 具备从恶意网页访问到设备高权限数据访问的完整链路，可影响通信、凭据、Keychain、云端令牌、加密钱包和位置等敏感信息。
2. **主要投递方式为水坑攻击。** 攻击者入侵合法网站并注入隐藏 iframe，对访问者进行设备型号与系统版本指纹识别，仅对满足条件的目标触发漏洞链。**[多源]**
3. **它不是传统意义上的 iMessage 零点击攻击。** 多数公开来源将其归类为 one-click 或 drive-by：受害者需要访问或被重定向至投毒网页，页面加载后无需继续交互。Kaspersky 的部分表述使用过 zero-click，存在术语冲突。**[冲突]**
4. **公开分析普遍认为完整链包含 6 个 CVE，其中 3 个在被利用时属于 0-day、3 个属于已修补但仍可攻击未更新设备的 n-day。** Apple 对 CVE-2025-43529、CVE-2025-14174 与 CVE-2026-20700 使用了“可能已被用于极复杂定向攻击”一类措辞。**[多源]**
5. **DarkSword 的战略风险高于单个漏洞。** 同一套能力被不同国家关联主体、商业监控厂商及使用泄露副本的攻击者采用，说明高端 iOS 利用能力正从少数专有平台向可复用、可租赁、可泄露的工具包演变。**[多源]**
6. **无持久化与自清理显著压缩检测窗口。** 攻击完成数据窃取后可删除暂存文件，不依赖传统植入物驻留；设备重启虽可终止运行态载荷，却也可能销毁关键易失证据。
7. **最有效的控制不是传统防病毒，而是快速补丁、Lockdown Mode、网络侧监测和取证准备。** DarkSword 链中约一半漏洞在主要攻击活动发生时已有补丁，及时升级可以直接切断攻击链。

### 1.1 风险评级

| 维度 | 评级 | 原因 |
|---|---|---|
| 可利用性 | 高 | 受害者访问投毒网页后可自动触发；攻击者会筛选版本以提高成功率 |
| 技术影响 | 严重 | 可组合实现 WebContent RCE、沙箱逃逸、内核权限和敏感数据访问 |
| 受害范围 | 中至高 | 原始活动偏定向，但工具包扩散和加密资产窃取用途扩大了潜在目标面 |
| 检测难度 | 严重 | 内存态、短驻留、自清理，iOS 又缺乏传统 EDR 级主机遥测 |
| 修复可用性 | 良好 | 相关漏洞已有 Apple 安全更新；关键问题是设备更新滞后 |
| 综合风险 | **严重** | 高影响、高隐蔽性和能力扩散叠加 |

---

## 2. DarkSword 是什么

DarkSword 被公开描述为一套面向 iOS 的全链利用工具包，而不是单一漏洞。其核心能力包括：

- 在被入侵或仿冒的网站上部署 JavaScript 投递代码；
- 识别访问者的 iPhone/iPad 型号、架构与 iOS 构建版本；
- 为匹配的设备选择相应漏洞链，避免在无关目标上暴露；
- 从 Safari WebContent 受限进程逐层突破至 GPU/媒体守护进程与内核；
- 在原生进程上下文中访问敏感数据；
- 数据外传后清理临时文件，降低取证可见性。

公开研究认为相关活动在 **2025 年 11 月前后**已被观测，并于 **2026 年 3 月**被 Google Threat Intelligence 等机构集中披露。**[多源]**

### 2.1 与单个 CVE 的区别

将 DarkSword 简称为“一个漏洞”并不准确。它是一套由多个漏洞、版本探测、进程间移动、数据收集和基础设施组成的攻击系统：

```text
水坑网页 / 仿冒页面
        ↓
设备与版本指纹识别
        ↓
WebKit / JavaScriptCore 初始代码执行
        ↓
dyld / PAC 等缓解机制绕过
        ↓
WebContent → GPU → mediaplaybackd 横向移动
        ↓
内核提权与任意读写
        ↓
原生守护进程内执行、数据收集与外传
        ↓
删除暂存文件，结束运行
```

任何一个关键环节被补丁或策略阻断，完整攻击链都可能失败。因此，企业不必等待“覆盖整个 DarkSword 的单一检测签名”，应分别控制入口、漏洞版本、横向移动信号和数据外传。

---

## 3. 投递方式与感染条件

### 3.1 水坑与仿冒站点

公开材料显示，攻击者曾在乌克兰新闻或政府相关网站中注入隐藏 iframe，也使用过 Snapchat 主题的仿冒页面。Safari 加载页面后，JavaScript 会检查设备型号与系统版本，仅对符合条件的设备继续投递。**[多源]**

这种方式具有三项优势：

1. **利用合法站点信誉**：被入侵网站本身可能具有有效 TLS 证书和长期访问历史；
2. **精准筛选目标**：减少无效利用与样本暴露；
3. **绕过邮件附件检测**：恶意内容在浏览器会话中动态加载，传统邮件网关难以直接看到完整链路。

### 3.2 是否属于零点击

| 来源口径 | 判断 |
|---|---|
| iVerify、Zimperium、Holland & Knight 等 | 需要访问或被重定向到网页，之后无需进一步交互；更准确地称为 one-click / drive-by |
| Kaspersky 部分报道 | 使用过 zero-click 表述 |
| 本报告结论 | **按 one-click / drive-by 管理**；未发现 iMessage、FaceTime 或推送通知自动触发的直接证据 |

**防御含义**：用户安全意识能够降低风险，但不能替代技术控制。合法网站被入侵时，用户无法仅靠域名、证书或页面外观判断风险。

### 3.3 受影响版本

公开来源对版本范围并不一致：

- iVerify、Zimperium、Holland & Knight：主要指向 **iOS 18.4–18.7**；
- runZero：扩大到 **iOS 18.0–18.7.2 与 iOS 26.0–26.2**；
- Help Net Security 引述的更宽口径涉及 iOS 13 至 18.6.2，但缺少逐版本漏洞链证据。

**保守防御结论**：将 **iOS 18.4–18.7.2 与 26.0–26.2** 视为重点排查范围；任何低于当前 Apple 安全更新水位的设备均应视为潜在暴露，而不应以“未在受影响列表中”为由豁免。**[冲突]**

---

## 4. 完整漏洞利用链分析

### 4.1 链路分解

| 阶段 | 漏洞 / 组件 | 公开描述的作用 | 状态与置信度 |
|---|---|---|---|
| 初始访问 | CVE-2025-31277 / JavaScriptCore | JIT/正则相关内存安全问题，用于 WebContent 进程内代码执行 | n-day；组件与精确漏洞类别需继续以 Apple 公告校验 **[多源·待核]** |
| 替代初始访问 | CVE-2025-43529 / WebKit JIT | 释放后使用或类型混淆类内存破坏，获取 WebContent 代码执行 | 公开分析列为 0-day **[多源]** |
| 缓解绕过 | CVE-2026-20700 / dyld | 利用内存破坏扩大已有内存写能力，绕过 PAC/TRO 相关约束，实现用户态任意代码执行 | Apple 确认可能被极复杂攻击利用 **[确证]** |
| 沙箱逃逸 | CVE-2025-14174 / WebKit ANGLE、WebGPU | 越界写或内存破坏，从 WebContent 向 GPU 进程扩展控制 | 公开分析列为 0-day **[多源]** |
| 进程间移动 | GPU → `mediaplaybackd` | 借助系统守护进程与 XPC 信任关系横向移动 | 非独立 CVE 阶段 **[多源]** |
| 内核提权 | CVE-2025-43510 / Kernel | 内存管理或锁验证缺陷，为内核权限路径提供条件 | n-day；Apple 未标注其单独在野利用 **[多源·待核]** |
| 内核提权 | CVE-2025-43520 / Kernel | 内存破坏，公开分析称可形成内核任意写能力 | n-day；Apple 未标注其单独在野利用 **[多源·待核]** |
| 后利用 | 原生进程 / 守护进程 | 注入或借用原生进程上下文，读取敏感数据并外传 | 无独立 CVE **[多源]** |

### 4.2 0-day 与 n-day 构成

| CVE | 分类 | Apple 修复版本 | 修复时间 | 说明 |
|---|---|---|---|---|
| CVE-2025-43529 | 公开分析列为 0-day | iOS/iPadOS 26.2、18.7.3 | 2025-12-12 | Apple 加注极复杂定向攻击相关措辞 |
| CVE-2025-14174 | 公开分析列为 0-day | iOS/iPadOS 26.2、18.7.3 | 2025-12-12 | WebKit/ANGLE 路径；同期多平台修复 |
| CVE-2026-20700 | 0-day | iOS/iPadOS 26.3 | 2026-02-11 | dyld 内存破坏；归功 Google TAG |
| CVE-2025-31277 | n-day | iOS 18.6 时期 | 2025-07 | DarkSword 被主要观测时已有补丁 |
| CVE-2025-43510 | n-day | iOS 26.1、18.7.2 回移植 | 2025-11-03 | Apple 未标注该漏洞单独在野利用 |
| CVE-2025-43520 | n-day | iOS 26.1、18.7.2 回移植 | 2025-11-03 | Apple 未标注该漏洞单独在野利用 |

> **关键结论**：约一半链路在主要活动阶段已属于 n-day。企业只要及时安装系统更新，就可能在多个位置切断完整攻击链。

### 4.3 安全机制为何仍被突破

DarkSword 并不意味着 iOS 纵深防御毫无价值。相反，攻击者必须组合多个漏洞，说明单个 WebKit RCE 无法直接控制设备：

| iOS 安全层 | 设计目标 | DarkSword 对抗方式 |
|---|---|---|
| WebContent 沙箱 | 限制网页代码接触系统资源 | 通过 ANGLE/WebGPU 路径进入 GPU 进程 |
| 进程隔离与 XPC 权限 | 限制跨进程访问 | 利用 GPU 与 `mediaplaybackd` 等系统服务间的信任边界 |
| PAC | 防止伪造控制流指针，阻断 ROP/JOP | 利用 dyld 缺陷绕过指针与链接相关约束 |
| 内核内存保护 | 防止用户态改写内核 | 组合内核漏洞形成高权限读写 |
| 代码签名 | 禁止运行未授权二进制 | 不投放独立二进制，转而借用合法进程或内存态执行 |
| 数据保护 | 锁定状态下保护文件与密钥 | 在设备解锁、获得高权限后读取已解密数据 |

---

## 5. 后利用行为与数据风险

公开研究报告的潜在数据访问范围包括：

- Keychain 中可访问的凭据与令牌；
- Apple ID / iCloud 相关会话信息；
- SMS、iMessage、Telegram、WhatsApp 等通信数据；
- 联系人、照片、备忘录、日历、位置和 Wi-Fi 配置；
- 浏览器 Cookie 与会话令牌；
- SIM 与设备身份信息；
- 加密钱包应用、钱包标识及其他数字资产相关数据；
- 部分健康数据或应用数据库。

**影响评估**：

| 资产 | 可能后果 |
|---|---|
| 身份与登录凭据 | 账户接管、横向进入企业 SaaS、绕过部分会话验证 |
| 通信内容 | 情报泄露、关系网分析、钓鱼素材扩充、人员安全风险 |
| 加密资产 | 私钥或会话被窃取后发生不可逆资金损失 |
| 位置与照片 | 跟踪、敲诈、现实世界安全威胁 |
| 企业数据 | 邮件、聊天、文档及云端令牌泄露，形成二次入侵入口 |

### 5.1 无持久化与自清理

多家研究机构将 DarkSword 描述为“hit-and-run”模式：完成收集与外传后删除暂存文件，不依赖启动项或长期驻留植入物。**[多源]**

这会导致：

- 传统基于已知恶意 App、描述文件或二进制哈希的检测失效；
- 设备重启可能结束活动，但同时清除运行态证据；
- 崩溃日志、Unified Log、网络流量和临时文件残留成为主要证据；
- 安全团队必须在隔离、止损与证据保全之间做出顺序判断。

---

## 6. 威胁主体与攻击目的

| 主体 | 公开归因 | 目标与场景 | 主要目的 | 置信度 |
|---|---|---|---|---|
| UNC6353 | 疑似俄罗斯国家背景，与 Coruna 活动存在关联 | 乌克兰新闻与政府相关站点访问者 | 情报收集与加密资产窃取 | [多源] |
| UNC6748 | 尚未明确归属于特定国家 | 沙特阿拉伯；Snapchat 主题诱饵 | 定向监控 | [多源] |
| PARS Defense | 被描述为土耳其商业监控厂商 | 土耳其、马来西亚等 | 商业监控 | [多源] |
| TA446 / Star Blizzard | Proofpoint 等来源关联至俄罗斯 FSB | 政府、智库、高校、金融与法律机构 | 间谍活动；据报使用泄露副本 | [多源] |

### 6.1 战略意义

DarkSword 最重要的变化不是某一个 CVE，而是能力扩散：

1. 同一工具包被多个互不隶属的主体使用；
2. 使用者横跨国家关联组织、商业监控公司和可能的犯罪用途；
3. 有报道称攻击者使用从其他基础设施泄露的副本；
4. 监控工具被复用于加密资产窃取，目标从少数高价值人士扩大到普通高资产用户和企业员工。

这意味着“本组织不是国家级攻击目标”不再是有效的风险豁免理由。

---

## 7. 已公开 IOC 与检测线索

> IOC 具有较短生命周期，应与行为检测结合。将被入侵的合法站点直接封禁可能产生业务影响和误报。

### 7.1 网络 IOC

| 类型 | 指标 | 建议动作 |
|---|---|---|
| 域名 | `static.cdncounter[.]net` | 历史回溯、DNS/代理告警、结合访问时间排查 |
| 域名 | `cdncounter[.]net` | 评估业务关联后阻断或监控 |
| 域名 | `sqwas.shapelie[.]com` | 重点排查与端口 8881/8882 的连接 |
| 域名 | `snapshare[.]chat` | 作为仿冒/投递基础设施处理 |
| IP | `141.105.130[.]237` | 回溯代理、防火墙、移动网络出口记录 |
| IP | `62.72.21[.]10` | 回溯代理、防火墙、移动网络出口记录 |
| 合法站点 | `novosti[.]dn[.]ua` | 被入侵站点；建议监控并结合时间窗研判，不宜永久封禁 |
| 合法站点 | `7aac[.]gov[.]ua` | 被入侵站点；建议监控并通知站点所有方 |

### 7.2 主机与日志线索

公开分析提出的可疑信号包括：

- `mediaplaybackd` 日志中出现与利用链或 Wi-Fi 数据导出相关的异常字符串；
- Safari / GPU 日志反复出现 `GPUProcessProxy::childConnectionDidBecomeUnresponsive`；
- `Springboard`、`mediaplaybackd` 异常崩溃、重启或资源使用；
- `/tmp/`、`/private/var/tmp/` 中短暂出现 Keychain、钱包或凭据导出文件；
- 对 `com.bitcoin.*`、`io.metamask.*` 等钱包标识的异常访问；
- 浏览会话后短时间内发生异常 HTTPS 突发外联；
- WebKit、GPU 或媒体进程崩溃数量在短期内显著升高。

上述信号中，进程无响应和崩溃可能由普通软件缺陷造成，必须结合访问域名、系统版本、时间关系与其他证据研判。

### 7.3 建议的检测逻辑

```text
如果：
  设备版本处于重点排查范围
并且：
  Safari 会话访问已知基础设施或异常新注册域名
并且出现以下任一项：
  - GPU/WebKit/mediaplaybackd 短时间连续崩溃
  - 浏览后立即发生异常外联突发
  - Apple Threat Notification
则：
  升级为高优先级移动端安全事件，立即保全 sysdiagnose 与网络日志。
```

---

## 8. MDM、MTD 与传统 EDR 的能力边界

### 8.1 MDM 能够完成的工作

- 强制最低 iOS 版本与自动更新；
- 检查设备合规状态、越狱迹象和异常配置描述文件；
- 管理 USB 配件策略、密码策略与数据保护设置；
- 配合 Mobile Threat Defense 产品收集有限的设备与网络侧遥测；
- 对不合规设备撤销企业资源访问权限。

### 8.2 MDM 无法完成的工作

- 无法像桌面 EDR 一样注入内核或获得完整进程树；
- 无法直接观察内存态 JavaScript 注入与内核利用；
- 无法保证发现无持久化、自清理攻击；
- 无法在设备已经获得内核级控制后继续信任本机合规状态；
- 无法仅通过“未发现恶意 App/描述文件”证明设备未受感染。

**结论**：MDM 是补丁与配置控制平台，不是 iOS 内核威胁检测平台。建议采用“MDM 合规 + MTD 行为信号 + 网络监测 + 离线取证”的组合。

---

## 9. 事件响应与数字取证流程

### 9.1 发现可疑设备后的优先顺序

1. **确认人员与业务风险**：识别设备所有者是否属于高风险岗位，记录异常发生时间和当时访问的网站；
2. **网络隔离但不要立即重启**：可切断蜂窝网络和 Wi-Fi，避免继续外传；是否开启飞行模式需考虑其对证据与远程管理的影响；
3. **采集易失证据**：尽快获取 sysdiagnose、Unified Log、崩溃日志、设备版本和应用清单；
4. **保全网络证据**：导出 DNS、代理、VPN、移动安全网关、防火墙和身份认证日志；
5. **保全云端证据**：核对 Apple ID、iCloud、邮件、企业 SSO、即时通信的登录与令牌活动；
6. **建立时间线**：关联网页访问、进程崩溃、异常外联和账户行为；
7. **从干净设备轮换凭据**：Apple ID、企业 SSO、邮件、VPN、密码管理器和关键服务会话；
8. **加密钱包按私钥泄露处理**：从可信干净设备迁移资产，不继续使用原钱包；
9. **完成取证后擦除重装**：安装最新 iOS，再重新注册 MDM；不要恢复未经审查的完整设备状态；
10. **评估数据泄露义务**：根据通信、客户、员工与监管数据暴露情况启动法务和合规流程。

### 9.2 为什么不应第一时间重启

重启可能快速终止无持久化载荷，是止损手段；但它也可能清空运行进程、内存内容和短期日志关联。对于高价值目标，应优先在受控隔离条件下采集证据，再重启或擦除。若人员安全或持续资金损失风险高于取证价值，可立即断网并重启，但必须记录决策原因。

### 9.3 重点取证数据

| 数据源 | 关注内容 |
|---|---|
| sysdiagnose | WebKit/GPU/媒体进程崩溃、异常重启、资源压力、网络状态 |
| Unified Log | `mediaplaybackd`、Safari、GPU、Springboard 的时间关联 |
| 代理/DNS/VPN | 已知 IOC、低信誉域名、异常端口、短时大流量外联 |
| Apple / SSO 登录日志 | 新设备、新地理位置、令牌重用、会话持续时间异常 |
| MDM/MTD | 系统版本、更新失败、设备完整性变化、网络告警 |
| 用户访谈 | 访问链接、异常发热、耗电、崩溃、登录通知、资产变化 |

---

## 10. 修复与加固建议

### 10.1 立即措施

- 将所有可升级设备更新到 Apple 当前支持的最新 iOS/iPadOS；
- DarkSword 重点排查设备至少达到 **iOS/iPadOS 26.3 或 18.7.3 以上**，以覆盖公开链路的关键修复；
- 对 iOS 18.4–18.7.2、26.0–26.2 及更低版本建立专项资产清单并限制访问企业资源；
- 对高风险人员开启 **Lockdown Mode（锁定模式）**；
- 回溯已知 IOC 与 Safari/GPU/媒体进程崩溃记录；
- 检查 Apple Threat Notifications 与企业身份平台的异常登录；
- 对无法升级的设备执行退役或隔离，不以其他配置控制替代安全更新。

### 10.2 补丁 SLA

| 情况 | 建议 SLA |
|---|---|
| Apple 标注已被在野利用的 WebKit、JavaScriptCore、内核或 dyld 漏洞 | 72 小时内完成高风险人员与关键岗位升级 |
| Rapid Security Response | 24 小时内验证并部署 |
| 其他严重远程代码执行漏洞 | 7 天内 |
| 常规安全更新 | 30 天内 |
| 无法更新的设备 | 立即限制企业访问并制定退役日期 |

### 10.3 高风险人员基线

- 强制 Lockdown Mode；
- 使用独立工作设备与独立 Apple ID，避免个人加密资产和企业数据共存；
- 禁止安装来源不明的描述文件和企业证书；
- 缩短自动锁定时间，启用“访问 USB 配件需要解锁”；
- 开启 iCloud 高级数据保护，并为 Apple ID 配置安全密钥或强多因素认证；
- 不在主工作设备打开来源不明的短链接、二维码和即时消息链接；
- 对经常出差、接触政府/国防/并购信息或持有大量加密资产人员实施定期安全检查；
- 接到 Apple Threat Notification 后按高级别事件响应，不应自行忽略。

### 10.4 Lockdown Mode 的价值与代价

Lockdown Mode 会限制部分 Web 技术、消息附件、有线连接和邀请功能，可显著收缩 WebKit、字体、媒体解析等高风险攻击面。截至本报告日期，没有可信公开材料证明 DarkSword 已完整绕过 Lockdown Mode。**[多源]**

代价包括部分网站功能异常、附件受限和配件兼容问题，因此应在高风险人群中强制部署，在普通人群中提供清晰说明和自助启用渠道。

---

## 11. SOC 检查清单

### 11.1 预防

- [ ] MDM 已强制最低安全版本；
- [ ] 自动更新与 Rapid Security Response 已开启；
- [ ] 高风险人员已启用 Lockdown Mode；
- [ ] 无法升级设备已隔离或退役；
- [ ] Apple 安全公告已接入漏洞响应流程；
- [ ] 移动端流量已纳入 DNS、代理或安全网关可见范围；
- [ ] 已建立 Apple Threat Notification 上报渠道。

### 11.2 检测

- [ ] 已导入 DarkSword 网络 IOC；
- [ ] 被入侵合法站点采用“监控+时间关联”而非永久封禁；
- [ ] 已建立 WebKit/GPU/`mediaplaybackd` 连续崩溃告警；
- [ ] 已能快速导出 sysdiagnose 与网络日志；
- [ ] 已关联移动设备、SSO、邮件与 VPN 异常登录。

### 11.3 响应

- [ ] 处置手册明确“先保全证据还是先重启”的决策条件；
- [ ] 已准备干净设备用于凭据轮换；
- [ ] 加密钱包泄露有独立应急流程；
- [ ] 擦除重装后必须安装最新 iOS 才能重新接入企业；
- [ ] 法务、隐私和人员安全团队已纳入升级路径。

---

## 12. 情报冲突与不确定性登记

| 争议点 | 不同说法 | 本报告采用结论 |
|---|---|---|
| 受影响版本 | 18.4–18.7；18.0–18.7.2 + 26.0–26.2；更宽口径称 iOS 13+ | 重点排查 18.4–18.7.2 与 26.0–26.2，所有未更新设备均按暴露处理 |
| 是否 zero-click | Kaspersky 部分措辞称 zero-click；多数来源描述为访问网页后自动触发 | 按 one-click / drive-by 管理 |
| 0-day 数量 | 部分来源称 1 个或 6 个 | 采用“3 个 0-day + 3 个 n-day”的多源口径，同时以 Apple 公告为最终依据 |
| CVE-2025-43529 修复版本 | 有来源提及 18.6.2；更多来源指向 26.2 / 18.7.3 | 以 26.2 / 18.7.3 为主要处置基线，18.6.2 说法待 Apple 原文复核 |
| 载荷名称 | GHOSTBLADE、GHOSTKNIFE、GHOSTSABER 主要来自少数二手材料 | 仅作关联线索，不作为确定归因依据 |
| 中介机构 | 有来源提及 Matrix LLC / Operation Zero | 单源，暂不纳入核心结论 |
| 与 Operation Triangulation 的关系 | Kaspersky 提及架构关联，其他来源缺少代码级印证 | 视为待核研究方向，不表述为已证实继承关系 |
| 与 Graphite 的关系 | 网络上存在混用 | 未发现可信证据证明 Coruna/DarkSword 与 Graphite 为同一工具 |
| CVSS | 多个漏洞缺少统一、可验证的官方 CVSS 口径 | 本报告不自行推算 CVSS，采用链路影响评级 |

---

## 13. 结论

DarkSword 标志着 iOS 攻击生态发生了三项结构性变化：

1. **从单一高级攻击行动转向可复用工具包**：同一链路被多个主体使用；
2. **从长期植入转向短驻留数据窃取**：无持久化、自清理降低了取证可见性；
3. **从定向间谍活动扩展至经济犯罪**：加密资产与企业会话令牌成为重要目标。

对企业而言，最实际的控制顺序是：

```text
快速更新系统
    → 高风险人员启用 Lockdown Mode
    → 建立移动端网络与崩溃日志可见性
    → 准备 sysdiagnose 取证流程
    → 发现异常时从干净设备轮换全部凭据
```

DarkSword 的完整利用链虽然技术复杂，但其中多个环节已经有补丁。安全团队应把移动设备补丁延迟视为可被高级攻击者直接利用的暴露面，而不是普通运维问题。

---

## 参考来源

### Apple 官方

- [Apple Security Releases](https://support.apple.com/en-us/100100)
- [About the security content of iOS 26.2 and iPadOS 26.2](https://support.apple.com/en-us/125884)
- [About the security content of iOS 26.3 and iPadOS 26.3](https://support.apple.com/en-us/126346)
- [About the security content of iOS 26.1 and iPadOS 26.1](https://support.apple.com/en-il/125632)
- [About the security content of iOS 18.7.2 and iPadOS 18.7.2](https://support.apple.com/en-us/125633)
- [Apple Platform Security Guide](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)

### 一线与高可信威胁情报

- [Google Threat Intelligence — The Proliferation of DarkSword: iOS Exploit Chain Adopted by Multiple Actors](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain)
- [Google Threat Intelligence — Coruna: a powerful iOS exploit kit](https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit)
- [Cloud Security Alliance — DarkSword: Full-Chain iOS Zero-Day Exploitation by State Actors](https://labs.cloudsecurityalliance.org/research/csa-research-note-darksword-ios-fullchain-zeroday-multiactor/)
- [iVerify — Inside DarkSword](https://www.iverify.com/blog/darksword-ios-exploit-kit-explained)
- [Zimperium — DarkSword: The Hit-and-Run Successor to Coruna](https://zimperium.com/blog/darksword-the-hit-and-run-successor-to-the-coruna-ios-exploit-kit)
- [Kaspersky — Invincible no more: DarkSword and Coruna in mass attacks](https://www.kaspersky.com/blog/ios-exploits-darksword-and-coruna-in-mass-attacks/55622/)
- [runZero — Apple devices and DarkSword exposure](https://www.runzero.com/blog/apple-devices/)

### 补充分析

- [Holland & Knight — New iOS Exploit “DarkSword” and a New Era of Mobile Security](https://www.hklaw.com/en/insights/publications/2026/03/new-ios-exploit-darksword-and-a-new-era-of-mobile-security)
- [Help Net Security — DarkSword: Researchers uncover another iOS exploit kit](https://www.helpnetsecurity.com/2026-03-19/darksword-ios-exploit-iphone/)
- [安全内参 — 通过攻陷合法网站传播的新型 iOS 漏洞利用工具包 DarkSword](https://www.secrss.com/articles/88644)
- [The Hacker News — Apple fixes CVE-2026-20700](https://thehackernews.com/2026/02/apple-fixes-exploited-zero-day.html)
- [The Register — Apple patches iOS zero-day exploited in the wild](https://www.theregister.com/security/2026/02/12/apple-patches-decade-old-ios-zero-day-exploited-in-the-wild/4315395)

---

*本报告基于公开情报编制。IOC、归因和影响版本会随研究更新而变化，正式处置时应再次核对 Apple 最新安全公告与一手研究机构信息。*

咨询ios系统请咨询  telegram：@DZHT333333
