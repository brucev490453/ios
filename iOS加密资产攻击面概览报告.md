# iOS 端加密资产攻击面概览报告

| 项目 | 内容 |
|---|---|
| 报告日期 | 2026-10-05 |
| 报告范围 | iOS 平台上针对加密资产（钱包、交易所 App、助记词、授权签名）的攻击面与防御 |
| 适用对象 | 加密资产持有人、交易所 SOC、钱包团队安全工程师、企业移动安全与合规 |
| 报告性质 | 防御性网络安全研究 |
| 风险等级 | 高（High） |

> 本报告**不包含**任何漏洞利用代码、钱包盗取技术、授权骗取构造、恶意合约示例、助记词窃取方法或绕过检测手段。全部内容面向识别、监测、加固与响应。
>
> 置信度标记：**[确证]** = Apple / 一手研究机构 / 钱包厂商直接确认；**[多源]** = 多个独立来源交叉印证；**[待核]** = 公开来源存在冲突或尚缺一手证据。

---

## 1. 执行摘要

iOS 设备承载的加密资产面临的风险来自**三条叠加的攻击链**：

1. **系统层入侵链**：Coruna、DarkSword 等 iOS 漏洞利用工具包通过 WebKit 水坑或消息零点击触发沙箱逃逸与内核提权，具备访问 Keychain、钱包 App 数据目录和内存中敏感字符串的能力。**[多源]**
2. **应用层社会工程链**：伪装成空投、客服、交易所验证、Web3 游戏的 dApp 页面，诱导用户在合法钱包中签署高风险授权（无限额度、代币转移、NFT setApprovalForAll），资产以"用户主动签名"的形式离开钱包，无需系统漏洞。**[多源]**
3. **物理与边信道链**：解锁屏幕被窥、USB 调试模式被滥用、设备被取回后在 USB Restricted Mode 失效窗口内接入取证设备、剪贴板中的助记词被后台应用读取。**[多源]**

关键结论：

1. **私钥 / 助记词一旦离开硬件安全边界即视为永久泄漏。** 任何"异地恢复""官方帮您导入"的流程都是明确的红线。
2. **授权骗取（approval phishing）在 2024—2026 年已超过助记词骗取**，成为链上资产损失的主要来源。**[多源]**
3. **Lockdown Mode 对系统层链具有显著收缩作用**：禁用 JIT、复杂字体、消息附件预览、不受信任的配置描述文件安装路径，能阻断多数 WebKit/消息零点击链。**[确证]**
4. **硬件钱包 + 盲签警示** 是对抗授权骗取的实际有效组合：签名内容在硬件屏幕上可读、异常合约地址可拒绝。
5. **iOS 自身没有"扫描恶意合约"的能力**，钱包 App 的风险提示质量差异极大，需要在应用层叠加识别。
6. **剪贴板是被低估的攻击面**：地址替换、助记词读取、OTP 嗅探，均可在不越权的前提下通过前台/后台 API 组合完成。**[多源]**

---

## 2. iOS 加密资产技术栈概览

### 2.1 密钥与敏感数据存放位置

| 存放位置 | 典型内容 | 保护强度 | 风险场景 |
|---|---|---|---|
| **Secure Enclave (SEP)** | 生物识别密钥、部分钱包的签名密钥封装 | 最高：密钥不离开 SEP | SEP 自身零日（罕见、修复优先级极高） |
| **Keychain（kSecAttrAccessible…WhenUnlocked / ThisDeviceOnly）** | 助记词加密后的 blob、API Token、交易所登录态 | 高：越狱或内核权限可读 | 内核提权后的 Keychain dump；iCloud 同步到低信任设备 |
| **App 沙箱 Documents/Library** | 钱包数据库（SQLite）、交易记录缓存、地址簿 | 中：沙箱逃逸后可读 | DarkSword 等工具链已有钱包数据外传路径 **[多源]** |
| **UserDefaults / plist** | 配置、特性开关、极少数误存的敏感字段 | 低：仅沙箱隔离 | 开发不规范导致明文助记词存入 plist **[待核]** |
| **剪贴板（UIPasteboard）** | 临时复制的地址、助记词、OTP | 极低：同设备前台 App 可读 | 地址替换、助记词截取 |
| **屏幕录制 / 截图缓存** | 包含余额、二维码、恢复短语的屏幕内容 | 低 | 后台录屏滥用、"游戏录制"类应用权限滥用 |

### 2.2 iOS 上的加密资产 App 分类

- **自托管钱包**（MetaMask、Trust、Rainbow、imToken、OKX Wallet 等）：助记词由用户持有，签名在设备内完成。
- **交易所 App**（Binance、Coinbase、OKX、Bybit 等）：资产由中心化托管，攻击面集中在账户劫持、API Key 泄漏、提币地址白名单绕过。
- **硬件钱包伴侣 App**（Ledger Live、Trezor Suite Lite 等）：私钥在硬件设备中，手机端承担交易构造与广播。
- **Web3 dApp 浏览器 / WalletConnect 客户端**：承载签名请求的路由，是授权骗取的主要入口。
- **云钱包 / MPC 钱包**（Zengo、Fireblocks 等）：密钥碎片分布式，攻击面向服务端账户与设备绑定。

---

## 3. 已知攻击面分类

### 3.1 系统漏洞链对加密资产的影响

#### 3.1.1 Coruna 工具包（iOS 13.0 – 17.2.1）

- 通过 WebKit 水坑投递，组合浏览器 RCE + 沙箱逃逸 + 内核提权。**[多源]**
- 完成提权后，具备读取 Keychain、钱包 App 沙箱数据库、系统剪贴板历史的能力。
- **对加密资产的典型路径**（防御视角）：读取钱包 App 沙箱 → 导出已解锁的助记词 blob → 外传至 C2。
- 修复：升级至 iOS 17.3 以上即关闭 Coruna 已知链路；iOS 18/26 仍需保持最新版本。**[确证]**

#### 3.1.2 DarkSword 工具包（iOS 18.x、iOS 26.x）

- 支持 iOS 18.4 – 18.7.2、iOS 26.0 – 26.2.x 的多条链；通过水坑、消息、恶意描述文件投递。**[多源]**
- 公开分析提到的加密资产相关行为：**钱包数据库外传、WalletConnect 会话凭据提取、剪贴板历史收集**。**[待核：具体行为集合在不同样本间差异较大]**
- 修复：Apple 已针对多条已知链发布补丁；仍在服役的 iOS 18.3 之前设备风险显著更高。

#### 3.1.3 USB Restricted Mode 失效窗口（iOS 11.4 – 18.3）

- 影响：设备被取回后，在超过 1 小时未解锁的保护窗口被打破的情况下，取证设备可建立 USB 配件连接。**[多源]**
- 对加密资产的意义：助记词、钱包 App 本地未加密缓存、浏览器历史均可能被取证工具提取。
- 修复：升级至 iOS 18.4 及以上；并在 Face ID/Touch ID 关闭后立即强制重启。**[确证]**

### 3.2 应用层：授权骗取（Approval Phishing）

> **防御描述**：授权骗取是攻击者在合约层面诱导用户签名，使恶意地址获得对用户代币 / NFT 的转移权；资产离开钱包的瞬间是用户主动签名，而非系统被入侵。

#### 3.2.1 常见诱导场景

- 伪装空投网站，要求"连接钱包领取"后弹出 `approve` / `increaseAllowance` / `setApprovalForAll` 签名请求。
- 伪装成 OpenSea、Blur、Uniswap 的二级域名或 Punycode 相似域名。
- 利用 Telegram、X / Twitter 评论区推送"NFT 免费铸造"链接。
- 伪装成"钱包升级""助记词验证""Node 节点认证"的客服对话，诱导用户签署 EIP-712 消息。

#### 3.2.2 高风险签名类型（识别角度）

| 签名类型 | 风险信号 |
|---|---|
| `approve(spender, 2^256-1)` | 无限额度授权给非主流合约 |
| `setApprovalForAll(operator, true)` | 对未经验证的 operator 全量 NFT 授权 |
| EIP-712 `Permit` / `Permit2` | 允许离线签名直接转移代币，受害人常以为是"登录签名" |
| EIP-712 `SeaportOrder` / `BlurOrder` 变体 | 挂单形式低价卖出 NFT |
| 原生代币 `transfer` 到陌生地址 | 直接转账，常见于"地址剪贴板替换"场景 |

#### 3.2.3 iOS 侧的识别信号

- 钱包 App 内风险提示告警后用户仍选择继续（可观测的用户行为日志，钱包厂商侧）。
- WalletConnect 会话来自未知 Peer 名称、Peer URL 不在白名单。
- 签名发起域名与钱包连接前访问的域名不一致（钱包 App 可记录）。
- Web3 浏览器加载 `javascript:` 或 `data:` URL 调用 `ethereum.request`。

### 3.3 恶意 dApp 与 WalletConnect 滥用

- **伪造 WalletConnect 中转服务器**：相同协议格式但由攻击者托管，签名请求在中转层被改写。**[待核]**
- **Deep Link 劫持**：恶意 App 注册与真实钱包相似的 URL Scheme，截获 WalletConnect `wc:` 协议链接。
- **恶意 Safari 扩展 / 书签脚本**：注入脚本篡改 dApp 页面显示的接收地址。
- **误导性合约前端**：合约 ABI 显示"Claim"，实际函数为代币转移。

### 3.4 剪贴板与边信道

- **剪贴板地址替换**：iOS 应用在前台时可读取 `UIPasteboard.general`；用户复制钱包地址，粘贴时地址已被相同前缀/后缀的陌生地址替换。
- **剪贴板历史收集**：部分越狱设备或存在系统提权能力的工具链可读取历史剪贴板。
- **屏幕录制滥用**：录屏类 App 或"游戏助手"申请屏幕广播权限，用户在录制状态下输入助记词或私钥。
- **通知横幅内容泄漏**：锁屏时交易所 OTP、提币确认码以明文形式出现。
- **AirDrop 与"分享"面板**：用户错将截图（含二维码私钥）通过 AirDrop 发送到陌生设备。

### 3.5 助记词 / 私钥识别风险

- 用户将助记词截图后保存至系统相册 → iCloud 相册同步 → 其他登录同一 Apple ID 的设备可见。
- 使用笔记类 App（备忘录、第三方云笔记）保存助记词 → 云端被撞库。
- 使用邮件 / Telegram "发给自己" 保存助记词 → 账号被盗后助记词随之泄漏。
- 使用 OCR 扫描纸质助记词的"钱包辅助"类工具 → 工具本身上传服务器。

### 3.6 社会工程与假冒 App

- App Store 伪装成"钱包""资产管理"的假冒 App，诱导输入助记词后立即外传。**[多源]**
- 企业证书 / TestFlight 分发的"内测钱包"或"交易所高级版"，绕过 App Store 审核。
- "官方客服"通过 iMessage / Telegram 要求屏幕共享 → 用户展示助记词或签名流程。

---

## 4. 检测信号与观测点

### 4.1 终端侧

| 观测点 | 低风险基线 | 异常信号 |
|---|---|---|
| iOS 版本 | 当前最新稳定版 | 停留在已知利用链覆盖的旧版本 |
| 已安装描述文件 | 仅限 MDM / 已知配置 | 存在未知来源的 VPN / Root CA / 配置文件 |
| 剪贴板使用提示 | 偶发前台粘贴 | 后台 App 频繁触发剪贴板读取通知 |
| 屏幕录制 / 广播 | 用户主动 | 后台 App 启动广播、用户未感知 |
| 电量 / 发热 | 正常曲线 | 待机状态下持续高负载（可能的后台数据外传） |
| Lockdown Mode | 高风险人员：开启 | 关闭或被频繁临时关闭 |

### 4.2 网络侧

- 对已公开的 Coruna / DarkSword C2 域名与 IP 的 DNS 查询与出站连接。
- 向非主流 WalletConnect 中转服务器的连接。
- 对伪装为交易所域名的 Punycode / 相似域名的 TLS 握手。
- 向 Telegram Bot API、Discord Webhook 的异常外传（可能的助记词回传渠道）。**[待核]**

### 4.3 链上侧（企业级 / 钱包厂商）

- 同一地址对多个 token 发出 `approve(max)` 后被单一 EOA 批量转移。
- 新创建合约在短时间内收到大量 `setApprovalForAll` 并随后转移 NFT。
- 用户钱包向混币器、已被标记地址转账。
- 该监测应由钱包 / 交易所 / 链上风控平台实施，非终端用户职责。

---

## 5. Lockdown Mode 与硬件钱包的保护效果

### 5.1 Lockdown Mode 对加密资产相关攻击面的覆盖

| 攻击面 | Lockdown Mode 效果 |
|---|---|
| WebKit 水坑（Coruna / DarkSword 入口） | **显著收缩**：禁用 JIT、复杂字体、WebAssembly 部分特性 **[确证]** |
| iMessage 零点击 | **显著收缩**：禁用大多数附件预览与链接预览 **[确证]** |
| 未知来源的描述文件安装 | **阻断**：禁止安装配置描述文件 **[确证]** |
| 恶意 FaceTime / Game Center 入站 | **收缩**：限制未知来源来电 |
| 授权骗取（钱包 App 内） | **无直接影响**：Lockdown Mode 不进入 dApp 签名层 |
| 剪贴板地址替换 | **无直接影响** |
| 假冒 App | **无直接影响** |

> Lockdown Mode 是**系统层防御**，与**应用层签名风险**是正交问题。两者需同时覆盖。

### 5.2 硬件钱包的保护效果

| 风险 | 硬件钱包是否缓解 |
|---|---|
| 系统漏洞读取钱包内助记词 | **是**：助记词从未进入 iOS 设备 |
| Keychain / 沙箱 dump | **是** |
| 剪贴板地址替换 | **部分**：仍需用户在硬件屏幕核对接收地址 |
| 授权骗取（approve / setApprovalForAll） | **部分**：仅在用户认真核对硬件屏幕显示的函数名与参数时有效；盲签场景下无效 |
| 社会工程（用户主动输入助记词） | **否**：硬件钱包不能阻止用户自己把助记词告诉骗子 |
| 假冒伴侣 App | **部分**：若伴侣 App 伪造交易展示，用户仍需以硬件屏幕为准 |

### 5.3 建议组合

- **普通持币**：主流自托管钱包 + 系统常规更新 + 不启用描述文件安装 + 不启用剪贴板共享。
- **中等资产**：Lockdown Mode 开启 + 硬件钱包 + 独立的"消费钱包"与"储备钱包"分离。
- **高净值 / 公众人物**：Lockdown Mode 开启 + 多签 / MPC + 全部出金均走硬件钱包确认 + 独立设备仅用于签名 + 不在该设备上收取 iMessage / 邮件。

---

## 6. 加固基线（面向加密资产持有人）

### 6.1 iOS 系统层

1. 保持 iOS 升级到当前最新稳定版本（含安全响应 RSR）。
2. 高风险人员启用 **Lockdown Mode**。
3. **关闭** iMessage 对未知号码的附件预览；**关闭**邮件远程图像加载。
4. **禁止安装**非 MDM 来源的描述文件（设置 → 通用 → VPN 与设备管理）。
5. 启用 **USB 配件保护**（USB Restricted Mode），避免在失效窗口期将设备交给陌生人。
6. 启用 **Stolen Device Protection**（iOS 17.3+），在非信任地点要求生物识别+延迟。
7. 关闭 **iCloud 相册同步**对包含助记词的相册 / 使用隐藏专用相册。
8. 启用 **Advanced Data Protection**（如区域允许），提升 iCloud 内容的端到端加密强度。

### 6.2 钱包与应用层

1. **主钱包用硬件钱包**；手机端仅保留极少量支付用热钱包。
2. **分离消费与储备地址**；储备地址不与任何 dApp 交互。
3. 对所有历史授权执行**周期性撤销**（通过主流撤销工具，不在本报告列出具体 URL；由用户在钱包厂商官方指引下操作）。
4. **拒绝盲签**：硬件钱包无法清晰显示函数名与参数的交易，一律拒签。
5. 关闭钱包的 **"自动连接最近的 dApp"**；每次手动确认。
6. 不在 Web3 浏览器中打开通过 iMessage / Telegram / X 评论区转发的链接。
7. **只信任 App Store 下载的钱包**，拒绝任何 TestFlight / 企业证书分发的钱包 App。
8. 关闭钱包 App 对 **剪贴板的"自动粘贴"** 权限（如钱包提供该开关）。

### 6.3 使用习惯

1. **助记词不进入任何数字设备**：手写、金属板、分段分地点存储。
2. 不以截图、照片、OCR、聊天工具暂存助记词。
3. **粘贴地址后再次核对首尾字符与中段 4-6 位**，防止剪贴板替换。
4. 收到自称官方的客服 / 空投 / 升级消息，**默认视为诈骗**；通过官方 App 内公告反向验证。
5. 签名前阅读钱包的风险提示；若弹出"该域名首次签名"或"该合约未验证"等提示，暂停并复核。
6. 不在加密资产主设备上安装与资产无关的小众工具、输入法、键盘扩展、剪贴板增强。
7. 不使用公共 Wi-Fi 进行链上操作；若必须，使用自建或可信的 VPN。

### 6.4 企业 / 钱包厂商

1. 对自家钱包 App 强制启用 **证书钉扎（Certificate Pinning）** 与反调试；但不以此为唯一防线。
2. 对 WalletConnect Peer URL 做**官方域名白名单 + 相似度检测**。
3. 风险签名（max approve、setApprovalForAll、EIP-712 Permit）**强制二次确认**与清晰话术说明。
4. 对剪贴板读取调用频率做审计（App 内自我约束，减少系统横幅提示的噪声）。
5. 定期扫描 App Store / TestFlight 上的仿冒 App 并提交下架申诉。
6. 与链上风控服务商建立**地址黑名单**同步机制。

---

## 7. 应急响应

### 7.1 疑似助记词 / 私钥泄漏

1. **立即在未受影响的设备上**用相同助记词恢复钱包，构造一笔**优先级足够高**的转账，将剩余资产转移到**全新生成**的硬件钱包地址。
2. 对已授权的 ERC-20 / ERC-721 合约执行**全量撤销**（在新设备上操作，不在被怀疑污染的 iOS 设备上）。
3. 对与该助记词相关的交易所提币白名单、API Key、2FA 绑定做更换。
4. 原助记词**永不复用**。
5. 保留现场：被怀疑污染的 iOS 设备不要立即恢复出厂，交由安全团队取证。

### 7.2 疑似授权骗取

1. 查看最近的签名记录，确认是哪一笔 `approve` / `setApprovalForAll` / `Permit`。
2. **争分夺秒**地撤销授权（gas 竞价与攻击者的转移交易赛跑）。
3. 若已被转走部分资产：剩余资产立即转移至新地址；对已泄漏的授权关系做完整梳理。
4. 保留 dApp 域名、WalletConnect 会话、签名内容截图，用于后续追溯与标记。

### 7.3 疑似设备被植入

1. 立即将加密资产相关的交易所 / 钱包 App **登出并解绑设备**。
2. 使用**另一台干净设备**在新网络环境下将资产转移到新钱包。
3. 对可疑设备执行 **备份 → 擦除 → 作为新设备恢复**（不要从疑似污染的 iCloud 备份恢复钱包 App）。
4. 更换 Apple ID 密码并撤销全部可信设备；检查 iCloud Keychain 中的敏感条目。
5. 若怀疑是定向攻击，启用 Lockdown Mode 并考虑换设备。

---

## 8. 不确定性登记

| 议题 | 现状 | 置信度 |
|---|---|---|
| DarkSword 对钱包数据的具体字段提取范围 | 公开样本差异大，部分研究仅披露类别 | [待核] |
| 恶意 WalletConnect 中转服务器的真实流行度 | 存在概念验证讨论，缺少量化规模 | [待核] |
| iCloud Keychain 对第三方钱包助记词的默认同步比例 | 取决于钱包实现与用户设置 | [待核] |
| Lockdown Mode 对 WebAssembly 的具体限制清单 | Apple 文档偏总括式，细节随版本演进 | [多源] |
| 硬件钱包伴侣 App 的签名内容显示一致性 | 不同厂商差异明显，部分存在"精简显示"问题 | [多源] |
| App Store 对仿冒钱包 App 的平均下架时效 | 无公开数据 | [待核] |

---

## 9. 参考来源

- [Apple — Lockdown Mode](https://support.apple.com/en-us/105120)
- [Apple — About Stolen Device Protection for iPhone](https://support.apple.com/en-us/120340)
- [Apple — Advanced Data Protection for iCloud](https://support.apple.com/en-us/102651)
- [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web)
- [Apple Security Releases](https://support.apple.com/en-us/100100)
- [Google Threat Intelligence — Coruna: The Mysterious Journey of a Powerful iOS Exploit Kit](https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit)
- [iVerify — Coruna: Inside the Nation-State-Grade iOS Exploit Kit We've Been Tracking](https://www.iverify.com/blog/coruna-inside-the-nation-state-grade-ios-exploit-kit-we-ve-been-tracking)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [EIP-2612: Permit — Signed Approvals](https://eips.ethereum.org/EIPS/eip-2612)
- [EIP-712: Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712)
- [Uniswap Labs — Permit2](https://github.com/Uniswap/permit2)
- [WalletConnect Documentation](https://docs.walletconnect.com/)

---

*本报告基于截至 2026-10-05 的公开情报与官方文档编制。iOS 版本、Lockdown Mode 规则、钱包 App 行为与链上生态可能变化，正式处置前请复核 Apple、钱包厂商和链上风控平台的最新公告。本报告仅用于防御性网络安全目的，严禁用于任何形式的攻击、窃取或未授权访问。*

咨询ios系统请咨询  telegram：@DZHT333333
