#include <algorithm>
#include <chrono>
#include <cctype>
#include <ctime>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

namespace {

const std::set<std::string> kDarkSwordDomains = {
    "cdncounter.net",
    "static.cdncounter.net",
    "sqwas.shapelie.com",
    "snapshare.chat",
};

const std::set<std::string> kCompromisedWateringHoles = {
    "7aac.gov.ua",
    "novosti.dn.ua",
};

const std::set<std::string> kDarkSwordIps = {
    "141.105.130.237",
    "62.72.21.10",
};

const std::set<int> kSuspiciousPorts = {8881, 8882};

const std::regex kDomainPattern(
    R"(\b([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)\b)");
const std::regex kIpv4Pattern(R"(\b(\d{1,3}(?:\.\d{1,3}){3})\b)");
const std::regex kIosUserAgentPattern(
    R"(iPhone\s+OS\s+(\d+)[_.](\d+)(?:[_.](\d+))?)",
    std::regex::icase);
const std::regex kCryptoLurePattern(
    R"((backup[-_ ]?phrase|seed[-_ ]?phrase|mnemonic|wallet[-_ ]?recover|airdrop[-_ ]?claim|metamask|bitkeep|bitcoin[-_ ]?bonus|crypto[-_ ]?invest|free[-_ ]?token))",
    std::regex::icase);
const std::regex kGamblingLurePattern(
    R"((online[-_ ]?casino|slot[-_ ]?machine|bet[-_ ]?now|jackpot[-_ ]?win|lucky[-_ ]?spin))",
    std::regex::icase);

struct Version {
    int major = 0;
    int minor = 0;
    int patch = 0;
};

struct VersionRange {
    std::string name;
    Version minimum;
    Version maximum;
    std::string severity;
    std::string description;
};

const std::vector<VersionRange> kVulnerableRanges = {
    {"Coruna", {13, 0, 0}, {17, 2, 1}, "严重",
     "Coruna 工具包公开适配范围：5 条完整利用链、23 个利用模块"},
    {"DarkSword (iOS 18)", {18, 4, 0}, {18, 7, 2}, "严重",
     "DarkSword 工具包公开适配范围（iOS 18 分支）"},
    {"DarkSword (iOS 26)", {26, 0, 0}, {26, 2, 99}, "严重",
     "DarkSword 工具包公开适配范围（iOS 26 分支）"},
    {"USB Restricted Mode 绕过", {11, 4, 0}, {18, 3, 0}, "高",
     "CVE-2025-24200：物理接触攻击可禁用 USB 限制"},
};

struct VersionFinding {
    std::string version;
    std::string threat;
    std::string severity;
    std::string description;
    std::string recommendation;
};

struct Alert {
    std::string timestamp;
    std::string level;
    std::string category;
    std::string detail;
    std::string indicator;
    std::string source;
};

std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return "";
    }
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool is_option(const char* value) {
    return value != nullptr && value[0] == '-';
}

std::string normalize_domain(std::string domain) {
    domain = to_lower(trim(domain));
    while (!domain.empty() && domain.back() == '.') {
        domain.pop_back();
    }
    return domain;
}

std::string now_utc() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &time);
#else
    gmtime_r(&time, &utc);
#endif
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%d %H:%M:%S UTC");
    return output.str();
}

Alert make_alert(const std::string& level,
                 const std::string& category,
                 const std::string& detail,
                 const std::string& indicator,
                 const std::string& source = "") {
    return {now_utc(), level, category, detail, indicator, source};
}

bool parse_version(const std::string& input, Version& result) {
    std::string normalized = trim(input);
    std::replace(normalized.begin(), normalized.end(), '_', '.');
    const std::regex pattern(R"(^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?\s*$)");
    std::smatch match;
    if (!std::regex_match(normalized, match, pattern)) {
        return false;
    }

    try {
        result.major = std::stoi(match[1].str());
        result.minor = match[2].matched ? std::stoi(match[2].str()) : 0;
        result.patch = match[3].matched ? std::stoi(match[3].str()) : 0;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

std::tuple<int, int, int> version_tuple(const Version& version) {
    return {version.major, version.minor, version.patch};
}

std::vector<VersionFinding> check_version(const std::string& version_text) {
    Version version;
    if (!parse_version(version_text, version)) {
        return {{version_text, "版本格式无效", "错误",
                 "请输入 major.minor.patch 格式，例如 17.2.1", "修正输入格式"}};
    }

    std::vector<VersionFinding> findings;
    for (const auto& range : kVulnerableRanges) {
        if (version_tuple(version) >= version_tuple(range.minimum) &&
            version_tuple(version) <= version_tuple(range.maximum)) {
            findings.push_back({version_text, range.name, range.severity,
                                range.description, "立即升级至 Apple 当前支持的安全版本"});
        }
    }

    if (findings.empty()) {
        findings.push_back({version_text, "无已知匹配", "信息",
                            "该版本不在本工具收录的公开工具包适配范围内",
                            "继续保持最新版本并核对 Apple 安全公告"});
    }
    return findings;
}

bool is_subdomain_of(const std::string& domain, const std::string& parent) {
    if (domain.size() <= parent.size()) {
        return false;
    }
    const std::size_t offset = domain.size() - parent.size();
    return domain.compare(offset, parent.size(), parent) == 0 &&
           domain[offset - 1] == '.';
}

std::vector<Alert> check_domain(const std::string& domain_text,
                                const std::string& source = "") {
    std::vector<Alert> alerts;
    const std::string domain = normalize_domain(domain_text);

    if (kDarkSwordDomains.count(domain) != 0) {
        alerts.push_back(make_alert(
            "严重", "IOC 域名匹配",
            "域名匹配 DarkSword 已知 C2 或投递基础设施", domain, source));
    }

    if (kCompromisedWateringHoles.count(domain) != 0) {
        alerts.push_back(make_alert(
            "高", "水坑站点访问",
            "域名为已知被入侵的合法站点；建议监控告警而非直接封禁",
            domain, source));
    }

    for (const auto& parent : kDarkSwordDomains) {
        if (is_subdomain_of(domain, parent)) {
            alerts.push_back(make_alert(
                "高", "IOC 子域名匹配",
                "域名是 DarkSword 已知基础设施的子域", domain, source));
            break;
        }
    }

    for (const auto& parent : kCompromisedWateringHoles) {
        if (is_subdomain_of(domain, parent)) {
            alerts.push_back(make_alert(
                "高", "水坑站点子域访问",
                "域名是已知被入侵合法站点的子域", domain, source));
            break;
        }
    }

    if (std::regex_search(domain, kCryptoLurePattern)) {
        alerts.push_back(make_alert(
            "中", "加密资产诱饵域名",
            "域名包含加密资产、助记词或钱包恢复诱饵关键词", domain, source));
    }

    if (std::regex_search(domain, kGamblingLurePattern)) {
        alerts.push_back(make_alert(
            "中", "博彩诱饵域名",
            "域名包含博彩诱饵关键词，此类页面曾被用于 Coruna 投递", domain, source));
    }

    return alerts;
}

bool valid_ipv4(const std::string& input) {
    std::stringstream stream(input);
    std::string token;
    int count = 0;
    while (std::getline(stream, token, '.')) {
        if (token.empty() || token.size() > 3 ||
            !std::all_of(token.begin(), token.end(),
                         [](unsigned char c) { return std::isdigit(c) != 0; })) {
            return false;
        }
        const int value = std::stoi(token);
        if (value < 0 || value > 255) {
            return false;
        }
        ++count;
    }
    return count == 4;
}

std::vector<Alert> check_ip(const std::string& ip_text,
                            const std::string& source = "") {
    const std::string ip = trim(ip_text);
    if (!valid_ipv4(ip)) {
        return {make_alert("错误", "IP 格式无效", "输入不是有效的 IPv4 地址", ip, source)};
    }
    if (kDarkSwordIps.count(ip) != 0) {
        return {make_alert("严重", "IOC IP 匹配",
                           "IP 匹配 DarkSword 已知基础设施", ip, source)};
    }
    return {};
}

std::vector<Alert> check_port(int port,
                              const std::string& destination = "",
                              const std::string& source = "") {
    if (kSuspiciousPorts.count(port) == 0) {
        return {};
    }
    std::string detail = "目标端口匹配 DarkSword 已知通信端口";
    if (!destination.empty()) {
        detail += "（目标：" + destination + "）";
    }
    return {make_alert("高", "可疑端口", detail, std::to_string(port), source)};
}

std::vector<Alert> check_user_agent(const std::string& user_agent,
                                    const std::string& source = "") {
    std::smatch match;
    if (!std::regex_search(user_agent, match, kIosUserAgentPattern)) {
        return {};
    }

    std::string version = match[1].str() + "." + match[2].str() + "." +
                          (match[3].matched ? match[3].str() : "0");
    std::vector<Alert> alerts;
    for (const auto& finding : check_version(version)) {
        if (finding.severity != "信息") {
            alerts.push_back(make_alert(
                finding.severity, "脆弱版本 User-Agent",
                "检测到 iOS " + version + "：" + finding.description,
                version, source));
        }
    }
    return alerts;
}

void append_alerts(std::vector<Alert>& destination,
                   const std::vector<Alert>& source) {
    destination.insert(destination.end(), source.begin(), source.end());
}

std::vector<std::string> extract_matches(const std::string& text,
                                         const std::regex& pattern) {
    std::vector<std::string> matches;
    for (std::sregex_iterator it(text.begin(), text.end(), pattern), end;
         it != end; ++it) {
        matches.push_back((*it)[1].str());
    }
    return matches;
}

std::vector<Alert> analyze_dns_log(const std::string& path) {
    std::ifstream input(path);
    if (!input) {
        return {make_alert("错误", "日志读取失败", "无法打开 DNS 日志文件", path)};
    }

    std::vector<Alert> alerts;
    std::map<std::string, int> domain_counts;
    std::string line;
    std::size_t line_number = 0;

    while (std::getline(input, line)) {
        ++line_number;
        const std::string cleaned = trim(line);
        if (cleaned.empty() || cleaned[0] == '#') {
            continue;
        }

        const std::string source = "行 " + std::to_string(line_number);
        for (const auto& domain_text : extract_matches(cleaned, kDomainPattern)) {
            const std::string domain = normalize_domain(domain_text);
            ++domain_counts[domain];
            append_alerts(alerts, check_domain(domain, source));
        }

        for (const auto& ip : extract_matches(cleaned, kIpv4Pattern)) {
            if (valid_ipv4(ip)) {
                append_alerts(alerts, check_ip(ip, source));
            }
        }
    }

    constexpr int kHighFrequencyThreshold = 50;
    for (const auto& [domain, count] : domain_counts) {
        if (count >= kHighFrequencyThreshold) {
            alerts.push_back(make_alert(
                "低", "高频 DNS 查询",
                "域名在日志中出现 " + std::to_string(count) +
                    " 次；可能是正常业务，也可能是 C2 心跳",
                domain));
        }
    }
    return alerts;
}

std::vector<std::string> parse_csv_line(const std::string& line) {
    std::vector<std::string> fields;
    std::string field;
    bool quoted = false;

    for (std::size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (c == '"') {
            if (quoted && i + 1 < line.size() && line[i + 1] == '"') {
                field.push_back('"');
                ++i;
            } else {
                quoted = !quoted;
            }
        } else if (c == ',' && !quoted) {
            fields.push_back(field);
            field.clear();
        } else {
            field.push_back(c);
        }
    }
    fields.push_back(field);
    return fields;
}

std::map<std::string, std::size_t> csv_headers(const std::vector<std::string>& fields) {
    std::map<std::string, std::size_t> headers;
    for (std::size_t i = 0; i < fields.size(); ++i) {
        headers[to_lower(trim(fields[i]))] = i;
    }
    return headers;
}

std::string csv_value(const std::vector<std::string>& row,
                      const std::map<std::string, std::size_t>& headers,
                      const std::string& name) {
    const auto it = headers.find(name);
    if (it == headers.end() || it->second >= row.size()) {
        return "";
    }
    return trim(row[it->second]);
}

std::vector<Alert> analyze_network_log(const std::string& path) {
    std::ifstream input(path);
    if (!input) {
        return {make_alert("错误", "日志读取失败", "无法打开网络 CSV 日志文件", path)};
    }

    std::string header_line;
    if (!std::getline(input, header_line)) {
        return {make_alert("错误", "日志格式无效", "CSV 文件为空", path)};
    }

    const auto headers = csv_headers(parse_csv_line(header_line));
    if (headers.count("domain") == 0 && headers.count("dst_ip") == 0) {
        return {make_alert(
            "错误", "日志格式无效",
            "CSV 至少需要 domain 或 dst_ip 列", path)};
    }

    std::vector<Alert> alerts;
    std::string line;
    std::size_t line_number = 1;
    while (std::getline(input, line)) {
        ++line_number;
        const auto row = parse_csv_line(line);
        const std::string source = "行 " + std::to_string(line_number);
        const std::string domain = csv_value(row, headers, "domain");
        const std::string destination_ip = csv_value(row, headers, "dst_ip");
        const std::string destination_port = csv_value(row, headers, "dst_port");
        const std::string user_agent = csv_value(row, headers, "user_agent");
        const std::string bytes_out_text = csv_value(row, headers, "bytes_out");

        if (!domain.empty()) {
            append_alerts(alerts, check_domain(domain, source));
        }
        if (!destination_ip.empty()) {
            append_alerts(alerts, check_ip(destination_ip, source));
        }
        if (!destination_port.empty()) {
            try {
                append_alerts(alerts, check_port(std::stoi(destination_port), domain, source));
            } catch (const std::exception&) {
                alerts.push_back(make_alert(
                    "错误", "端口格式无效", "dst_port 不是有效数字",
                    destination_port, source));
            }
        }
        if (!user_agent.empty()) {
            append_alerts(alerts, check_user_agent(user_agent, source));
        }
        if (!bytes_out_text.empty()) {
            try {
                const long long bytes_out = std::stoll(bytes_out_text);
                if (bytes_out > 5000000) {
                    alerts.push_back(make_alert(
                        "中", "大流量出站",
                        "单次连接出站 " + std::to_string(bytes_out) +
                            " 字节，可能为数据外传",
                        domain.empty() ? destination_ip : domain, source));
                }
            } catch (const std::exception&) {
                alerts.push_back(make_alert(
                    "错误", "流量字段格式无效", "bytes_out 不是有效整数",
                    bytes_out_text, source));
            }
        }
    }
    return alerts;
}

int severity_rank(const std::string& level) {
    if (level == "严重") return 0;
    if (level == "高") return 1;
    if (level == "中") return 2;
    if (level == "低") return 3;
    if (level == "信息") return 4;
    return 5;
}

std::string markdown_escape(std::string value) {
    std::size_t position = 0;
    while ((position = value.find('|', position)) != std::string::npos) {
        value.replace(position, 1, "\\|");
        position += 2;
    }
    std::replace(value.begin(), value.end(), '\n', ' ');
    std::replace(value.begin(), value.end(), '\r', ' ');
    return value;
}

std::string json_escape(const std::string& value) {
    std::ostringstream output;
    for (unsigned char c : value) {
        switch (c) {
            case '"': output << "\\\""; break;
            case '\\': output << "\\\\"; break;
            case '\b': output << "\\b"; break;
            case '\f': output << "\\f"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (c < 0x20) {
                    output << "\\u" << std::hex << std::setw(4)
                           << std::setfill('0') << static_cast<int>(c)
                           << std::dec << std::setfill(' ');
                } else {
                    output << static_cast<char>(c);
                }
        }
    }
    return output.str();
}

void print_json(const std::vector<Alert>& alerts) {
    std::cout << "[\n";
    for (std::size_t i = 0; i < alerts.size(); ++i) {
        const auto& alert = alerts[i];
        std::cout << "  {\n"
                  << "    \"timestamp\": \"" << json_escape(alert.timestamp) << "\",\n"
                  << "    \"level\": \"" << json_escape(alert.level) << "\",\n"
                  << "    \"category\": \"" << json_escape(alert.category) << "\",\n"
                  << "    \"detail\": \"" << json_escape(alert.detail) << "\",\n"
                  << "    \"indicator\": \"" << json_escape(alert.indicator) << "\",\n"
                  << "    \"source\": \"" << json_escape(alert.source) << "\"\n"
                  << "  }" << (i + 1 < alerts.size() ? "," : "") << "\n";
    }
    std::cout << "]\n";
}

std::string build_report(std::vector<Alert> alerts,
                         const std::vector<std::string>& versions) {
    std::stable_sort(alerts.begin(), alerts.end(),
                     [](const Alert& left, const Alert& right) {
                         return severity_rank(left.level) < severity_rank(right.level);
                     });

    std::map<std::string, int> counts;
    for (const auto& alert : alerts) {
        ++counts[alert.level];
    }

    std::ostringstream report;
    report << "# iOS 网络安全威胁监测报告（C++）\n\n"
           << "| 项目 | 内容 |\n"
           << "|---|---|\n"
           << "| 生成时间 | " << now_utc() << " |\n"
           << "| 告警总数 | " << alerts.size() << " |\n"
           << "| 严重 | " << counts["严重"] << " |\n"
           << "| 高 | " << counts["高"] << " |\n"
           << "| 中 | " << counts["中"] << " |\n"
           << "| 低 | " << counts["低"] << " |\n\n"
           << "> 本报告由防御性日志分析工具自动生成。该工具不抓取实时流量，"
              "仅分析用户明确提供的日志和指标。\n\n";

    if (!versions.empty()) {
        report << "## 设备版本合规检查\n\n"
               << "| iOS 版本 | 风险 | 严重度 | 建议 |\n"
               << "|---|---|---|---|\n";
        for (const auto& version : versions) {
            for (const auto& finding : check_version(version)) {
                report << "| " << markdown_escape(finding.version)
                       << " | " << markdown_escape(finding.threat)
                       << " | " << markdown_escape(finding.severity)
                       << " | " << markdown_escape(finding.recommendation) << " |\n";
            }
        }
        report << "\n";
    }

    report << "## 告警详情\n\n";
    if (alerts.empty()) {
        report << "未发现匹配当前规则的告警。该结果不等于设备或网络不存在未知威胁。\n\n";
    } else {
        report << "| # | 严重度 | 类别 | 详情 | 指标 | 来源 |\n"
               << "|---|---|---|---|---|---|\n";
        for (std::size_t i = 0; i < alerts.size(); ++i) {
            const auto& alert = alerts[i];
            report << "| " << i + 1
                   << " | **" << markdown_escape(alert.level)
                   << "** | " << markdown_escape(alert.category)
                   << " | " << markdown_escape(alert.detail)
                   << " | `" << markdown_escape(alert.indicator)
                   << "` | " << markdown_escape(alert.source) << " |\n";
        }
        report << "\n";
    }

    report << "## 已知 IOC 参考\n\n"
           << "### DarkSword C2 / 投递域名\n\n";
    for (const auto& domain : kDarkSwordDomains) {
        report << "- `" << domain << "`\n";
    }
    report << "\n### 被入侵的合法水坑站点\n\n"
           << "> 应监控访问并告警，不建议仅依据域名直接封禁。\n\n";
    for (const auto& domain : kCompromisedWateringHoles) {
        report << "- `" << domain << "`\n";
    }
    report << "\n### DarkSword 已知 IP\n\n";
    for (const auto& ip : kDarkSwordIps) {
        report << "- `" << ip << "`\n";
    }
    report << "\n### 已知通信端口\n\n";
    for (int port : kSuspiciousPorts) {
        report << "- `" << port << "`\n";
    }

    report << "\n## 响应建议\n\n"
           << "1. **严重：**立即隔离相关设备，采集 sysdiagnose、DNS、代理和身份日志。\n"
           << "2. **高：**4 小时内确认访问上下文，排除合法水坑站点误报。\n"
           << "3. **中：**24 小时内关联 WebKit 崩溃、账户异常和出站流量。\n"
           << "4. **版本不合规：**72 小时内升级或将设备退出敏感业务。\n"
           << "5. **确认感染：**完成取证后擦除重装，并从可信设备轮换全部凭据。\n\n"
           << "## 数据与规则限制\n\n"
           << "- IOC 会快速过期，应至少每 90 天更新一次。\n"
           << "- 域名关键词规则可能误报，不能作为单独定罪依据。\n"
           << "- 未命中规则不代表安全；未知基础设施和新变体不会被静态 IOC 捕获。\n"
           << "- 版本范围来自公开研究，实际可利用性取决于完整构建号、芯片和补丁状态。\n\n"
           << "## 参考来源\n\n"
           << "- [Google Threat Intelligence — DarkSword](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain)\n"
           << "- [Google Threat Intelligence — Coruna](https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit)\n"
           << "- [Apple Security Releases](https://support.apple.com/en-us/100100)\n"
           << "- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)\n\n"
           << "---\n\n"
           << "*本工具仅用于授权的防御性安全监测。*\n\n"
           << "咨询ios系统请咨询  telegram：@DZHT333333\n";
    return report.str();
}

bool write_report(const std::string& path,
                  const std::vector<Alert>& alerts,
                  const std::vector<std::string>& versions) {
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        std::cerr << "报告生成失败：无法打开 " << path << "\n";
        return false;
    }
    output << build_report(alerts, versions);
    if (!output) {
        std::cerr << "报告生成失败：写入 " << path << " 时发生错误\n";
        return false;
    }
    std::cout << "监测报告已生成：" << path << "\n";
    return true;
}

void print_alert(const Alert& alert) {
    std::cout << "[" << alert.level << "] " << alert.category
              << "：" << alert.detail << "（" << alert.indicator << "）";
    if (!alert.source.empty()) {
        std::cout << " [" << alert.source << "]";
    }
    std::cout << "\n";
}

void print_usage(const char* program) {
    std::cout
        << "iOS 网络安全威胁监测工具（C++17）\n\n"
        << "用法：\n"
        << "  " << program << "                                  演示模式\n"
        << "  " << program << " --check-version 17.2.1 18.5      检查版本\n"
        << "  " << program << " --check-domain cdncounter.net   检查域名\n"
        << "  " << program << " --check-ip 141.105.130.237       检查 IP\n"
        << "  " << program << " --dns-log dns.txt                分析 DNS 日志\n"
        << "  " << program << " --scan-network connections.csv  分析 CSV 网络日志\n"
        << "  " << program << " --report --output report.md      生成报告\n"
        << "  " << program << " --json                           输出 JSON 告警\n\n"
        << "CSV 支持列：domain,dst_ip,dst_port,user_agent,bytes_out\n"
        << "咨询ios系统请咨询  telegram：@DZHT333333\n";
}

void run_demo() {
    std::cout << "============================================================\n"
              << "  iOS 网络安全威胁监测工具（C++）— 演示模式\n"
              << "============================================================\n\n";

    const std::vector<std::string> versions = {
        "15.6.1", "17.2.1", "18.5", "18.7.3", "26.2", "26.6"};
    std::vector<Alert> alerts;

    std::cout << "[1/3] 设备版本合规检查\n";
    for (const auto& version : versions) {
        for (const auto& finding : check_version(version)) {
            std::cout << "  [" << finding.severity << "] iOS " << version
                      << " → " << finding.threat << "\n";
        }
    }

    std::cout << "\n[2/3] 域名 IOC 检测\n";
    for (const auto& domain : {"static.cdncounter.net", "novosti.dn.ua",
                               "wallet-recovery-free-token.example", "www.apple.com"}) {
        const auto found = check_domain(domain, "演示数据");
        if (found.empty()) {
            std::cout << "  [未命中] " << domain << "\n";
        } else {
            for (const auto& alert : found) {
                print_alert(alert);
            }
            append_alerts(alerts, found);
        }
    }

    std::cout << "\n[3/3] IP 和端口 IOC 检测\n";
    append_alerts(alerts, check_ip("141.105.130.237", "演示数据"));
    append_alerts(alerts, check_port(8881, "sqwas.shapelie.com", "演示数据"));
    for (const auto& alert : alerts) {
        if (alert.category == "IOC IP 匹配" || alert.category == "可疑端口") {
            print_alert(alert);
        }
    }

    write_report("iOS网络安全威胁监测报告_cpp_demo.md", alerts, versions);
    std::cout << "共生成 " << alerts.size() << " 条演示告警。\n"
              << "咨询ios系统请咨询  telegram：@DZHT333333\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 1) {
        run_demo();
        return 0;
    }

    std::vector<Alert> alerts;
    std::vector<std::string> versions;
    std::string output_path = "iOS网络安全威胁监测报告_cpp.md";
    bool generate_report = false;
    bool json_output = false;

    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];

        if (argument == "--help" || argument == "-h") {
            print_usage(argv[0]);
            return 0;
        }
        if (argument == "--report") {
            generate_report = true;
            continue;
        }
        if (argument == "--json") {
            json_output = true;
            continue;
        }
        if ((argument == "--output" || argument == "-o") && i + 1 < argc) {
            output_path = argv[++i];
            continue;
        }
        if (argument == "--dns-log" && i + 1 < argc) {
            const std::string path = argv[++i];
            append_alerts(alerts, analyze_dns_log(path));
            generate_report = true;
            continue;
        }
        if (argument == "--scan-network" && i + 1 < argc) {
            const std::string path = argv[++i];
            append_alerts(alerts, analyze_network_log(path));
            generate_report = true;
            continue;
        }
        if (argument == "--check-version" && i + 1 < argc) {
            while (i + 1 < argc && !is_option(argv[i + 1])) {
                const std::string version = argv[++i];
                versions.push_back(version);
                for (const auto& finding : check_version(version)) {
                    std::cout << "[" << finding.severity << "] iOS " << version
                              << " — " << finding.threat << "："
                              << finding.description << "\n";
                }
            }
            continue;
        }
        if (argument == "--check-domain" && i + 1 < argc) {
            while (i + 1 < argc && !is_option(argv[i + 1])) {
                const std::string domain = argv[++i];
                const auto found = check_domain(domain, "命令行输入");
                if (found.empty()) {
                    std::cout << "[未命中] " << domain << "\n";
                } else {
                    append_alerts(alerts, found);
                    for (const auto& alert : found) print_alert(alert);
                }
            }
            continue;
        }
        if (argument == "--check-ip" && i + 1 < argc) {
            while (i + 1 < argc && !is_option(argv[i + 1])) {
                const std::string ip = argv[++i];
                const auto found = check_ip(ip, "命令行输入");
                if (found.empty()) {
                    std::cout << "[未命中] " << ip << "\n";
                } else {
                    append_alerts(alerts, found);
                    for (const auto& alert : found) print_alert(alert);
                }
            }
            continue;
        }

        std::cerr << "未知或缺少参数值：" << argument << "\n";
        print_usage(argv[0]);
        return 2;
    }

    if (json_output) {
        print_json(alerts);
    }
    if (generate_report || !alerts.empty()) {
        if (!write_report(output_path, alerts, versions)) {
            return 1;
        }
    }
    return 0;
}
