## THuntPro

THuntPro（Threat Hunt Pro）是一款面向安全研究与威胁情报检索的本地化聚合工具。它通过整合多家威胁情报、样本分析与IOC服务，对哈希、URL/域名、IP 等指标进行快速查询与结果汇总，辅助威胁溯源、告警验证与样本联动分析。

### 功能与作用
- 聚合查询：整合 VirusTotal、ThreatFox、ThreatBook、AlienVault OTX、AbuseIPDB、Hybrid Analysis、Triage、Malshare、MalwareBazaar、URLHaus、InQuest、VirusExchange 等来源的检索结果。
- 指标支持：
  - 文件哈希：MD5/SHA1/SHA256（样本情报检索、关联样本展示、样本下载（视权限））。
  - URL/域名：威胁标签、被动解析、证书、黑名单命中等聚合信息。
  - IP 地址：信誉与基础情报（各来源支持范围可能不同）。
- 样本流转：支持多平台样本上传（可选），支持从指定源下载可公开共享的样本。
- 结果呈现：中文报告与彩色终端渲染，便于快速浏览关键信息。

### 主要模块
- `modules/aggregate.py`：核心聚合与报告输出逻辑。
- `modules/urlgate.py`：URL/域名专用查询与展示。
- `modules/*.py`：对接各情报/沙箱平台的具体实现（如 `malshare.py`、`bazaar.py`、`hybrid.py`、`inquest.py` 等）。
- `utils/*.py`：通用工具（颜色渲染、哈希计算、PE 信息等）。

### 运行环境
- Python 3.9+（建议 3.9/3.10）。
- 操作系统：macOS、Linux、Windows（Windows 需 `colorama` 自动处理控制台颜色）。

### 必需与可选依赖库
- Python 库（必需）
  - `colorama`：终端颜色与跨平台兼容。
  - `requests`：HTTP 请求。
  - `validators`：URL 合法性校验。
  - `python-magic`：文件类型识别（用于样本元信息展示）。
  - `pefile`：PE 文件结构解析（Windows 样本相关能力）。
  - `geocoder`：IP 地理信息（Hybrid Analysis 报告展示中用到）。

- 系统级依赖（如需）
  - `libmagic`：`python-magic` 的底层依赖。不同系统需通过各自包管理器安装（例如 macOS 可通过 Homebrew 安装 `libmagic`，Linux 发行版对应 `file/libmagic` 包）。

说明：部分平台接口需要在用户目录或项目目录下准备 `.malwapi.conf` 配置以存放 API Key；不同来源的可用性与返回字段以其在线服务为准。

### 配置文件 `.malwapi.conf`
项目根目录：`THuntPro/.malwapi.conf`


示例（INI 格式）：
```
[VIRUSTOTAL]
VTAPI = <your_vt_api_key>

[BAZAAR]
BAZAARAPI = <your_malware_bazaar_auth_key>

[THREATFOX]
THREATFOXAPI = <your_threatfox_auth_key>

[THREATBOOK]
THREATBOOKAPI = <your_threatbook_api_key>

[ALIENVAULT]
ALIENAPI = <your_otx_api_key>

[ABUSEIPDB]
APIKEY = <your_abuseipdb_key>

[HYBRID-ANALYSIS]
HAAPI = <your_hybrid_analysis_key>

[TRIAGE]
TRIAGEAPI = <your_triage_key>

[MALSHARE]
MALSHAREAPI = <your_malshare_key>

[URLHAUS]
HAUSSUBMITAPI = <optional_submit_key_if_any>

[INQUEST]
INQUESTAPI = <your_inquest_key>

[VIRUSEXCHANGE]
VXAPI = <your_virus_exchange_token>
```

说明与映射：
- 工具内部会同时兼容大写段名与常用别名。例如 `VIRUSTOTAL` 段也会读取 `VTAPI` 键。
- 并非所有平台都必须配置；未配置时相关查询会跳过或返回“未命中/不可用”。

### 使用方式（命令）
```
python THuntPro.py -t <indicator>
  指标示例：
  - 哈希：da095241b82ced1d375181e67a72696703f894ae74e8d98fe43576544981cb50
  - IP：45.204.215.15
  - URL：http://example.com/malware.exe
  - 域名：example.com

python THuntPro.py -u <file_path>
  将本地样本上传至已配置的平台（如 VT、HA、Triage、Bazaar、OTX）。

python THuntPro.py -d <engine_id> -t <hash>
  下载公开共享样本：1=Malshare, 2=HybridAnalysis, 3=URLHaus, 4=InQuest, 5=VirusExchange, 6=MalwareBazaar
```

### 安装依赖
使用与你运行脚本相同的 Python 安装依赖（示例基于 macOS/Linux）：
```
python3 -m pip install --user colorama requests validators pefile python-magic geocoder
```

如提示 `urllib3` 与本机 LibreSSL 版本兼容性警告，属环境提示，不影响功能；若需消除，可升级 OpenSSL 或将 `urllib3` 固定到兼容版本。

### 注意事项
- 样本下载、上传能力受各平台策略限制，需遵守相应服务条款与法律法规，仅用于合规的安全研究与分析。
- `python-magic` 依赖 `libmagic`，如缺失请通过系统包管理器安装对应的底层包。
- Windows 控制台颜色由 `colorama` 处理，若颜色异常请确认其是否已安装。
