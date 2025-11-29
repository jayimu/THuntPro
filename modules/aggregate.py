import re
import json
import socket
import requests
import os
import shutil
import glob
import time
import functools
import shutil
from typing import Dict, Any, List, Tuple, Optional
import concurrent.futures
from .threatbook import query_threatbook
from .abuseipdb import AbuseIPDBClient
from datetime import datetime, timedelta

# 预期的情报源列表
EXPECTED_SOURCES = [
    "VirusTotal", "MalwareBazaar", "ThreatFox", "URLHaus", "AlienVault", 
    "InQuest", "AbuseIPDB", "HybridAnalysis", "Triage", "ThreatBook", "Malshare"
]

def get_terminal_width() -> int:
    """获取终端宽度，用于响应式布局"""
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 120  # 默认宽度


def format_multi_column(items: List[str], label_width: int = 18, min_col_width: int = 30) -> str:
    """将项目列表格式化为多列显示"""
    if not items:
        return ""
    
    terminal_width = get_terminal_width()
    available_width = terminal_width - label_width - 3  # 减去标签宽度和分隔符
    
    # 计算列数
    cols = max(1, min(3, available_width // min_col_width))
    if cols == 1:
        return ", ".join(items)
    
    # 计算每列宽度
    col_width = available_width // cols
    
    lines = []
    for i in range(0, len(items), cols):
        row_items = items[i:i+cols]
        # 确保每列不超过计算宽度
        formatted_items = []
        for item in row_items:
            if len(item) > col_width - 2:
                formatted_items.append(item[:col_width-5] + "...")
            else:
                formatted_items.append(item)
        
        # 填充到相同宽度
        padded_items = [item.ljust(col_width-2) for item in formatted_items]
        lines.append("  ".join(padded_items))
    
    return "\n".join(lines)


# 内存缓存装饰器
@functools.lru_cache(maxsize=128)
def get_cached_data_memory(indicator: str, engine_name: str) -> Optional[Dict[str, Any]]:
    """内存缓存：检查文件缓存并返回数据，使用LRU缓存避免重复文件I/O"""
    return check_cache_and_load(indicator, engine_name)


def clear_tmp_folder() -> None:
    """清空 tmp 文件夹"""
    try:
        tmp_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tmp")
        if os.path.exists(tmp_dir):
            for file in os.listdir(tmp_dir):
                file_path = os.path.join(tmp_dir, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)
    except Exception:
        pass  # 忽略清理错误


def save_json_data(indicator: str, engine_name: str, data: Dict[str, Any]) -> None:
    """保存各引擎完整 JSON 数据到 modules/tmp。
    - 默认：{engine}_{indicator}_{timestamp}.json（仅保留最新一份）。
    - 特例：HybridAnalysis 与 MalwareBazaar 使用固定命名：
      HybridAnalysis+<hash>.json, MalwareBazaar+<hash>.json。
    - 过期逻辑通过 mtime 与 clear_old_cache 实现。
    """
    try:
        # 创建包目录下的 tmp 缓存文件夹
        tmp_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tmp")
        if not os.path.exists(tmp_dir):
            os.makedirs(tmp_dir)
        
        # 对 indicator 进行安全处理，移除特殊字符
        safe_indicator = re.sub(r'[^\w\-\.]', '_', indicator)
        # 限制长度，避免文件名过长
        safe_indicator = safe_indicator[:50]
        
        eng_lower = (engine_name or '').lower()
        # 特例固定命名：覆盖写
        if eng_lower == 'hybrid':
            filename = f"HybridAnalysis+{safe_indicator}.json"
            filepath = os.path.join(tmp_dir, filename)
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception:
                pass
        elif eng_lower == 'bazaar':
            filename = f"MalwareBazaar+{safe_indicator}.json"
            filepath = os.path.join(tmp_dir, filename)
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception:
                pass
        else:
            # 文件名：引擎名_安全指标_时间戳.json，仅保留一个最新文件
            filename = f"{eng_lower}_{safe_indicator}_{int(time.time())}.json"
            filepath = os.path.join(tmp_dir, filename)
            # 先清理同前缀旧文件：仅保留一个最新文件
            try:
                prefix_pattern = os.path.join(tmp_dir, f"{eng_lower}_{safe_indicator}_*.json")
                old_files = sorted(glob.glob(prefix_pattern), key=os.path.getmtime, reverse=True)
                for old in old_files[1:]:
                    try:
                        os.remove(old)
                    except Exception:
                        pass
            except Exception:
                pass

        # 保存 JSON 数据
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            
    except Exception as e:
        print(f"保存 JSON 数据失败: {e}")


def _ensure_url_tmp_dir() -> str:
    """确保包目录下 url_tmp 存在（用于 URL 类结果缓存）。"""
    try:
        base_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "url_tmp")
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
        return base_dir
    except Exception:
        return os.path.join(os.path.dirname(os.path.dirname(__file__)), "url_tmp")


def save_url_json(indicator: str, engine_name: str, data: Dict[str, Any]) -> None:
    """将 URL/域名查询 JSON 保存至包目录下 url_tmp（稳定文件名，无时间戳）。"""
    try:
        out_dir = _ensure_url_tmp_dir()
        safe_indicator = re.sub(r'[^\w\-\.]', '_', indicator)[:80]
        filepath = os.path.join(out_dir, f"{engine_name.lower()}_{safe_indicator}.json")
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def check_cache_and_load(indicator: str, engine_name: str) -> Optional[Dict[str, Any]]:
    """检查缓存是否在一个月内，如有效则加载最新文件；否则返回 None。
    - 特例优先：HybridAnalysis+<hash>.json, MalwareBazaar+<hash>.json。
    - 其次：{engine}_{indicator}_{timestamp}.json 取最新。
    """
    try:
        tmp_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tmp")
        if not os.path.exists(tmp_dir):
            return None
        
        safe_indicator = re.sub(r'[^\w\-\.]', '_', indicator)[:50]
        eng_lower = (engine_name or '').lower()
        candidates: List[str] = []
        # 特例固定命名优先
        if eng_lower == 'hybrid':
            candidates.append(os.path.join(tmp_dir, f"HybridAnalysis+{safe_indicator}.json"))
        elif eng_lower == 'bazaar':
            candidates.append(os.path.join(tmp_dir, f"MalwareBazaar+{safe_indicator}.json"))
        # 新命名（带时间戳）：选择同前缀的最新文件
        try:
            pattern = os.path.join(tmp_dir, f"{eng_lower}_{safe_indicator}_*.json")
            stamped_files = glob.glob(pattern)
            if stamped_files:
                latest = max(stamped_files, key=os.path.getmtime)
                candidates.append(latest)
        except Exception:
            pass

        for fp in candidates:
            if not os.path.isfile(fp):
                continue
            try:
                file_time = datetime.fromtimestamp(os.path.getmtime(fp))
                if datetime.now() - file_time <= timedelta(days=30):
                    with open(fp, 'r', encoding='utf-8') as f:
                        return json.load(f)
            except Exception:
                continue
        return None
            
    except Exception:
        return None
    
    return None


def clear_old_cache() -> None:
    """清理超过一个月的旧缓存文件（按 mtime 判断）。"""
    try:
        tmp_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tmp")
        if not os.path.exists(tmp_dir):
            return
        
        now = datetime.now()
        cutoff_time = now - timedelta(days=30)
        
        for file_path in glob.glob(os.path.join(tmp_dir, "*.json")):
            try:
                mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                if mtime < cutoff_time:
                        os.remove(file_path)
            except (OSError, ValueError):
                continue
                
    except Exception as e:
        print(f"清理旧缓存失败: {e}")


def clear_tmp_folder() -> None:
    """清理超过一个月的旧缓存文件，保留新缓存"""
    try:
        clear_old_cache()
    except Exception as e:
        print(f"清理缓存失败: {e}")


def extract_iocs_from_strings(text: str) -> Tuple[List[str], List[str], List[str]]:
    """从文本中提取 IOC（IP、域名、URL）"""
    ips = []
    domains = []
    urls = []
    
    # 提取 IP 地址
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ips = re.findall(ip_pattern, text)
    
    # 提取 URL
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, text)
    
    # 从 URL 中提取域名
    for url in urls:
        domain_match = re.search(r'https?://([^/]+)', url)
        if domain_match:
            domain = domain_match.group(1)
            if domain not in domains:
                domains.append(domain)
    
    # 提取其他域名（非 IP）
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    found_domains = re.findall(domain_pattern, text)
    for domain in found_domains:
        # 检查是否是 IP 地址
        if not re.match(ip_pattern, domain) and domain not in domains and domain not in ips:
            domains.append(domain)
    
    return list(dict.fromkeys(ips)), list(dict.fromkeys(domains)), list(dict.fromkeys(urls))


def is_md5(value: str) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]{32}", value))


def is_sha1(value: str) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]{40}", value))


def is_sha256(value: str) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]{64}", value))


def extract_indicators(text: str) -> Tuple[List[str], List[str]]:
    ips = re.findall(r"\b(?:(?:2(5[0-5]|[0-4]\d))|(?:1?\d?\d))(?:\.(?:(?:2(5[0-5]|[0-4]\d))|(?:1?\d?\\d))){3}\b", text)
    ips = [m[0] if isinstance(m, tuple) else m for m in ips]
    # 简单域名匹配（排除纯数字与已匹配 IP）
    domains = re.findall(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}\b", text)
    domains = [d for d in domains if not re.fullmatch(r"\d+(?:\.\d+){3}", d)]
    return list(dict.fromkeys(ips)), list(dict.fromkeys(domains))


def vt_lookup(hash_value: str, api_key: str) -> Dict[str, Any]:
    # 首先检查内存缓存
    cached_result = get_cached_data_memory(hash_value, "vt_result")
    if cached_result:
        print(f"📦 使用 VirusTotal 缓存数据")
        return cached_result
    
    # 没有缓存，进行完整 API 查询
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code != 200:
        return {"source": "VirusTotal", "hit": False, "error": r.text}
    data = r.json()
    
    # 保存原始 JSON 数据
    save_json_data(hash_value, "virustotal", data)
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    names = attrs.get("names", [])
    cls = attrs.get("popular_threat_classification", {})
    label = (cls.get("suggested_threat_label") or "")
    
    # 简化威胁标签显示 - 只显示主要威胁类型和命中次数
    threat_tags = []
    if label:
        threat_tags.append(label)
    
    # 从 popular_threat_category 提取主要威胁类型和命中次数
    if cls:
        threat_categories = cls.get("popular_threat_category", [])
        if threat_categories:
            for cat in threat_categories:
                if isinstance(cat, dict) and cat.get("value") and cat.get("count"):
                    threat_tags.append(f"{cat['value']} ({cat['count']}次)")
        
        threat_names = cls.get("popular_threat_name", [])
        if threat_names:
            for name in threat_names:
                if isinstance(name, dict) and name.get("value") and name.get("count"):
                    threat_tags.append(f"{name['value']} ({name['count']}次)")
    # PE 元信息（如有）— 仅导入/导出
    pe_info = attrs.get("pe_info") or {}
    imports: List[str] = []
    exports: List[str] = []
    if pe_info:
        for lib in pe_info.get("import_list", []) or []:
            dll = lib.get("library_name")
            for fn in lib.get("imported_functions", []) or []:
                if dll and fn:
                    imports.append(f"{dll}!{fn}")
        for ex in pe_info.get("exported_functions", []) or []:
            if ex:
                exports.append(str(ex))

    # 关联关系（网络 IOC、URL、文件落地等）从 relationships 与 behaviour_summary 提取
    def _vt_rel(rel: str) -> List[Dict[str, Any]]:
        rel_url = f"https://www.virustotal.com/api/v3/files/{hash_value}/relationships/{rel}"
        try:
            rr = requests.get(rel_url, headers=headers, timeout=30)
            if rr.status_code != 200:
                return []
            return rr.json().get("data", []) or []
        except Exception:
            return []

    contacted_ips = _vt_rel("contacted_ips")
    contacted_domains = _vt_rel("contacted_domains")
    contacted_urls = _vt_rel("contacted_urls")
    dropped_rel = _vt_rel("dropped_files")

    net_ips = []
    for it in contacted_ips:
        attr = (it.get("attributes") or {})
        ip = attr.get("ip_address") or it.get("id")
        if ip:
            net_ips.append(ip)
    net_domains = []
    for it in contacted_domains:
        dom = it.get("id")
        if dom:
            net_domains.append(dom)
    urls = []
    for it in contacted_urls:
        attr = (it.get("attributes") or {})
        u = attr.get("url") or it.get("id")
        if u:
            urls.append(u)
    dropped = []
    for it in dropped_rel:
        attr = (it.get("attributes") or {})
        sha256 = attr.get("sha256") or it.get("id")
        if sha256:
            dropped.append(sha256)

    # 行为摘要（进程与进程树）
    procs: List[str] = []
    proc_nodes: List[Dict[str, Any]] = []
    behavior_data = {
        "shell_commands": [],
        "processes_created": [],
        "processes_terminated": [],
        "services_opened": [],
        "files_written": []
    }
    
    try:
        # 为 behaviour_summary 增加重试与可选关闭证书校验
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        import requests as _rq
        _session = _rq.Session()
        _session.mount("https://", HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504))))
        _verify = os.environ.get("VT_VERIFY", "1") not in {"0", "false", "False"}
        bs = _session.get(f"https://www.virustotal.com/api/v3/files/{hash_value}/behaviour_summary", headers=headers, timeout=30, verify=_verify)
        if bs.status_code == 200:
            bsj = bs.json().get("data", {})
            
            
            # 提取进程信息
            for p in bsj.get("processes", []) or []:
                name = p.get("name") or p.get("image")
                if name:
                    procs.append(name)
                if isinstance(p, dict):
                    node = {"pid": p.get("pid"), "ppid": p.get("ppid"), "name": name}
                    if node["pid"] is not None or node["name"]:
                        proc_nodes.append(node)
            
            # 提取行为数据
            # Shell commands - 使用正确的字段名 command_executions
            commands = bsj.get("command_executions", [])
            if isinstance(commands, list):
                for cmd in commands:
                    if isinstance(cmd, str) and cmd.strip():
                        behavior_data["shell_commands"].append(cmd.strip())
                    elif isinstance(cmd, dict):
                        # 尝试不同的命令字段
                        cmd_text = cmd.get("command") or cmd.get("cmd") or cmd.get("executable") or cmd.get("args")
                        if cmd_text and cmd_text.strip():
                            behavior_data["shell_commands"].append(cmd_text.strip())
            
            # Processes created
            for proc in bsj.get("processes_created", []) or []:
                if isinstance(proc, str) and proc.strip():
                    behavior_data["processes_created"].append(proc.strip())
            
            # Processes terminated
            for proc in bsj.get("processes_terminated", []) or []:
                if isinstance(proc, str) and proc.strip():
                    behavior_data["processes_terminated"].append(proc.strip())
            
            # Services opened
            for service in bsj.get("services_opened", []) or []:
                if isinstance(service, str) and service.strip():
                    behavior_data["services_opened"].append(service.strip())
            
            # Files written
            for file in bsj.get("files_written", []) or []:
                if isinstance(file, str) and file.strip():
                    behavior_data["files_written"].append(file.strip())
            
            # 追加从行为获取的网络 IOC（如可用）
            for ip in bsj.get("contacted_ips", []) or []:
                if isinstance(ip, str):
                    net_ips.append(ip)
            for dom in bsj.get("contacted_domains", []) or []:
                if isinstance(dom, str):
                    net_domains.append(dom)
            for u in bsj.get("contacted_urls", []) or []:
                if isinstance(u, str):
                    urls.append(u)
    except Exception as e:
        # 网络/SSL 问题不应中断整体流程，仅提示一次
        print(f"⚠️ Behaviour Summary 错误: {e}")

    # 时间格式化
    def _fmt(ts):
        try:
            if isinstance(ts, (int, float)):
                return datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d")
        except Exception:
            return ts
        return ts

    result = {
        "source": "VirusTotal",
        "hit": True,
        "summary": {
            "检测统计": {
                "恶意": stats.get("malicious", 0),
                "可疑": stats.get("suspicious", 0), 
                "无害": stats.get("harmless", 0),
                "未检测": stats.get("undetected", 0),
                "失败": stats.get("failure", 0) + stats.get("timeout", 0) + stats.get("type-unsupported", 0)
            },
            "样本别名": names[:10],
            "威胁标签": threat_tags if threat_tags else [],
            "文件类型": attrs.get("type_description"),
            "首次见到": _fmt(attrs.get("first_submission_date")),
            "最后分析": _fmt(attrs.get("last_analysis_date")),
            # 不做裁剪，完整输出导入/导出函数（展示层自行分组/去重）
            "导入函数": imports,
            "导出函数": exports,
        },
        "raw": attrs,
        "ioc": {"ips": list(dict.fromkeys(net_ips)), "domains": list(dict.fromkeys(net_domains)), "urls": list(dict.fromkeys(urls[:100]))},
        "dropped": list(dict.fromkeys(dropped[:50])),
        "processes": list(dict.fromkeys(procs[:50])),
        "process_tree": proc_nodes[:200],
        "behavior": behavior_data,
    }
    
    # 保存完整结果到缓存
    save_json_data(hash_value, "vt_result", result)
    return result


def bazaar_lookup(hash_value: str, api_key: str) -> Dict[str, Any]:
    # 首先检查内存缓存
    cached_data = get_cached_data_memory(hash_value, "bazaar")
    if cached_data:
        print(f"📦 使用 MalwareBazaar 缓存数据")
        js = cached_data
    else:
        # 没有缓存，进行 API 查询
        url = "https://mb-api.abuse.ch/api/v1/"
        s = requests.Session()
        s.headers.update({"accept": "application/json", "Auth-Key": api_key})
        
        # 首先尝试 get_info 查询
        resp = s.post(url, data={"query": "get_info", "hash": hash_value}, timeout=30)
        try:
            js = resp.json()
            # 保存完整 JSON 数据
            save_json_data(hash_value, "bazaar", js)
        except Exception:
            return {"source": "MalwareBazaar", "hit": False, "error": resp.text}
    
    # 如果 get_info 没有找到，尝试其他查询方法
    if js.get("query_status") in {"hash_not_found", "no_results"}:
        # 尝试通过 imphash 查询（如果是 PE 文件）
        try:
            # 从 VirusTotal 获取 imphash（如果可用）
            vt_data = check_cache_and_load(hash_value, "vt_result")
            if vt_data and vt_data.get("hit"):
                pe_info = vt_data.get("raw", {}).get("pe_info", {})
                imphash = pe_info.get("imphash")
                if imphash:
                    resp = s.post(url, data={"query": "get_imphash", "imphash": imphash}, timeout=30)
                    try:
                        js = resp.json()
                        if js.get("query_status") not in {"hash_not_found", "no_results"}:
                            save_json_data(hash_value, "bazaar", js)
                    except Exception:
                        pass
        except Exception:
            pass
        
        # 如果仍然没有找到，尝试通过签名查询
        if js.get("query_status") in {"hash_not_found", "no_results"}:
            try:
                # 从 VirusTotal 获取签名信息
                vt_data = check_cache_and_load(hash_value, "vt_result")
                if vt_data and vt_data.get("hit"):
                    signature = vt_data.get("summary", {}).get("家族/签名", "")
                    if signature and signature != "威胁分数: 10":
                        # 尝试通过签名查询
                        resp = s.post(url, data={"query": "get_taginfo", "tag": signature}, timeout=30)
                        try:
                            js = resp.json()
                            if js.get("query_status") not in {"hash_not_found", "no_results"}:
                                save_json_data(hash_value, "bazaar", js)
                        except Exception:
                            pass
            except Exception:
                pass
    
    if js.get("query_status") in {"hash_not_found", "no_results"}:
        return {"source": "MalwareBazaar", "hit": False}
    
    data = (js.get("data") or [])
    first = data[0] if data else {}
    vendor_intel = first.get("vendor_intel") or {}
    comment = first.get("comment") or ""
    
    # 提取更多信息
    intelligence = first.get("intelligence", {})
    clamav = intelligence.get("clamav", [])
    downloads = intelligence.get("downloads", "0")
    uploads = intelligence.get("uploads", "0")
    
    return {
        "source": "MalwareBazaar",
        "hit": True,
        "summary": {
            "文件名": first.get("file_name"),
            "家族/签名": first.get("signature"),
            "标签": first.get("tags"),
            "国家": first.get("origin_country"),
            "文件大小": first.get("file_size"),
            "文件类型": first.get("file_type"),
            "首次发现": first.get("first_seen"),
            "最后发现": first.get("last_seen"),
            "下载次数": downloads,
            "上传次数": uploads,
            "ClamAV检测": clamav[:5] if clamav else [],
        },
        "raw": first,
        "notes": comment,
        "vendor_intel": vendor_intel,
        "intelligence": intelligence,
    }


def threatfox_lookup(ioc: str, api_key: str) -> Dict[str, Any]:
    # 首先检查内存缓存
    cached_data = get_cached_data_memory(ioc, "threatfox")
    if cached_data:
        print(f"📦 使用 ThreatFox 缓存数据")
        js = cached_data
    else:
        # 没有缓存，进行 API 查询
        url = "https://threatfox-api.abuse.ch/api/v1/"
        s = requests.Session()
        s.headers.update({"accept": "application/json", "Auth-Key": api_key, "Content-Type": "application/json"})
        # 优先尝试 ioc: 前缀（例如 ioc:payload.tahirvoip.shop），不命中再回退原值
        js = {}
        for term in (f"ioc:{ioc}", ioc):
            try:
                resp = s.post(url, data=json.dumps({"query": "search_ioc", "search_term": term}), timeout=30)
                tmp = resp.json()
                if tmp.get("query_status") != "no_result":
                    js = tmp
                    break
            except Exception:
                continue
        
        # 保存完整 JSON 数据
        # ThreatFox 结果写入 url_tmp（而非 tmp）
        save_url_json(ioc, "threatfox", js)
    if not js or js.get("query_status") == "no_result":
        return {"source": "ThreatFox", "hit": False}
    items = js.get("data") or []
    # 解析 ThreatFox 返回的 IOC 类型
    tf_ips: List[str] = []
    tf_domains: List[str] = []
    tf_urls: List[str] = []
    # 汇总ThreatFox关键信息（类型/别名/置信度/时间/国家）
    threat_types: List[str] = []
    malware_aliases: List[str] = []
    confidences: List[str] = []
    first_seen_list: List[str] = []
    last_seen_list: List[str] = []
    countries: List[str] = []
    tf_tags: List[str] = []
    refs: List[str] = []
    for it in items:
        val = it.get("ioc") or ""
        t = (it.get("ioc_type") or "").lower()
        if not val:
            continue
        if t in {"ip", "ipv4", "ipv6"}:
            tf_ips.append(val)
        elif t in {"domain", "fqdn"}:
            tf_domains.append(val)
        elif t in {"url"}:
            tf_urls.append(val)
        # 汇总附加字段
        th_type = it.get("threat_type") or it.get("threat_type_desc") or it.get("threat_type_label")
        if th_type:
            threat_types.append(str(th_type))
        # 完整恶意家族别名：兼容多字段/列表/逗号分隔
        malias_val = (
            it.get("malware_alias")
            or it.get("malware_aliases")
            or it.get("malware_printable")
            or it.get("malware_family")
            or it.get("malware")
        )
        if malias_val:
            if isinstance(malias_val, list):
                malware_aliases.append(", ".join([str(x) for x in malias_val if x]))
            else:
                malware_aliases.append(str(malias_val))
        conf = it.get("confidence_level")
        if conf is not None:
            confidences.append(str(conf))
        fs = it.get("first_seen") or it.get("first_seen_utc")
        if fs:
            first_seen_list.append(str(fs))
        ls = it.get("last_seen") or it.get("last_seen_utc")
        if ls:
            last_seen_list.append(str(ls))
        ctry = it.get("country") or it.get("cc")
        if ctry:
            countries.append(str(ctry))
        tags_val = it.get("tags") or it.get("tag")
        if tags_val:
            if isinstance(tags_val, list):
                tf_tags.extend([str(x) for x in tags_val if x])
            else:
                # 逗号分隔或字符串
                tf_tags.extend([s.strip() for s in str(tags_val).split(',') if s.strip()])
        ref = it.get("reference") or it.get("reference_link") or it.get("urlhaus_reference")
        if ref:
            refs.append(str(ref))
    # 去重
    threat_types = list(dict.fromkeys(threat_types))
    malware_aliases = list(dict.fromkeys(malware_aliases))
    confidences = list(dict.fromkeys(confidences))
    first_seen_list = list(dict.fromkeys(first_seen_list))
    last_seen_list = list(dict.fromkeys(last_seen_list))
    countries = list(dict.fromkeys(countries))
    summary = {}
    if threat_types:
        summary["Threat Type"] = threat_types
    if malware_aliases:
        summary["Malware alias"] = malware_aliases
    if confidences:
        summary["Confidence Level"] = confidences
    if first_seen_list:
        summary["First seen"] = first_seen_list[0]
    if last_seen_list:
        summary["Last seen"] = last_seen_list[0]
    if countries:
        summary["Country"] = countries
    if refs:
        summary["Reference"] = list(dict.fromkeys(refs))
        # 自动抽取 Triage 样本ID列表，供上层触发补查
        triage_ids: List[str] = []
        for rlink in summary["Reference"]:
            m = re.search(r"(\d{6,}-[A-Za-z0-9]+)", rlink)
            if m:
                triage_ids.append(m.group(1))
        if triage_ids:
            summary["TriageIDs"] = list(dict.fromkeys(triage_ids))
    if tf_tags:
        summary["Tags"] = list(dict.fromkeys(tf_tags))
    return {
        "source": "ThreatFox",
        "hit": bool(items),
        "items": items,
        "summary": summary,
        "ioc": {"ips": list(dict.fromkeys(tf_ips)), "domains": list(dict.fromkeys(tf_domains)), "urls": list(dict.fromkeys(tf_urls))},
    }


def threatfox_multi_lookup(indicator: str, api_key: str) -> Dict[str, Any]:
    """Try multiple ThreatFox strategies: search_ioc with and without ioc: prefix; fallback to get_iocs(days=7) and filter."""
    best = threatfox_lookup(indicator, api_key)
    if best.get("hit"):
        return best
    # fallback: get_iocs last 7 days and filter (per API, max 7)
    url = "https://threatfox-api.abuse.ch/api/v1/"
    s = requests.Session()
    s.headers.update({"accept": "application/json", "Auth-Key": api_key, "Content-Type": "application/json"})
    try:
        resp = s.post(url, data=json.dumps({"query": "get_iocs", "days": 7}), timeout=30)
        js = resp.json()
        data = js.get("data") or []
        if not data:
            return {"source": "ThreatFox", "hit": False}
        ips: List[str] = []
        domains: List[str] = []
        urls: List[str] = []
        key = indicator.lower()
        for it in data:
            ioc_val = (it.get("ioc") or "").lower()
            if not ioc_val:
                continue
            if key in ioc_val:
                t = (it.get("ioc_type") or "").lower()
                if t in {"ip", "ipv4", "ipv6"}:
                    ips.append(it.get("ioc"))
                elif t in {"domain", "fqdn"}:
                    domains.append(it.get("ioc"))
                elif t in {"url"}:
                    urls.append(it.get("ioc"))
        hit = bool(ips or domains or urls)
        return {"source": "ThreatFox", "hit": hit, "ioc": {"ips": list(dict.fromkeys(ips)), "domains": list(dict.fromkeys(domains)), "urls": list(dict.fromkeys(urls))}}
    except Exception:
        return {"source": "ThreatFox", "hit": False}


def alienvault_lookup(hash_value: str, api_key: str) -> Dict[str, Any]:
    # 首先检查内存缓存
    cached_data = get_cached_data_memory(hash_value, "alienvault")
    if cached_data:
        print(f"📦 使用 AlienVault 缓存数据")
        js = cached_data
    else:
        # 没有缓存，进行 API 查询
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}/general"
        headers = {"X-OTX-API-KEY": api_key}
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code != 200:
            return {"source": "AlienVault", "hit": False, "error": r.text}
        js = r.json()
        
        # 保存完整 JSON 数据
        save_json_data(hash_value, "alienvault", js)
    
    pulse_info = (js.get("pulse_info") or {})
    pulses = pulse_info.get("pulses") or []
    # 从 OTX 脉冲提取 IOC
    av_ips: List[str] = []
    av_domains: List[str] = []
    av_urls: List[str] = []
    for p in pulses:
        for ind in p.get("indicators", []) or []:
            val = ind.get("indicator") or ""
            t = (ind.get("type") or "").lower()
            if not val:
                continue
            if t in {"ipv4", "ipv6", "ip"}:
                av_ips.append(val)
            elif t in {"domain", "hostname"}:
                av_domains.append(val)
            elif t in {"url", "uri"}:
                av_urls.append(val)
    # 构建可用于统一摘要的最小补位信息（不改变 VT 模版，仅在缺失时可被合并逻辑拾取）
    def _unique(seq: List[str]) -> List[str]:
        return list(dict.fromkeys([s for s in seq if s]))
    tag_list: List[str] = []
    ref_list: List[str] = []
    first_seen: List[str] = []
    last_seen: List[str] = []
    for p in pulses:
        # tags
        if isinstance(p.get("tags"), list):
            tag_list.extend([str(x) for x in p.get("tags") if x])
        # references
        refs = p.get("references")
        if isinstance(refs, list):
            ref_list.extend([str(x) for x in refs if x])
        elif isinstance(refs, str):
            ref_list.append(refs)
        # times
        if p.get("created"):
            first_seen.append(str(p.get("created")))
        if p.get("modified"):
            last_seen.append(str(p.get("modified")))
    summary: Dict[str, Any] = {}
    if tag_list:
        summary["标签"] = _unique(tag_list)
    if first_seen:
        summary["首次发现"] = first_seen[0]
    if last_seen:
        summary["最后发现"] = last_seen[0]
    if ref_list:
        summary["参考"] = _unique(ref_list)
    hit = bool(pulses)

    # 若 general 无脉冲，尝试 analysis 端点补充（不改变 VT 模版，仅补位可用字段）
    analysis_raw: Dict[str, Any] = {}
    if not hit:
        try:
            r2 = requests.get(f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}/analysis", headers=headers, timeout=30)
            if r2.status_code == 200:
                analysis_raw = r2.json()
                # 采取保守提取：从原始文本中正则抓取 IOC，以避免结构差异导致漏抓
                try:
                    text_blob = json.dumps(analysis_raw, ensure_ascii=False)
                    # URLs
                    for u in re.findall(r"https?://[A-Za-z0-9_\-\.:%/#?=&]+", text_blob):
                        av_urls.append(u)
                    # IPv4
                    for ip in re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b", text_blob):
                        av_ips.append(ip)
                    # Domains（粗略提取，避免与 IP 冲突）
                    for dom in re.findall(r"\b(?:(?:[a-zA-Z0-9-]{1,63})\.)+[a-zA-Z]{2,}\b", text_blob):
                        if not re.match(r"^\d+(?:\.\d+){3}$", dom):
                            av_domains.append(dom)
                    if (not summary.get("标签")) and "plugins" in analysis_raw:
                        # 例如 yara/malware_classification 的标签名
                        tags_tmp: List[str] = []
                        try:
                            for k, v in (analysis_raw.get("plugins") or {}).items():
                                if isinstance(v, dict):
                                    n = v.get("name") or k
                                    if n:
                                        tags_tmp.append(str(n))
                        except Exception:
                            pass
                        if tags_tmp:
                            summary["标签"] = list(dict.fromkeys(tags_tmp))
                except Exception:
                    pass
                # 若抓取到任何 IOC，则视为命中
                if av_urls or av_domains or av_ips:
                    hit = True
        except Exception:
            pass

    return {
        "source": "AlienVault",
        "hit": hit,
        "summary": summary,
        "pulses": pulses[:5],
        "ioc": {"ips": list(dict.fromkeys(av_ips)), "domains": list(dict.fromkeys(av_domains)), "urls": list(dict.fromkeys(av_urls))},
        "raw": {"general": js, "analysis": analysis_raw} if analysis_raw else js,
    }


def inquest_lookup(hash_value: str, api_key: str) -> Dict[str, Any]:
    # 首先检查内存缓存
    cached_data = get_cached_data_memory(hash_value, "inquest")
    if cached_data:
        print(f"📦 使用 InQuest 缓存数据")
        js = cached_data
    else:
        # 没有缓存，进行 API 查询
        base = "https://labs.inquest.net/api/iad/"
        endpoint = "sample/info/sha256/" if is_sha256(hash_value) else ("sample/info/md5/" if is_md5(hash_value) else None)
        if not endpoint:
            return {"source": "InQuest", "hit": False}
        url = base + endpoint + hash_value
        headers = {"Authorization": f"Bearer {api_key}"}
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code != 200:
            return {"source": "InQuest", "hit": False, "error": r.text}
        js = r.json()
        
        # 保存完整 JSON 数据
        save_json_data(hash_value, "inquest", js)
    
    return {
        "source": "InQuest",
        "hit": True,
        "raw": js,
    }


def inquest_ioc_lookup(target: str) -> Dict[str, Any]:
    """InQuest Labs IOC 查询（域名/IP），用于补充网络情报。
    文档: https://labs.inquest.net/docs/ （公共 Labs 通常无需 API Key）
    """
    base = "https://labs.inquest.net/api/ioc"
    try:
        r = requests.get(base, params={"q": target}, timeout=30)
        if r.status_code != 200:
            return {"source": "InQuest", "hit": False, "error": r.text}
        js = r.json()
    except Exception as e:
        return {"source": "InQuest", "hit": False, "error": str(e)}

    # 兼容返回：有的接口返回对象，有的返回列表
    items = []
    if isinstance(js, list):
        items = js
    elif isinstance(js, dict):
        # 常见字段：data/list/results
        for key in ("data", "list", "results", "ioc"):
            if isinstance(js.get(key), list):
                items = js.get(key)
                break
        if not items:
            items = [js]

    # 解析关键信息
    urls: List[str] = []
    ips: List[str] = []
    domains: List[str] = []
    threat_types: List[str] = []
    countries: List[str] = []
    first_seen: List[str] = []
    last_seen: List[str] = []

    for it in items:
        if not isinstance(it, dict):
            continue
        val = str(it.get("ioc") or it.get("value") or it.get("data") or "").strip()
        ioc_type = (it.get("type") or it.get("category") or "").lower()
        if val:
            if ioc_type in {"ip", "ipv4", "ipv6"} or (":" not in val and val.replace(".", "").isdigit()):
                ips.append(val)
            elif ioc_type in {"domain", "hostname", "fqdn"} or ("/" not in val and "." in val):
                domains.append(val)
            elif ioc_type in {"url", "uri"} or val.startswith(("http://", "https://")):
                urls.append(val)
        tt = it.get("threat_type") or it.get("classification") or it.get("label")
        if tt:
            threat_types.append(str(tt))
        c = it.get("country") or it.get("cc")
        if c:
            countries.append(str(c))
        fs = it.get("first_seen") or it.get("created") or it.get("date_first_seen")
        if fs:
            first_seen.append(str(fs))
        ls = it.get("last_seen") or it.get("updated") or it.get("date_last_seen")
        if ls:
            last_seen.append(str(ls))

    # 去重
    urls = list(dict.fromkeys(urls))
    ips = list(dict.fromkeys(ips))
    domains = list(dict.fromkeys(domains))
    threat_types = list(dict.fromkeys(threat_types))
    countries = list(dict.fromkeys(countries))

    hit = bool(urls or ips or domains or threat_types or countries or first_seen or last_seen)
    summary: Dict[str, Any] = {}
    if threat_types:
        summary["Threat Type"] = threat_types
    if countries:
        summary["Country"] = countries
    if first_seen:
        summary["First seen"] = first_seen[0]
    if last_seen:
        summary["Last seen"] = last_seen[0]

    return {
        "source": "InQuest",
        "hit": hit,
        "summary": summary,
        "ioc": {"ips": ips, "domains": domains, "urls": urls},
        "raw": items,
    }


def hybrid_lookup(hash_value: str, api_key: str) -> Dict[str, Any]:
    base = "https://www.hybrid-analysis.com/api/v2"
    headers = {
        "user-agent": "Falcon Sandbox",
        "api-key": api_key,
        "X-Api-Key": api_key,
        "accept": "application/json",
    }
    
    # 首先搜索哈希是否存在；若无结果，后续走直接 report/overview 回退
    env_id = None
    verdict = ""
    reported_envs: List[int] = []
    try:
        search_url = f"{base}/search/hash?hash={hash_value}"
        search_r = requests.get(search_url, headers=headers, timeout=30)
        if search_r.status_code == 200:
            search_data = search_r.json()
            reports = search_data.get("reports", [])
            if reports:
                # 收集所有返回的 environment_id，并优先 100
                for report in reports:
                    env = report.get("environment_id")
                    if isinstance(env, int):
                        reported_envs.append(env)
                    if env == 100 and not env_id:
                        env_id = 100
                        verdict = report.get("verdict", "")
                if not env_id:
                    first_report = reports[0]
                    env_id = first_report.get("environment_id", 100)
                    verdict = first_report.get("verdict", "")
    except Exception:
        # 忽略搜索异常，继续回退
        pass
    
    # 使用找到的环境ID获取详细报告；若无 env_id，直接尝试多环境与 overview 回退
    r = None
    try_envs = [env_id] if env_id else []
    # 先加入 search 返回的所有环境（保持唯一并保序）
    for env in reported_envs:
        if env and env not in try_envs:
            try_envs.append(env)
    # 再加入常见环境优先级（包含 160）
    for default_env in [100, 110, 120, 160, 200, 300]:
        if default_env not in try_envs:
            try_envs.append(default_env)

    # 先试 report/{hash}:{env}/summary
    for env in try_envs:
        try:
            rr = requests.get(f"{base}/report/{hash_value}:{env}/summary", headers=headers, timeout=30)
            if rr.status_code == 200:
                r = rr
                env_id = env
                break
        except Exception:
            continue

    # 若仍未获取，尝试 overview/{hash}/summary（有些样本仅该端点可用）
    if r is None:
        try:
            orr = requests.get(f"{base}/overview/{hash_value}/summary", headers=headers, timeout=30)
            if orr.status_code == 200:
                r = orr
        except Exception:
            pass

    # 若仍未获取，使用 terms 搜索回退补充环境并重试
    if r is None:
        try:
            terms_r = requests.get(f"{base}/search/terms?query={hash_value}", headers=headers, timeout=30)
            if terms_r.status_code == 200:
                terms_data = terms_r.json() if callable(getattr(terms_r, 'json', None)) else {}
                # 兼容返回结构：有的返回 reports，有的直接返回列表
                t_reports = []
                if isinstance(terms_data, dict):
                    t_reports = terms_data.get('reports') or terms_data.get('data') or []
                elif isinstance(terms_data, list):
                    t_reports = terms_data
                extra_envs: List[int] = []
                for rep in t_reports:
                    if isinstance(rep, dict):
                        env = rep.get('environment_id')
                        if isinstance(env, int):
                            extra_envs.append(env)
                # 合并补充环境并重试 summary
                for env in extra_envs:
                    if env not in try_envs:
                        try_envs.append(env)
                for env in try_envs:
                    try:
                        rr2 = requests.get(f"{base}/report/{hash_value}:{env}/summary", headers=headers, timeout=30)
                        if rr2.status_code == 200:
                            r = rr2
                            env_id = env
                            break
                    except Exception:
                        continue
        except Exception:
            pass

    if r is None or r.status_code != 200:
        last_text = getattr(r, 'text', '') if r is not None else 'all attempts failed'
        return {"source": "HybridAnalysis", "hit": False, "error": last_text}
    try:
        js = r.json()
        # 保存完整 JSON 数据
        save_json_data(hash_value, "hybrid", js)
    except Exception:
        return {"source": "HybridAnalysis", "hit": False, "error": r.text}
    # 提取 IOC（summary）
    domains = js.get("domains") or []
    hosts = js.get("hosts") or []
    compromised = js.get("compromised_hosts") or []
    # 进程与 DNS/URL 等（summary 能提供的有限）
    procs = js.get("processes") or []
    urls = js.get("urls") or []
    dns = js.get("dns_requests") or []
    
    # 从 Memory Forensics 和 Interesting Strings 中提取 IOC
    memory_iocs = js.get("mitre_attcks", []) or []
    for mitre in memory_iocs:
        if isinstance(mitre, dict):
            description = mitre.get("description", "")
            if description:
                # 从描述中提取 IOC
                mem_ips, mem_domains, mem_urls = extract_iocs_from_strings(description)
                hosts.extend(mem_ips)
                domains.extend(mem_domains)
                urls.extend(mem_urls)
    
    # 从 signatures 数组中提取 IOC
    signatures = js.get("signatures", []) or []
    for sig in signatures:
        if isinstance(sig, dict):
            description = sig.get("description", "")
            if description:
                # 从描述中提取 IOC
                mem_ips, mem_domains, mem_urls = extract_iocs_from_strings(description)
                hosts.extend(mem_ips)
                domains.extend(mem_domains)
                urls.extend(mem_urls)

    # 详细端点尝试（网络、DNS、进程树等），失败则忽略
    detailed: Dict[str, Any] = {}
    # 详细端点优先使用已经确认的 env_id，否则尝试 100
    _env_for_detail = env_id or 100
    for endpoint in ("network", "dns", "processes"):
        try:
            rr = requests.get(f"{base}/report/{hash_value}:{_env_for_detail}/{endpoint}", headers=headers, timeout=30)
            if rr.status_code == 200:
                detailed[endpoint] = rr.json()
        except Exception:
            pass
    # 合并详细端点的可识别项
    try:
        net = detailed.get("network") or {}
        urls += net.get("urls", []) or []
        hosts += net.get("hosts", []) or []
        domains += net.get("domains", []) or []
    except Exception:
        pass
    try:
        dns_raw = detailed.get("dns") or []
        for d in dns_raw:
            if isinstance(d, dict) and d.get("query"):
                dns.append(d.get("query"))
    except Exception:
        pass
    try:
        procs_raw = detailed.get("processes") or []
        for p in procs_raw:
            if isinstance(p, dict) and p.get("name"):
                procs.append(p.get("name"))
    except Exception:
        pass
    # 提取核心威胁情报数据
    summary_data = {}
    threat_tags = []
    
    try:
        # 基本信息
        summary_data["文件名"] = js.get("submit_name", "")
        summary_data["文件大小"] = f"{js.get('size', 0)} bytes"
        summary_data["文件类型"] = js.get("type", "")
        summary_data["环境"] = js.get("environment_description", "")
        summary_data["状态"] = js.get("state", "")
        summary_data["威胁等级"] = js.get("threat_level", "")
        summary_data["威胁分数"] = js.get("threat_score", "")
        summary_data["AV检测"] = js.get("av_detect", 0)
        summary_data["恶意软件家族"] = js.get("vx_family", "")
        summary_data["分析时间"] = js.get("analysis_start_time", "")
        
        # 哈希值信息
        summary_data["MD5"] = js.get("md5", "")
        summary_data["SHA1"] = js.get("sha1", "")
        summary_data["SHA256"] = js.get("sha256", "")
        summary_data["SHA512"] = js.get("sha512", "")
        summary_data["SSDeep"] = js.get("ssdeep", "")
        summary_data["ImpHash"] = js.get("imphash", "")
        
        # PE 信息
        summary_data["入口点"] = js.get("entrypoint", "")
        summary_data["入口点段"] = js.get("entrypoint_section", "")
        summary_data["镜像基址"] = js.get("image_base", "")
        summary_data["子系统"] = js.get("subsystem", "")
        summary_data["主版本"] = js.get("major_os_version", "")
        summary_data["次版本"] = js.get("minor_os_version", "")
        
        # 威胁标签提取
        if verdict:
            threat_tags.append(f"verdict: {verdict}")
        
        # 从 classification_tags 提取
        classification_tags = js.get("classification_tags", [])
        if classification_tags:
            threat_tags.extend([str(tag) for tag in classification_tags if tag])
        
        # 从 tags 提取
        tags = js.get("tags", [])
        if tags:
            threat_tags.extend([str(tag) for tag in tags if tag])
        
        # 从 crowdstrike_ai 提取
        crowdstrike_ai = js.get("crowdstrike_ai", {})
        if crowdstrike_ai:
            for key, value in crowdstrike_ai.items():
                if value and isinstance(value, list) and value:
                    verdicts = []
                    for item in value:
                        if isinstance(item, dict) and item.get("verdict"):
                            verdicts.append(item["verdict"])
                    if verdicts:
                        unique_verdicts = list(dict.fromkeys(verdicts))
                        threat_tags.append(f"{key}: {', '.join(unique_verdicts)}")
                elif value and not isinstance(value, list):
                    threat_tags.append(f"{key}: {value}")
        
        # 从 machine_learning_models 提取
        ml_models = js.get("machine_learning_models", {})
        if ml_models:
            for model, result in ml_models.items():
                if result:
                    threat_tags.append(f"ML-{model}: {result}")
        
        # 从 signatures 提取威胁标签
        signatures = js.get("signatures", [])
        if signatures:
            for sig in signatures:
                if isinstance(sig, dict):
                    sig_name = sig.get("name", "")
                    sig_desc = sig.get("description", "")
                    if sig_name:
                        threat_tags.append(f"signature: {sig_name}")
                    if sig_desc and sig_desc != sig_name:
                        threat_tags.append(f"desc: {sig_desc}")
        
        # 从 mitre_attcks 提取
        mitre_attacks = js.get("mitre_attcks", [])
        if mitre_attacks:
            for attack in mitre_attacks:
                if isinstance(attack, dict):
                    attack_name = attack.get("name", "")
                    attack_desc = attack.get("description", "")
                    if attack_name:
                        threat_tags.append(f"MITRE: {attack_name}")
                    if attack_desc and attack_desc != attack_name:
                        threat_tags.append(f"technique: {attack_desc}")
        
        # 统计信息
        summary_data["网络连接数"] = js.get("total_network_connections", 0)
        summary_data["进程数"] = js.get("total_processes", 0)
        summary_data["签名数"] = js.get("total_signatures", 0)
        summary_data["提取文件数"] = len(js.get("extracted_files", []))
        
    except Exception as e:
        print(f"⚠️ Hybrid Analysis 数据提取错误: {e}")

    # 去重整理
    hosts = list(dict.fromkeys(hosts)) if isinstance(hosts, list) else []
    compromised = list(dict.fromkeys(compromised)) if isinstance(compromised, list) else []
    domains = list(dict.fromkeys(domains)) if isinstance(domains, list) else []
    urls = list(dict.fromkeys(urls)) if isinstance(urls, list) else []
    dns = list(dict.fromkeys(dns)) if isinstance(dns, list) else []
    # 确保 procs 只包含字符串，然后去重
    procs = [str(p) for p in procs if p] if isinstance(procs, list) else []
    procs = list(dict.fromkeys(procs))
    # 提取行为数据
    behavior_data = {
        "processes_created": [],
        "processes_terminated": [],
        "files_created": [],
        "files_modified": [],
        "files_deleted": [],
        "registry_keys": [],
        "network_connections": [],
        "dns_requests": [],
        "signatures": [],
        "mitre_attacks": []
    }
    
    try:
        # 从 processes 提取进程信息
        processes = js.get("processes", [])
        if processes:
            for proc in processes:
                if isinstance(proc, dict):
                    proc_name = proc.get("name", "")
                    if proc_name:
                        behavior_data["processes_created"].append(proc_name)
        
        # 从 extracted_files 提取文件信息
        extracted_files = js.get("extracted_files", [])
        if extracted_files:
            for file_info in extracted_files:
                if isinstance(file_info, dict):
                    file_name = file_info.get("name", "")
                    if file_name:
                        behavior_data["files_created"].append(file_name)
        
        # 从 signatures 提取签名信息
        signatures = js.get("signatures", [])
        if signatures:
            for sig in signatures:
                if isinstance(sig, dict):
                    sig_name = sig.get("name", "")
                    if sig_name:
                        behavior_data["signatures"].append(sig_name)
        
        # 从 mitre_attcks 提取攻击技术
        mitre_attacks = js.get("mitre_attcks", [])
        if mitre_attacks:
            for attack in mitre_attacks:
                if isinstance(attack, dict):
                    attack_name = attack.get("name", "")
                    if attack_name:
                        behavior_data["mitre_attacks"].append(attack_name)
        
        # 从详细端点提取更多行为数据
        if detailed.get("network"):
            network_data = detailed["network"]
            if isinstance(network_data, dict):
                # 提取网络连接
                network_connections = network_data.get("connections", [])
                if network_connections:
                    for conn in network_connections:
                        if isinstance(conn, dict):
                            conn_info = f"{conn.get('protocol', '')} {conn.get('host', '')}:{conn.get('port', '')}"
                            if conn_info.strip():
                                behavior_data["network_connections"].append(conn_info)
        
        if detailed.get("dns"):
            dns_data = detailed["dns"]
            if isinstance(dns_data, list):
                for dns_entry in dns_data:
                    if isinstance(dns_entry, dict):
                        dns_query = dns_entry.get("query", "")
                        if dns_query:
                            behavior_data["dns_requests"].append(dns_query)
        
        if detailed.get("processes"):
            processes_data = detailed["processes"]
            if isinstance(processes_data, list):
                for proc in processes_data:
                    if isinstance(proc, dict):
                        proc_name = proc.get("name", "")
                        if proc_name:
                            behavior_data["processes_created"].append(proc_name)
    
    except Exception as e:
        print(f"⚠️ Hybrid Analysis 行为数据提取错误: {e}")
    
    # 去重行为数据
    for key in behavior_data:
        behavior_data[key] = list(dict.fromkeys(behavior_data[key]))
    
    # 即使有错误状态，如果有基本信息也应该显示
    has_basic_info = bool(summary_data.get("文件名") or summary_data.get("恶意软件家族") or summary_data.get("AV检测") or threat_tags)
    
    return {
        "source": "HybridAnalysis",
        "hit": bool(domains or hosts or compromised or urls or dns or procs or threat_tags or has_basic_info),
        "summary": summary_data,
        "threat_tags": threat_tags,
        "ioc": {
            "ips": (hosts + [h for h in compromised if h not in hosts])[:100],
            "domains": domains[:100],
            "urls": urls[:100],
        },
        "dns": dns[:100],
        "processes": procs[:100],
        "behavior": behavior_data,
        "detailed_test": {k: (v if isinstance(v, list) else v) for k, v in detailed.items()},
        "raw": js,
    }


def triage_lookup(hash_value: str, api_key: str) -> Dict[str, Any]:
    base = "https://api.tria.ge/v0"
    headers = {"accept": "application/json", "Authorization": f"Bearer {api_key}"}
    sid = None
    # 如果传入的就是 Triage Sample ID，直接使用
    if re.fullmatch(r"\d{6,}-[A-Za-z0-9]+", hash_value):
        sid = hash_value
    else:
        # 先搜索样本 ID（使用 params 避免编码问题）
        try:
            rs = requests.get(f"{base}/search", params={"query": f"sha256:{hash_value}"}, headers=headers, timeout=30)
            js = rs.json() if rs.status_code == 200 else {"error": rs.text}
            try:
                save_json_data(hash_value, "triage_search", js)
            except Exception:
                pass
        except Exception as exc:
            return {"source": "Triage", "hit": False, "error": str(exc)}
        data = js.get("data") or []
        if not data:
            return {"source": "Triage", "hit": False}
        # 默认选择第一个，也可根据需要更换为随机选择
        sid = data[0].get("id")
    if not sid:
        return {"source": "Triage", "hit": False}
    # 拉取概要/报告（尽量轻量）
    try:
        rs2 = requests.get(f"{base}/samples/{sid}/summary", headers=headers, timeout=30)
        sumj = rs2.json() if rs2.status_code == 200 else {}
        try:
            save_json_data(hash_value, "triage_summary", sumj)
        except Exception:
            pass
    except Exception:
        sumj = {}
    # 详细端点：network、behavior
    detailed: Dict[str, Any] = {}
    for endpoint in ("network", "behavior"):
        try:
            rr = requests.get(f"{base}/samples/{sid}/{endpoint}", headers=headers, timeout=30)
            if rr.status_code == 200:
                detailed[endpoint] = rr.json()
        except Exception:
            pass
    # 从 summary/analysis 提取 IOC
    urls: List[str] = []
    ips: List[str] = []
    domains: List[str] = []
    procs: List[str] = []
    dns: List[str] = []
    # 兼容不同字段命名
    for key in ("urls", "network_urls"):
        if isinstance(sumj.get(key), list):
            urls.extend(sumj.get(key) or [])
    for key in ("ips", "network_ips"):
        if isinstance(sumj.get(key), list):
            ips.extend(sumj.get(key) or [])
    if isinstance(sumj.get("dns"), list):
        for d in sumj.get("dns") or []:
            if isinstance(d, dict) and d.get("query"):
                dns.append(d.get("query"))
    if isinstance(sumj.get("processes"), list):
        for p in sumj.get("processes") or []:
            if isinstance(p, dict) and p.get("name"):
                procs.append(p.get("name"))
    # 从详细端点补充
    try:
        net = detailed.get("network") or {}
        urls.extend(net.get("urls", []) or [])
        ips.extend(net.get("ips", []) or [])
        if isinstance(net.get("dns"), list):
            for d in net.get("dns") or []:
                if isinstance(d, dict) and d.get("query"):
                    dns.append(d.get("query"))
    except Exception:
        pass
    try:
        beh = detailed.get("behavior") or {}
        for p in beh.get("processes", []) or []:
            if isinstance(p, dict) and p.get("name"):
                procs.append(p.get("name"))
    except Exception:
        pass
    # 域名从 DNS 中补充
    domains.extend(dns)
    # 即使行为分析失败，只要找到了样本就算命中
    hit = bool(sid and sumj)
    
    return {
        "source": "Triage",
        "hit": hit,
        "summary": {
            "sample_id": sid,
            "filename": sumj.get("target", ""),
            "score": sumj.get("score", 0),
            "status": sumj.get("status", ""),
            "completed": sumj.get("completed", ""),
            "tasks": sumj.get("tasks", {})
        },
        "ioc": {"ips": list(dict.fromkeys(ips)), "domains": list(dict.fromkeys(domains)), "urls": list(dict.fromkeys(urls))},
        "dns": list(dict.fromkeys(dns))[:50],
        "processes": list(dict.fromkeys(procs))[:50],
        "detailed_test": {k: (v if isinstance(v, list) else v) for k, v in detailed.items()},
        "raw": sumj,
    }


def malshare_lookup(hash_value: str, api_key: str) -> Dict[str, Any]:
    """Malshare查询函数 - 主要用于检查样本是否存在，支持下载"""
    if not api_key:
        return {"source": "Malshare", "hit": False, "error": "No API key"}
    
    # 首先检查内存缓存
    cached_data = get_cached_data_memory(hash_value, "malshare")
    if cached_data:
        print(f"📦 使用 Malshare 缓存数据")
        js = cached_data
    else:
        # 没有缓存，进行 API 查询
        # 使用getfile action检查特定hash是否存在，而不是getlist（避免缓存大量无用数据）
        base_url = "https://malshare.com/api.php"
        params = {
            "api_key": api_key,
            "action": "getfile",
            "hash": hash_value
        }
        
        try:
            r = requests.get(base_url, params=params, timeout=30)
            if r.status_code != 200:
                return {"source": "Malshare", "hit": False, "error": f"HTTP {r.status_code}"}
            
            # 检查响应内容
            if b'Sample not found by hash' in r.content:
                # 样本不存在，返回未命中
                result = {"source": "Malshare", "hit": False, "raw": {"message": "Sample not found"}}
                save_json_data(hash_value, "malshare", result["raw"])
                return result
            else:
                # 样本存在，返回命中信息
                result = {
                    "source": "Malshare", 
                    "hit": True, 
                    "summary": {
                        "可下载": True,
                        "文件大小": f"{len(r.content)} bytes"
                    },
                    "raw": {"message": "Sample found", "downloadable": True},
                    "downloadable": True
                }
                save_json_data(hash_value, "malshare", result["raw"])
                return result
                
        except Exception as e:
            return {"source": "Malshare", "hit": False, "error": str(e)}
    
    # 处理缓存数据
    if isinstance(js, dict):
        if js.get("message") == "Sample found":
            return {
                "source": "Malshare",
                "hit": True,
                "summary": {"可下载": True},
                "raw": js,
                "downloadable": True
            }
        elif js.get("message") == "Sample not found":
            return {"source": "Malshare", "hit": False, "raw": js}
    
    return {"source": "Malshare", "hit": False, "raw": js}


def abuseipdb_check(ips: List[str], api_key: str) -> List[Dict[str, Any]]:
    results = []
    headers = {"Key": api_key, "Accept": "application/json"}
    for ip in ips:
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 365}, headers=headers, timeout=20)
            if r.status_code == 200:
                results.append(r.json().get("data", {}))
        except Exception:
            continue
    return results


def resolve_domains_to_ips(domains: List[str]) -> List[str]:
    ips: List[str] = []
    for d in domains:
        try:
            ip = socket.gethostbyname(d)
            ips.append(ip)
        except Exception:
            pass
    return list(dict.fromkeys(ips))


def _merge_iocs(parts: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """汇总所有引擎的 IOC 数据，在汇总层进行过滤和去重"""
    ips: List[str] = []
    domains: List[str] = []
    urls: List[str] = []
    hashes: List[str] = []
    # 环境变量开关：
    #  - THUNTPRO_SHOW_ALL_URLS=1 时，关闭大厂域名过滤，尽可能保留 URL
    #  - THUNTPRO_KEEP_DOMAINS=1 时，结果中保留 domains 字段（默认隐藏）
    show_all_urls: bool = bool(os.environ.get("THUNTPRO_SHOW_ALL_URLS"))
    keep_domains: bool = bool(os.environ.get("THUNTPRO_KEEP_DOMAINS"))
    
    for r in parts:
        ioc = r.get("ioc") or {}
        # 收集所有原始 IOC 数据，不做过滤
        ips.extend(ioc.get("ips") or [])
        domains.extend(ioc.get("domains") or [])
        urls.extend(ioc.get("urls") or [])
        hashes.extend(ioc.get("hashes") or [])
    
    # 定义需要过滤的大厂域名（使用正则表达式模式）
    big_tech_patterns = [
        # Microsoft
        r'.*\.microsoft\.com$', r'.*\.windowsupdate\.com$', r'.*\.update\.microsoft\.com$',
        r'.*\.download\.windowsupdate\.com$', r'.*\.officecdn\.microsoft\.com$', r'.*\.msedge\.net$',
        r'.*\.live\.com$', r'.*\.outlook\.com$', r'.*\.outlook\.office365\.com$', r'.*\.onedrive\.com$',
        r'.*\.onedrive\.live\.com$', r'.*\.xboxlive\.com$', r'.*\.azure\.com$', r'.*\.azureedge\.net$',
        r'.*\.blob\.core\.windows\.net$', r'.*\.office\.com$', r'.*\.skype\.com$', r'.*\.skypeassets\.com$',
        r'.*\.teams\.microsoft\.com$',
        
        # Google / Alphabet
        r'.*\.google\.com$', r'.*\.gstatic\.com$', r'.*\.googleapis\.com$', r'.*\.googleusercontent\.com$',
        r'.*\.googlesyndication\.com$', r'.*\.gvt1\.com$', r'.*\.gvt2\.com$', r'.*\.android\.com$',
        r'.*\.firebaseio\.com$', r'.*\.doubleclick\.net$', r'.*\.youtube\.com$', r'.*\.ytimg\.com$',
        r'.*\.withgoogle\.com$', r'.*\.1e100\.net$', r'.*\.cloud\.google\.com$', r'.*\.gcp\.gvt2\.com$',
        
        # Apple
        r'.*\.apple\.com$', r'.*\.itunes\.com$', r'.*\.icloud\.com$', r'.*\.me\.com$',
        r'.*\.apple-cloudkit\.com$', r'.*\.mzstatic\.com$', r'.*\.akadns\.net$', r'.*\.edgesuite\.net$',
        
        # Amazon / AWS
        r'.*\.amazon\.com$', r'.*\.amazon\.co\.jp$', r'.*\.amazonaws\.com$', r'.*\.cloudfront\.net$',
        r'.*\.awstrack\.me$', r'.*\.awsdns-.*\.org$', r'.*\.awsdns-.*\.net$', r'.*\.awsdns-.*\.co\.uk$',
        r'.*\.a2z\.com$', r'.*\.primevideo\.com$', r'.*\.media-amazon\.com$', r'.*\.firebasestorage\.googleapis\.com$',
        
        # Meta (Facebook / Instagram / WhatsApp)
        r'.*\.facebook\.com$', r'.*\.fbcdn\.net$', r'.*\.fb\.com$', r'.*\.whatsapp\.com$', r'.*\.whatsapp\.net$',
        r'.*\.instagram\.com$', r'.*\.cdninstagram\.com$', r'.*\.messenger\.com$', r'.*\.fbsbx\.com$',
        
        # CDN 服务商
        r'.*\.akamai\.net$', r'.*\.akamaiedge\.net$', r'.*\.akamaitechnologies\.com$', r'.*\.edgekey\.net$',
        r'.*\.cloudflare\.com$', r'.*\.cloudflare-dns\.com$', r'.*\.cloudflareinsights\.com$', r'.*\.cf-ipfs\.com$',
        r'.*\.crl\.cloudflare\.com$', r'.*\.fastly\.net$', r'.*\.fastlylb\.net$', r'.*\.global\.ssl\.fastly\.net$',
        r'.*\.fastlyjs\.com$', r'.*\.llnwd\.net$', r'.*\.limelight\.com$',
        
        # 其他大厂
        r'.*\.oracle\.com$', r'.*\.java\.com$', r'.*\.sun\.com$', r'.*\.update\.oracle\.com$',
        r'.*\.adobe\.com$', r'.*\.adobe\.io$', r'.*\.adobelogin\.com$', r'.*\.adobesc\.com$', r'.*\.adobecc\.com$',
        r'.*\.ibm\.com$', r'.*\.redhat\.com$', r'.*\.rhsm\.redhat\.com$', r'.*\.fedoraproject\.org$', r'.*\.centos\.org$',
        r'.*\.cisco\.com$', r'.*\.webex\.com$', r'.*\.ciscodigital\.com$', r'.*\.duo\.com$',
        r'.*\.salesforce\.com$', r'.*\.force\.com$', r'.*\.salesforceliveagent\.com$', r'.*\.visual\.force\.com$',
        r'.*\.cdn77\.com$', r'.*\.cdn77\.org$', r'.*\.quic\.cloud$', r'.*\.litespeedtech\.com$',
        r'.*\.atlassian\.com$', r'.*\.jira\.com$', r'.*\.bitbucket\.org$', r'.*\.trello\.com$', r'.*\.statuspage\.io$',
        r'.*\.github\.com$', r'.*\.githubusercontent\.com$', r'.*\.githubassets\.com$', r'.*\.gitlab\.com$', r'.*\.gitlab\.io$',
        r'.*\.mozilla\.org$', r'.*\.firefox\.com$', r'.*\.ffxblue\.com$', r'.*\.addons\.mozilla\.org$', r'.*\.crash-stats\.mozilla\.com$',
        r'.*\.netflix\.com$', r'.*\.nflximg\.net$', r'.*\.nflxvideo\.net$', r'.*\.netflixdnstest\.com$',
        r'.*\.zoom\.us$', r'.*\.zoom\.com$', r'.*\.zoomgov\.com$', r'.*\.slack\.com$', r'.*\.slack-edge\.com$',
        
        # 软件仓库
        r'.*\.npmjs\.com$', r'.*\.npmjs\.org$', r'.*\.pypi\.org$', r'.*\.rubygems\.org$', r'.*\.maven\.org$', r'.*\.repo1\.maven\.org$',
        
        # 中国大厂
        r'.*\.qq\.com$', r'.*\.weixin\.qq\.com$', r'.*\.wx\.qlogo\.cn$', r'.*\.wechat\.com$', r'.*\.qcloud\.com$',
        r'.*\.tencent\.com$', r'.*\.tencentcloud\.com$', r'.*\.gtimg\.com$', r'.*\.myqcloud\.com$', r'.*\.igamecj\.com$',
        r'.*\.alibaba\.com$', r'.*\.alicdn\.com$', r'.*\.aliyun\.com$', r'.*\.aliyuncs\.com$', r'.*\.taobao\.com$',
        r'.*\.tmall\.com$', r'.*\.tbcdn\.com$', r'.*\.mmstat\.com$', r'.*\.alipay\.com$', r'.*\.antfin\.com$',
        r'.*\.log\.aliyuncs\.com$', r'.*\.baidu\.com$', r'.*\.bdstatic\.com$', r'.*\.baidubcr\.com$', r'.*\.baidupcs\.com$',
        r'.*\.baidustatic\.com$', r'.*\.ers\.baidu\.com$', r'.*\.hm\.baidu\.com$', r'.*\.dueros\.baidu\.com$', r'.*\.a\.shifen\.com$',
        r'.*\.bytedance\.com$', r'.*\.toutiao\.com$', r'.*\.douyin\.com$', r'.*\.douyincdn\.com$', r'.*\.pstatp\.com$',
        r'.*\.snssdk\.com$', r'.*\.volcanoengine\.com$', r'.*\.huawei\.com$', r'.*\.huawei\.com\.cn$', r'.*\.huaweicloud\.com$',
        r'.*\.hwcdn\.net$', r'.*\.hicloud\.com$', r'.*\.update\.hicloud\.com$', r'.*\.mi\.com$', r'.*\.xiaomi\.com$',
        r'.*\.mi-img\.com$', r'.*\.miui\.com$', r'.*\.miuihuodong\.com$', r'.*\.xiaomicdn\.com$', r'.*\.163\.com$',
        r'.*\.126\.com$', r'.*\.127\.net$', r'.*\.163yun\.com$', r'.*\.music\.163\.com$', r'.*\.youdao\.com$',
        r'.*\.jd\.com$', r'.*\.jdcloud\.com$', r'.*\.jdpay\.com$', r'.*\.jdwl\.com$', r'.*\.360\.cn$',
        r'.*\.qihoo\.com$', r'.*\.so\.com$', r'.*\.360safe\.com$', r'.*\.360totalsecurity\.com$',
        r'.*\.bilibili\.com$', r'.*\.bilicdn1\.com$', r'.*\.hdslb\.com$', r'.*\.im9\.com$', r'.*\.sina\.com\.cn$',
        r'.*\.weibo\.com$', r'.*\.sinacdn\.com$', r'.*\.sinaimg\.cn$', r'.*\.iqiyi\.com$', r'.*\.71\.am\.com$',
        r'.*\.youku\.com$', r'.*\.aliyunccdn\.com$', r'.*\.hunantv\.com$', r'.*\.mgtv\.com$',
        
        # 特定域名
        r'^apache\.org$', r'^www\.apache\.org$', r'.*\.apache\.org$',
        r'^us-cert\.gov$', r'^www\.us-cert\.gov$', r'.*\.us-cert\.gov$',
        r'^exploit-db\.com$', r'^www\.exploit-db\.com$', r'.*\.exploit-db\.com$',
        r'^all\.bstring$',
        
        # 安全厂商
        r'.*\.symantec\.com$', r'.*\.symantecliveupdate\.com$', r'.*\.mcafee\.com$', r'.*\.mcafeeasap\.com$',
        r'.*\.kaspersky\.com$', r'.*\.kaspersky-labs\.com$', r'.*\.avast\.com$', r'.*\.trendmicro\.com$',
        r'.*\.sophos\.com$', r'.*\.eset\.com$', r'.*\.bitdefender\.com$', r'.*\.windowsdefender\.com$',
        
        # 运营商和 CDN
        r'.*\.chinanetcenter\.com$', r'.*\.chinacache\.net$', r'.*\.21vok00\.com$', r'.*\.chinaunicom\.com$',
        r'.*\.chinamobile\.com$', r'.*\.chinatelecom\.com\.cn$', r'.*\.cmvideo\.cn$', r'.*\.qiniu\.com$',
        r'.*\.qbox\.me$', r'.*\.upaiyun\.com$', r'.*\.ucloud\.cn$', r'.*\.ks-cdn\.com$', r'.*\.kingsoftcloud\.com$',
        
        # 开发者社区
        r'.*\.gitee\.com$', r'.*\.oschina\.net$', r'.*\.csdn\.net$', r'.*\.juejin\.cn$'
    ]
    
    # 将域名转换为 URL 格式，并过滤大厂域名
    all_urls = []
    
    # 处理原始 URLs
    for url in urls:
        # 过滤掉纯哈希值（32-64位十六进制字符串）
        if not re.match(r"^[a-fA-F0-9]{32,64}$", url):
            # 提取 URL 中的域名进行大厂域名过滤
            if '://' in url:
                domain = url.split('://')[1].split('/')[0]
            else:
                domain = url.split('/')[0]
            
            domain_lower = domain.lower()
            is_big_tech = False
            
            if not show_all_urls:
                for pattern in big_tech_patterns:
                    if re.match(pattern, domain_lower):
                        is_big_tech = True
                        break
            
            if not is_big_tech:
                all_urls.append(url)
    
    # 处理域名，转换为 URL 格式
    for domain in domains:
        # 过滤大厂域名（使用正则表达式）
        domain_lower = domain.lower()
        is_big_tech = False
        
        if not show_all_urls:
            for pattern in big_tech_patterns:
                if re.match(pattern, domain_lower):
                    is_big_tech = True
                    break
        
        if not is_big_tech:
            # 过滤文件扩展名和无效域名
            file_ext_re = r"\.(dll|pdb|exe|sys|drv|ocx|tlb|dat|bin|sdb|html|nls|mui)$"
            if not re.search(file_ext_re, domain_lower):
                # 将域名转换为 URL 格式
                if not domain.startswith(('http://', 'https://')):
                    url_format = f"http://{domain}"
                else:
                    url_format = domain
                all_urls.append(url_format)
    
    return {
        "ips": list(dict.fromkeys(ips)),
        "domains": (list(dict.fromkeys(domains)) if keep_domains else []),  # 默认隐藏，可通过开关保留
        "urls": list(dict.fromkeys(all_urls)),
        "hashes": list(dict.fromkeys(hashes)),
    }


def aggregate_hash(hash_value: str, apis: Dict[str, str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"hash": hash_value, "results": []}

    # 并发执行支持 hash 的各引擎查询，加速首批结果
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_source = {}
        vtapi = apis.get("VIRUSTOTAL") or ""
        if vtapi:
            future_to_source[executor.submit(vt_lookup, hash_value, vtapi)] = "VirusTotal"
        bazapi = apis.get("BAZAAR") or ""
        if bazapi:
            future_to_source[executor.submit(bazaar_lookup, hash_value, bazapi)] = "MalwareBazaar"
        avapi = apis.get("ALIENVAULT") or ""
        if avapi:
            future_to_source[executor.submit(alienvault_lookup, hash_value, avapi)] = "AlienVault"
        # InQuest 停用
        haapi = apis.get("HYBRID-ANALYSIS") or apis.get("HYBRID") or apis.get("HAAPI") or apis.get("HYBRID_ANALYSIS") or ""
        if haapi:
            future_to_source[executor.submit(hybrid_lookup, hash_value, haapi)] = "HybridAnalysis"
        trapi = apis.get("TRIAGE") or ""
        if trapi:
            future_to_source[executor.submit(triage_lookup, hash_value, trapi)] = "Triage"
        msapi = apis.get("MALSHARE") or ""
        if msapi:
            future_to_source[executor.submit(malshare_lookup, hash_value, msapi)] = "Malshare"
        # ThreatBook（hash）并入并发
        tbapi = apis.get("THREATBOOK") or ""
        if tbapi:
            future_to_source[executor.submit(query_threatbook, hash_value, tbapi)] = "ThreatBook"

        for future in concurrent.futures.as_completed(future_to_source):
            try:
                res = future.result()
                if isinstance(res, dict):
                    # ThreatBook 结果的 IOC 提取（从 summary 中的 IOC_* 字段）
                    if res.get("source") == "ThreatBook" and res.get("hit") and res.get("summary"):
                        summary = res.get("summary") or {}
                        ioc_data = {}
                        for key, value in summary.items():
                            if isinstance(key, str) and key.startswith("IOC_"):
                                ioc_type = key.replace("IOC_", "").lower()
                                if isinstance(value, list):
                                    ioc_data[ioc_type] = value
                        if ioc_data:
                            res["ioc"] = ioc_data
                    out["results"].append(res)
            except Exception as e:
                src = future_to_source[future]
                out["results"].append({"source": src, "hit": False, "error": str(e)})
    # URLHaus 查询已停用
    # ThreatFox：不再对合并IOC做补充查询；仅在用户输入为 IP / 域名 / URL 时在上层分支进行调用

    # 仅使用各平台结构化结果合并 IOC，避免引入非 IOC 噪声
    merged = _merge_iocs(out["results"])
    out["ioc"] = merged

    abuse_key = apis.get("ABUSEIPDB") or ""
    if abuse_key and (out["ioc"].get("ips") or out["ioc"].get("domains")):
        all_ips = list(dict.fromkeys((out["ioc"].get("ips") or []) + resolve_domains_to_ips(out["ioc"].get("domains") or [])))
        client = AbuseIPDBClient(abuse_key)
        out["abuseipdb"] = client.batch_check(all_ips)
    # 仅基于实际查询结果进行展示，不再为未查询的引擎添加占位项
    # 命中优先排序
    out["results"] = sorted(out["results"], key=lambda r: (0 if r.get("hit") else 1, r.get("source")))
    return out

    

def enhanced_url_domain_query(indicator: str, apis: Dict[str, str]) -> Dict[str, Any]:
    """增强的 URL/域名查询，提取威胁标签、子域名、相关样本、历史解析记录和 Whois 信息"""
    enhanced_data = {
        "threat_tags": [],
        "subdomains": [],
        "related_samples": [],
        "passive_dns": [],
        "whois_info": {}
    }
    
    # 提取域名（如果是 URL）
    domain = indicator
    if indicator.startswith(('http://', 'https://')):
        try:
            from urllib.parse import urlparse
            parsed = urlparse(indicator)
            domain = parsed.hostname or indicator
        except Exception:
            pass
    
    # 1. 威胁标签提取 - 从 VirusTotal 获取
    vtapi = apis.get("VIRUSTOTAL") or ""
    if vtapi:
        try:
            headers = {"x-apikey": vtapi}
            
            # 获取域名/URL 的详细信息
            if indicator.startswith(('http://', 'https://')):
                # URL 查询
                url_id = requests.post("https://www.virustotal.com/api/v3/urls", 
                                     headers=headers, 
                                     data={"url": indicator}, 
                                     timeout=30).json().get("data", {}).get("id")
                if url_id:
                    url_data = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", 
                                          headers=headers, timeout=30).json()
                    attrs = url_data.get("data", {}).get("attributes", {})
                    
                    # 提取威胁标签
                    if "last_analysis_results" in attrs:
                        for engine, result in attrs["last_analysis_results"].items():
                            if result.get("result") and result["result"] not in ["clean", "unrated"]:
                                enhanced_data["threat_tags"].append(f"{engine}: {result['result']}")
                    
                    # 提取相关样本 (Files Referring)
                    files_url = f"https://www.virustotal.com/api/v3/urls/{url_id}/relationships/contacted_files"
                    files_resp = requests.get(files_url, headers=headers, timeout=30)
                    if files_resp.status_code == 200:
                        files_data = files_resp.json()
                        for file_item in files_data.get("data", [])[:20]:
                            file_id = file_item.get("id")
                            if file_id:
                                enhanced_data["related_samples"].append(file_id)
            else:
                # 域名查询
                domain_data = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", 
                                         headers=headers, timeout=30)
                if domain_data.status_code == 200:
                    attrs = domain_data.json().get("data", {}).get("attributes", {})
                    
                    # 提取威胁标签
                    if "last_analysis_results" in attrs:
                        for engine, result in attrs["last_analysis_results"].items():
                            if result.get("result") and result["result"] not in ["clean", "unrated"]:
                                enhanced_data["threat_tags"].append(f"{engine}: {result['result']}")
                    
                    # 提取子域名 (Siblings)
                    siblings_url = f"https://www.virustotal.com/api/v3/domains/{domain}/relationships/siblings"
                    siblings_resp = requests.get(siblings_url, headers=headers, timeout=30)
                    if siblings_resp.status_code == 200:
                        siblings_data = siblings_resp.json()
                        for sibling in siblings_data.get("data", []):
                            sibling_id = sibling.get("id")
                            if sibling_id:
                                enhanced_data["subdomains"].append(sibling_id)
                    
                    # 提取相关样本
                    files_url = f"https://www.virustotal.com/api/v3/domains/{domain}/relationships/contacted_files"
                    files_resp = requests.get(files_url, headers=headers, timeout=30)
                    if files_resp.status_code == 200:
                        files_data = files_resp.json()
                        for file_item in files_data.get("data", [])[:20]:
                            file_id = file_item.get("id")
                            if file_id:
                                enhanced_data["related_samples"].append(file_id)
                    
                    # 提取历史解析记录 (Passive DNS)
                    # 使用带重试与可关闭证书校验的会话获取 Passive DNS
                    from requests.adapters import HTTPAdapter
                    from urllib3.util.retry import Retry
                    import requests as _rq
                    _session = _rq.Session()
                    _session.mount("https://", HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504))))
                    _verify = os.environ.get("VT_VERIFY", "1") not in {"0", "false", "False"}
                    resolutions_url = f"https://www.virustotal.com/api/v3/domains/{domain}/relationships/resolutions"
                    resolutions_resp = _session.get(resolutions_url, headers=headers, timeout=30, verify=_verify)
                    if resolutions_resp.status_code == 200:
                        resolutions_data = resolutions_resp.json()
                        for resolution in resolutions_data.get("data", []):
                            ip = resolution.get("attributes", {}).get("ip_address")
                            date = resolution.get("attributes", {}).get("date")
                            if ip and date:
                                enhanced_data["passive_dns"].append(f"{ip} ({date})")
        except Exception as e:
            print(f"VirusTotal 增强查询错误: {e}")
    
    # 2. Whois 信息提取 - 改为从 domains/{domain} attributes.whois 中解析，支持 SSL 容错
    if vtapi and domain:
        try:
            headers = {"x-apikey": vtapi}
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            import requests as _rq
            _session = _rq.Session()
            _session.mount("https://", HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504))))
            _verify = os.environ.get("VT_VERIFY", "1") not in {"0", "false", "False"}
            d_r = _session.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=30, verify=_verify)
            if d_r.status_code == 200:
                attrs = (d_r.json().get("data") or {}).get("attributes") or {}
                whois_text = str(attrs.get("whois") or "")
                registrar = attrs.get("registrar")
                creation_date = attrs.get("creation_date")
                registrant_phone = None
                registrant_email = None
                if whois_text:
                    import re as _re
                    m = _re.search(r"Registrant Phone:\s*([^\r\n]+)", whois_text, _re.I)
                    if m:
                        registrant_phone = m.group(1).strip()
                    m = _re.search(r"Registrant Email:\s*([^\r\n]+)", whois_text, _re.I)
                    if m:
                        registrant_email = m.group(1).strip()
                enhanced_data["whois_info"] = {
                    "registrar": registrar,
                    "creation_date": creation_date,
                    "registrant_phone": registrant_phone,
                    "registrant_email": registrant_email,
                }
        except Exception as e:
            print(f"Whois 查询错误: {e}")
    
    # 3. 从 ThreatFox 提取威胁标签
    tfapi = apis.get("THREATFOX") or ""
    if tfapi:
        try:
            tf_res = threatfox_multi_lookup(indicator, tfapi)
            if tf_res.get("hit") and tf_res.get("summary"):
                summary = tf_res["summary"]
                if summary.get("Threat Type"):
                    threat_type = summary["Threat Type"]
                    if isinstance(threat_type, list):
                        enhanced_data["threat_tags"].extend(threat_type)
                    else:
                        enhanced_data["threat_tags"].append(threat_type)
                
                if summary.get("Malware alias"):
                    alias = summary["Malware alias"]
                    if isinstance(alias, list):
                        enhanced_data["threat_tags"].extend(alias)
                    else:
                        enhanced_data["threat_tags"].append(alias)
        except Exception as e:
            print(f"ThreatFox 威胁标签提取错误: {e}")
    
    # 去重威胁标签
    enhanced_data["threat_tags"] = list(dict.fromkeys(enhanced_data["threat_tags"]))
    enhanced_data["subdomains"] = list(dict.fromkeys(enhanced_data["subdomains"]))
    enhanced_data["related_samples"] = list(dict.fromkeys(enhanced_data["related_samples"]))
    enhanced_data["passive_dns"] = list(dict.fromkeys(enhanced_data["passive_dns"]))
    
    return enhanced_data


def urlhaus_lookup(target: str, api_key: str) -> Dict[str, Any]:
    base = "https://urlhaus-api.abuse.ch/v1"
    s = requests.Session()
    headers = {"accept": "application/json"}
    if api_key:
        headers["Auth-Key"] = api_key
    s.headers.update(headers)
    data: Dict[str, Any] = {}
    hit = False
    urls: List[str] = []
    domains: List[str] = []
    summary: Dict[str, Any] = {}
    # URL 查询
    if re.match(r"^https?://", target, re.I):
        try:
            r = s.post(f"{base}/url/", data={"url": target}, timeout=30)
            js = r.json()
            hit = js.get("query_status") == "ok"
            if hit:
                data = js
                if js.get("host"):
                    domains.append(js.get("host"))
                urls.append(target)
                # 提取概要
                summary = {
                    "URL状态": js.get("url_status"),
                    "Host": js.get("host"),
                    "威胁": js.get("threat"),
                    "标签": js.get("tags"),
                    "添加时间": js.get("date_added"),
                    "参考": js.get("urlhaus_reference"),
                }
                # 可能存在的 payload 列表
                if isinstance(js.get("payloads"), list):
                    summary["样本数量"] = len(js.get("payloads"))
        except Exception:
            pass
    elif re.fullmatch(r"[A-Fa-f0-9]{32}", target) or re.fullmatch(r"[A-Fa-f0-9]{64}", target):
        # Hash 查询（payload by hash）
        try:
            payload_data = {"md5_hash": target} if len(target) == 32 else {"sha256_hash": target}
            r = s.post(f"{base}/payload/", data=payload_data, timeout=30)
            js = r.json()
            hit = js.get("query_status") == "ok"
            if hit:
                data = js
                # 关联 URLs
                for e in js.get("urls", []) or []:
                    u = e.get("url")
                    if u:
                        urls.append(u)
                        try:
                            from urllib.parse import urlparse
                            h = urlparse(u).hostname
                            if h:
                                domains.append(h)
                        except Exception:
                            pass
                summary = {
                    "文件类型": js.get("file_type"),
                    "样本大小": js.get("file_size"),
                    "首次见到": js.get("firstseen"),
                    "最后见到": js.get("lastseen"),
                }
        except Exception:
            pass
    else:
        # host 查询
        try:
            r = s.post(f"{base}/host/", data={"host": target}, timeout=30)
            js = r.json()
            hit = js.get("query_status") == "ok"
            if hit:
                data = js
                count = 0
                for e in js.get("urls", []) or []:
                    u = e.get("url")
                    if u:
                        urls.append(u)
                        count += 1
                summary = {"关联URL数量": count}
        except Exception:
            pass
    return {
        "source": "URLHaus",
        "hit": bool(hit),
        "summary": summary if hit else {},
        "ioc": {"ips": [], "domains": list(dict.fromkeys(domains)), "urls": list(dict.fromkeys(urls))},
        "raw": data,
    }

def aggregate_indicator(indicator: str, apis: Dict[str, str]) -> Dict[str, Any]:
    # 清空 tmp 文件夹
    clear_tmp_folder()
    
    out: Dict[str, Any] = {"indicator": indicator, "results": [], "apis": apis}
    # ThreatBook 并行执行支持
    tb_futures = []
    tb_executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
    is_hash = is_md5(indicator) or is_sha1(indicator) or is_sha256(indicator)
    is_ip = re.fullmatch(r"(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))(?:\\.(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))){3}", indicator) is not None
    is_url = re.match(r"^https?://", indicator, re.I) is not None

    # 识别 ip:port，并并行查询：ThreatFox 用完整 ip:port；其余引擎用纯 IP；报告指标显示为纯 IP
    m_ip_port = re.fullmatch(r"((?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))(?:\\.(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))){3}):(\\d{1,5})", indicator)
    if m_ip_port:
        pure_ip = m_ip_port.group(1)
        port = m_ip_port.group(3)
        out["indicator"] = pure_ip
        # ThreatFox 尝试完整 ip:port 与纯 IP
        tfapi = apis.get("THREATFOX") or ""
        if tfapi:
            out["results"].append(threatfox_multi_lookup(indicator, tfapi))
            out["results"].append(threatfox_multi_lookup(pure_ip, tfapi))
        # 对纯 IP 走原有 IP 分支（VT/AlienVault/URLHaus）
        vtapi = apis.get("VIRUSTOTAL") or ""
        if vtapi:
            try:
                headers = {"x-apikey": vtapi}
                urls: List[str] = []
                domains: List[str] = []
                # URLs 关系
                rr = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{pure_ip}/relationships/urls", headers=headers, timeout=30)
                if rr.status_code == 200:
                    for it in rr.json().get("data", []) or []:
                        u = (it.get("attributes") or {}).get("url") or it.get("id")
                        if u:
                            urls.append(u)
                # 解析域名 resolutions 关系
                rr = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{pure_ip}/relationships/resolutions", headers=headers, timeout=30)
                if rr.status_code == 200:
                    for it in rr.json().get("data", []) or []:
                        host_name = (it.get("attributes") or {}).get("host_name") or it.get("id")
                        if host_name:
                            domains.append(host_name)
                out["results"].append({"source": "VirusTotal", "hit": bool(urls or domains), "ioc": {"ips": [pure_ip], "domains": list(dict.fromkeys(domains)), "urls": list(dict.fromkeys(urls))}})
            except Exception:
                pass
        # AlienVault IP
        avapi = apis.get("ALIENVAULT") or ""
        if avapi:
            try:
                r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{pure_ip}/general", headers={"X-OTX-API-KEY": avapi}, timeout=30)
                if r.status_code == 200:
                    js = r.json()
                    pulses = (js.get("pulse_info") or {}).get("pulses") or []
                    domains: List[str] = []
                    urls: List[str] = []
                    for p in pulses:
                        for ind in p.get("indicators", []) or []:
                            val = ind.get("indicator") or ""
                            t = (ind.get("type") or "").lower()
                            if t in {"domain", "hostname"}:
                                domains.append(val)
                            elif t in {"url", "uri"}:
                                urls.append(val)
                    out["results"].append({"source": "AlienVault", "hit": bool(pulses), "ioc": {"ips": [pure_ip], "domains": list(dict.fromkeys(domains)), "urls": list(dict.fromkeys(urls))}})
            except Exception:
                pass
        # URLHaus 查询已停用
        # 合并、排序并返回
        merged = _merge_iocs(out["results"])
        out["ioc"] = merged
        abuse_key = apis.get("ABUSEIPDB") or ""
        if abuse_key and (merged.get("ips") or merged.get("domains")):
            all_ips = list(dict.fromkeys((merged.get("ips") or []) + resolve_domains_to_ips(merged.get("domains") or [])))
            client = AbuseIPDBClient(abuse_key)
            out["abuseipdb"] = client.batch_check(all_ips)
        out["results"] = sorted(out["results"], key=lambda r: (0 if r.get("hit") else 1, r.get("source")))
        return out

    if is_hash:
        return aggregate_hash(indicator, apis)
    if is_url:
        # URLHaus 查询已停用
        # ThreatFox 针对 URL 的 host 也尝试
        tfapi = apis.get("THREATFOX") or ""
        if tfapi:
            try:
                from urllib.parse import urlparse
                host = urlparse(indicator).hostname or ""
                if host:
                    tf_res = threatfox_multi_lookup(host, tfapi)
                    # 若 ThreatFox 提供 TriageIDs，使用配置中的 TRIAGE key 触发 Triage 查询
                    if tf_res.get("hit"):
                        triage_ids = (tf_res.get("summary") or {}).get("TriageIDs") or []
                        if triage_ids:
                            tr_id = triage_ids[0]
                            tr_key = apis.get("TRIAGE") or apis.get("TRIAGEAPI") or ""
                            out["results"].append(triage_lookup(tr_id, tr_key))
                    out["results"].append(tf_res)
            except Exception:
                pass
        vtapi = apis.get("VIRUSTOTAL") or ""
        if vtapi:
            try:
                headers = {"x-apikey": vtapi}
                # 正确方式：先 POST /urls 提交，再用返回的 id 查询；若失败回退到 url_id 计算
                rid = None
                try:
                    cr = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": indicator}, headers=headers, timeout=30)
                    if cr.status_code == 200:
                        rid = (cr.json().get("data") or {}).get("id")
                except Exception:
                    rid = None
                if not rid:
                    try:
                        from utils.utils import compute_vt_url_id
                        rid = compute_vt_url_id(indicator)
                    except Exception:
                        rid = None
                urls: List[str] = [indicator]
                domains: List[str] = []
                ips: List[str] = []
                if rid:
                    # 主报告（非必须）
                    try:
                        _ = requests.get(f"https://www.virustotal.com/api/v3/urls/{rid}", headers=headers, timeout=30)
                    except Exception:
                        pass
                    # 仅尝试常见可用的关系，403/404 忽略
                    for rel in ("contacted_ips", "contacted_domains"):
                        try:
                            rr = requests.get(f"https://www.virustotal.com/api/v3/urls/{rid}/relationships/{rel}", headers=headers, timeout=30)
                            if rr.status_code == 200:
                                for it in rr.json().get("data", []) or []:
                                    if rel == "contacted_ips":
                                        ip = (it.get("attributes") or {}).get("ip_address") or it.get("id")
                                        if ip:
                                            ips.append(ip)
                                    else:
                                        dom = it.get("id")
                                        if dom:
                                            domains.append(dom)
                        except Exception:
                            pass
                out["results"].append({"source": "VirusTotal", "hit": bool(urls or domains or ips), "ioc": {"ips": list(dict.fromkeys(ips)), "domains": list(dict.fromkeys(domains)), "urls": list(dict.fromkeys(urls))}})
            except Exception:
                pass
        # 同时尝试 host
        try:
            from urllib.parse import urlparse
            host = urlparse(indicator).hostname or ""
            if host:
                # URLHaus 查询已停用
                if tfapi:
                    out["results"].append(threatfox_multi_lookup(host, tfapi))
                # ThreatBook：URL 查询禁用（权限不足）
        except Exception:
            pass
        
        # 增强的 URL/域名查询 - 提取威胁标签、子域名、相关样本、历史解析记录和 Whois 信息
        enhanced_data = enhanced_url_domain_query(indicator, apis)
        if any(enhanced_data.values()):
            out["enhanced"] = enhanced_data
    elif is_ip:
        vtapi = apis.get("VIRUSTOTAL") or ""
        if vtapi:
            try:
                headers = {"x-apikey": vtapi}
                urls: List[str] = []
                domains: List[str] = []
                # URLs 关系
                rr = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}/relationships/urls", headers=headers, timeout=30)
                if rr.status_code == 200:
                    for it in rr.json().get("data", []) or []:
                        u = (it.get("attributes") or {}).get("url") or it.get("id")
                        if u:
                            urls.append(u)
                # 解析域名 resolutions 关系
                rr = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}/relationships/resolutions", headers=headers, timeout=30)
                if rr.status_code == 200:
                    for it in rr.json().get("data", []) or []:
                        host_name = (it.get("attributes") or {}).get("host_name") or it.get("id")
                        if host_name:
                            domains.append(host_name)
                out["results"].append({"source": "VirusTotal", "hit": bool(urls or domains), "ioc": {"ips": [indicator], "domains": list(dict.fromkeys(domains)), "urls": list(dict.fromkeys(urls))}})
            except Exception:
                pass
        # AlienVault IP
        avapi = apis.get("ALIENVAULT") or ""
        if avapi:
            try:
                r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general", headers={"X-OTX-API-KEY": avapi}, timeout=30)
                if r.status_code == 200:
                    js = r.json()
                    pulses = (js.get("pulse_info") or {}).get("pulses") or []
                    domains: List[str] = []
                    urls: List[str] = []
                    for p in pulses:
                        for ind in p.get("indicators", []) or []:
                            val = ind.get("indicator") or ""
                            t = (ind.get("type") or "").lower()
                            if t in {"domain", "hostname"}:
                                domains.append(val)
                            elif t in {"url", "uri"}:
                                urls.append(val)
                    out["results"].append({"source": "AlienVault", "hit": bool(pulses), "ioc": {"ips": [indicator], "domains": list(dict.fromkeys(domains)), "urls": list(dict.fromkeys(urls))}})
            except Exception:
                pass
        # URLHaus 查询已停用
        tfapi = apis.get("THREATFOX") or ""
        if tfapi:
            tf_res = threatfox_multi_lookup(indicator, tfapi)
            if tf_res.get("hit"):
                triage_ids = (tf_res.get("summary") or {}).get("TriageIDs") or []
                if triage_ids:
                    tr_id = triage_ids[0]
                    tr_key = apis.get("TRIAGE") or apis.get("TRIAGEAPI") or ""
                    out["results"].append(triage_lookup(tr_id, tr_key))
            out["results"].append(tf_res)
        # InQuest 停用
        # ThreatBook：IP 查询保留
        tbapi = apis.get("THREATBOOK") or ""
        if tbapi:
            tb_futures.append(tb_executor.submit(query_threatbook, indicator, tbapi))
    else:
        # 作为域名处理
        # URLHaus 查询已停用
        tfapi = apis.get("THREATFOX") or ""
        if tfapi:
            tf_res = threatfox_multi_lookup(indicator, tfapi)
            if tf_res.get("hit"):
                triage_ids = (tf_res.get("summary") or {}).get("TriageIDs") or []
                if triage_ids:
                    tr_id = triage_ids[0]
                    tr_key = apis.get("TRIAGE") or apis.get("TRIAGEAPI") or ""
                    out["results"].append(triage_lookup(tr_id, tr_key))
            out["results"].append(tf_res)
        # InQuest 停用
        # ThreatBook：域名查询保留
        tbapi = apis.get("THREATBOOK") or ""
        if tbapi:
            tb_futures.append(tb_executor.submit(query_threatbook, indicator, tbapi))
        # VT domain relationships
        vtapi = apis.get("VIRUSTOTAL") or ""
        if vtapi:
            try:
                headers = {"x-apikey": vtapi}
                domains: List[str] = [indicator]
                ips: List[str] = []
                urls: List[str] = []
                for rel in ("ip_addresses", "urls"):
                    rr = requests.get(f"https://www.virustotal.com/api/v3/domains/{indicator}/relationships/{rel}", headers=headers, timeout=30)
                    if rr.status_code == 200:
                        for it in rr.json().get("data", []) or []:
                            if rel == "ip_addresses":
                                ip = (it.get("attributes") or {}).get("ip_address") or it.get("id")
                                if ip:
                                    ips.append(ip)
                            else:
                                u = (it.get("attributes") or {}).get("url") or it.get("id")
                                if u:
                                    urls.append(u)
                out["results"].append({"source": "VirusTotal", "hit": bool(ips or urls), "ioc": {"ips": list(dict.fromkeys(ips)), "domains": domains, "urls": list(dict.fromkeys(urls))}})
            except Exception:
                pass
        # AlienVault domain general
        avapi = apis.get("ALIENVAULT") or ""
        if avapi:
            try:
                r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general", headers={"X-OTX-API-KEY": avapi}, timeout=30)
                if r.status_code == 200:
                    js = r.json()
                    pulses = (js.get("pulse_info") or {}).get("pulses") or []
                    ips: List[str] = []
                    urls: List[str] = []
                    for p in pulses:
                        for ind in p.get("indicators", []) or []:
                            val = ind.get("indicator") or ""
                            t = (ind.get("type") or "").lower()
                            if t in {"ipv4", "ipv6", "ip"}:
                                ips.append(val)
                            elif t in {"url", "uri"}:
                                urls.append(val)
                    out["results"].append({"source": "AlienVault", "hit": bool(pulses), "ioc": {"ips": list(dict.fromkeys(ips)), "domains": [indicator], "urls": list(dict.fromkeys(urls))}})
            except Exception:
                pass
        
        # 增强的 URL/域名查询 - 提取威胁标签、子域名、相关样本、历史解析记录和 Whois 信息
        enhanced_data = enhanced_url_domain_query(indicator, apis)
        if any(enhanced_data.values()):
            out["enhanced"] = enhanced_data
    # 收集 ThreatBook futures 结果
    for f in concurrent.futures.as_completed(tb_futures):
        try:
            tb = f.result()
            if isinstance(tb, dict):
                out["results"].append(tb)
                # 若存在原始数据，按原有行为保存
                raw = tb.get("raw", {})
                if raw:
                    save_json_data(indicator, "threatbook", raw)
        except Exception as e:
            out["results"].append({"source": "ThreatBook", "hit": False, "error": str(e)})
    # 关闭执行器
    tb_executor.shutdown(wait=False)

    merged = _merge_iocs(out["results"])
    out["ioc"] = merged
    abuse_key = apis.get("ABUSEIPDB") or ""
    if abuse_key and (merged.get("ips") or merged.get("domains")):
        all_ips = list(dict.fromkeys((merged.get("ips") or []) + resolve_domains_to_ips(merged.get("domains") or [])))
        client = AbuseIPDBClient(abuse_key)
        out["abuseipdb"] = client.batch_check(all_ips)
    # 确保所有引擎至少占位出现
    present = {r.get("source") for r in out["results"]}
    for src in EXPECTED_SOURCES:
        if src not in present:
            out["results"].append({"source": src, "hit": False})
    out["results"] = sorted(out["results"], key=lambda r: (0 if r.get("hit") else 1, r.get("source")))
    return out


def print_chinese_report(agg: Dict[str, Any]) -> None:
    # 导入颜色模块
    try:
        from colorama import Fore, Back, Style, init
        init(autoreset=True)
    except ImportError:
        # 如果没有 colorama，使用 ANSI 颜色码
        class Fore:
            RED = '\033[91m'
            GREEN = '\033[92m'
            YELLOW = '\033[93m'
            BLUE = '\033[94m'
            MAGENTA = '\033[95m'
            CYAN = '\033[96m'
            WHITE = '\033[97m'
        class Style:
            BRIGHT = '\033[1m'
            RESET_ALL = '\033[0m'
    
    # 入口脚本已打印标题与横线，这里不再重复打印标题，避免冗余
    print()
    
    if agg.get('hash'):
        print(f"{Fore.YELLOW}🔍 目标哈希:{Style.RESET_ALL} {agg.get('hash')}")
    elif agg.get('indicator'):
        print(f"{Fore.YELLOW}🎯 目标指标:{Style.RESET_ALL} {agg.get('indicator')}")
    
    print(f"\n{Fore.BLUE}{Style.BRIGHT}📊 检测结果:{Style.RESET_ALL}")
    results = agg.get("results", [])
    hit_results = [r for r in results if r.get("hit")]
    miss_results = [r for r in results if not r.get("hit")]

    # 判定模式：hash / ip / url / domain
    ind = str(agg.get('hash') or agg.get('indicator') or '')
    ind_low = ind.lower()
    is_hash = bool(ind_low) and (len(ind_low) in (32, 40, 64)) and all(c in '0123456789abcdef' for c in ind_low)
    is_ip = bool(re.fullmatch(r"(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))(?:\\.(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))){3}", ind))
    is_url = bool(re.match(r"^https?://", ind, re.I))
    url_or_domain_mode = (not is_hash) and (not is_ip) and (is_url or ind)

    # 先仅打印命中摘要（未命中移至末尾）
    for r in hit_results:
        src = r.get("source")
        print(f"{Fore.GREEN}✅ {src}: 命中{Style.RESET_ALL}")

    # 然后打印"综合命中结果"区块（统一字段展示）
    if hit_results and not url_or_domain_mode:
        # 汇总字段
        merged_threat_tags: List[str] = []
        merged_alias: List[str] = []
        merged_tags: List[str] = []
        merged_imports: List[str] = []
        filename = None
        family = None
        vt_stats = None

        for r in hit_results:
            _raw = r.get("raw") or {}
            summary = r.get("summary") or (_raw.get("summary") if isinstance(_raw, dict) else {}) or {}
            src = r.get("source")
            
            # 处理 Triage 的特殊 summary 结构
            if src == "Triage":
                if not filename:
                    filename = summary.get("filename")
                if not family:
                    score = summary.get("score", 0)
                    if score > 0:
                        family = f"威胁分数: {score}"
                # Triage 的威胁标签可以从 tasks 中提取
                tasks = summary.get("tasks", {})
                for task_id, task_info in tasks.items():
                    if isinstance(task_info, dict):
                        task_tags = task_info.get("tags", [])
                        if isinstance(task_tags, list):
                            merged_threat_tags.extend([str(x) for x in task_tags if x])
                        task_score = task_info.get("score", 0)
                        if task_score > 0:
                            merged_tags.append(f"{task_id}:{task_score}")
            else:
                # 其他引擎的原有逻辑
                if not filename:
                    filename = summary.get("文件名") or summary.get("文件名称") or summary.get("submit_name")
                if not family:
                    family = summary.get("家族/签名") or summary.get("家族") or summary.get("签名") or summary.get("vx_family")
                ttags = summary.get("威胁标签") or []
                if isinstance(ttags, list):
                    merged_threat_tags.extend([str(x) for x in ttags if x])
                elif ttags:
                    merged_threat_tags.append(str(ttags))
                tags = summary.get("标签") or summary.get("tags") or []
                if isinstance(tags, list):
                    merged_tags.extend([str(x) for x in tags if x])
                elif tags:
                    merged_tags.append(str(tags))
                alias = summary.get("样本别名") or summary.get("别名") or []
                if isinstance(alias, list):
                    merged_alias.extend([str(x) for x in alias if x])
                elif alias:
                    merged_alias.append(str(alias))
                if not vt_stats and isinstance(summary.get("检测统计"), dict):
                    vt_stats = summary.get("检测统计")
                merged_imports.extend(summary.get("导入函数") or [])

        # 去重
        merged_threat_tags = list(dict.fromkeys(merged_threat_tags))
        merged_tags = list(dict.fromkeys(merged_tags))
        merged_alias = list(dict.fromkeys(merged_alias))
        merged_imports = list(dict.fromkeys([str(x) for x in merged_imports]))

        # 打印统一区块
        if merged_threat_tags:
            print(f"  🔥 威胁标签: {Fore.RED}{', '.join(merged_threat_tags)}{Style.RESET_ALL}")
        if filename:
            print(f"  📄 文件名: {filename}")
        if family:
            print(f"  🧬 家族/签名: {family}")
        if merged_tags:
            print(f"  🏷️  标签: {', '.join(merged_tags)}")
        if vt_stats:
            stats_text = (
                f"恶意:{Fore.RED}{vt_stats.get('恶意', 0)}{Style.RESET_ALL} | "
                f"可疑:{Fore.YELLOW}{vt_stats.get('可疑', 0)}{Style.RESET_ALL} | "
                f"无害:{Fore.GREEN}{vt_stats.get('无害', 0)}{Style.RESET_ALL} | "
                f"未检测:{Fore.CYAN}{vt_stats.get('未检测', 0)}{Style.RESET_ALL}"
            )
            if vt_stats.get('失败', 0) > 0:
                stats_text += f" | 失败:{Fore.MAGENTA}{vt_stats.get('失败', 0)}{Style.RESET_ALL}"
            print(f"  📈 检测统计分析: {stats_text}")
        if merged_alias:
            print(f"  📋 样本别名: {', '.join(merged_alias)}")

        # 威胁分类函数
        def classify_api(func_name: str) -> str:
            name = (func_name or "").lower()
            download_kw = ["url", "http", "internet", "wininet", "urlmon", "download", "winhttp", "recv", "send", "connect", "socket"]
            crypto_kw = ["crypt", "bcrypt", "aes", "rc4", "sha", "md5", "rsa"]
            system_kw = ["process", "thread", "toolhelp", "createthread", "openthread", "openprocess"]
            file_kw = ["createfile", "writefile", "readfile", "deletefile", "remove", "copyfile"]
            if any(k in name for k in download_kw):
                return "网络访问/下载"
            if any(k in name for k in crypto_kw):
                return "加密/哈希"
            if any(k in name for k in system_kw):
                return "进程/线程操作"
            if any(k in name for k in file_kw):
                return "文件操作"
            return "其它"

        # 高危导入列表（合并后）
        high_risk_categories = {"网络访问/下载", "加密/哈希"}
        high_risk_imports = []
        for fn in merged_imports:
            cls = classify_api(str(fn))
            if cls in high_risk_categories:
                high_risk_imports.append(str(fn))
        high_risk_imports = list(dict.fromkeys(high_risk_imports))
        # 按需求：不需要"导入函数(高危)"单独区块，仅保留按模板分组展示

        # 导入函数分组表（对齐展示，名称保持为"导入函数"）——按用户模板分组，仅显示命中项
        if merged_imports:
            # 分组关键字
            # 使用有序分组，顺序与用户模板一致
            bucket_items = [
                ("文件操作函数", [
                    "CreateFile", "CreateFileA", "CreateFileW", "WriteFile", "ReadFile", "CopyFile", "MoveFile", "MoveFileEx", "MoveFileExA", "MoveFileExW", "DeleteFile", "DeleteFileA", "DeleteFileW",
                    "SetFileAttributes", "GetTempPath", "GetTempFileName", "SetFilePointer", "SetFilePointerEx", "GetFileSize", "GetFileType", "GetFileAttributes", "GetFileAttributesEx"
                ]),
                ("进程与内存操作", [
                    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "VirtualFree", "WriteProcessMemory", "ReadProcessMemory",
                    "CreateProcess", "CreateProcessA", "OpenProcess", "CreateRemoteThread", "GetProcAddress", "LoadLibrary",
                    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "FreeLibrary", "GetModuleHandle", "GetModuleHandleA", "GetModuleHandleW",
                    "NtMapViewOfSection", "ZwUnmapViewOfSection", "RtlMoveMemory", "memcpy", "VirtualQuery", "VirtualQueryEx",
                    "CreateToolhelp32Snapshot", "Process32First", "Process32Next", "TerminateProcess", "SuspendThread", "ResumeThread",
                    "CreateFiber", "DeleteFiber", "SwitchToFiber", "ConvertThreadToFiber", "ConvertFiberToThread", "GetExitCodeThread",
                    "GetCurrentProcess", "GetCurrentProcessId", "GetCurrentThread", "GetCurrentThreadId"
                ]),
                ("注册表操作", [
                    "RegCreateKey", "RegCreateKeyEx", "RegSetValue", "RegSetValueEx", "RegOpenKey", "RegOpenKeyEx",
                    "RegDeleteKey", "RegDeleteValue", "RegQueryValue", "RegQueryValueEx"
                ]),
                ("网络函数", [
                    "WSAStartup", "socket", "connect", "bind", "listen", "accept", "send", "recv", "HttpOpenRequest",
                    "HttpSendRequest", "InternetOpen", "InternetOpenUrl", "InternetReadFile", "InternetWriteFile", "WinHttpOpen",
                    "WinHttpConnect", "WinHttpSendRequest", "WSAConnect"
                ]),
                ("系统信息与防御规避", [
                    "GetComputerName", "GetUserName", "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetTickCount",
                    "QueryPerformanceCounter", "Sleep", "SleepEx", "SystemParametersInfo", "GetSystemInfo", "GetNativeSystemInfo", "GetWindowsDirectory",
                    "GetSystemDirectory", "GetSystemDirectoryA", "FindWindow", "FindWindowEx", "GetForegroundWindow", "SetWindowsHookEx",
                    "IsWow64Process", "GetVersionExA", "GetVersionExW", "OutputDebugStringA", "OutputDebugStringW",
                    "UnhandledExceptionFilter", "SetUnhandledExceptionFilter"
                ]),
                ("代码执行与注入", [
                    "CreateThread", "NtCreateThreadEx", "QueueUserAPC", "RtlCreateUserThread", "ShellExecute", "ShellExecuteEx",
                    "WinExec", "system"
                ]),
                ("同步机制", [
                    "CreateMutex", "CreateMutexW", "CreateEvent", "CreateEventW", "SetEvent", "ResetEvent",
                    "WaitForSingleObject", "WaitForSingleObjectEx", "WaitForMultipleObjects",
                    "InitializeCriticalSection", "EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection"
                ]),
                ("文件映射函数", [
                    "CreateFileMapping", "CreateFileMappingA", "CreateFileMappingW", "MapViewOfFile", "UnmapViewOfFile"
                ]),
                ("加密与哈希", [
                    "CryptAcquireContext", "CryptCreateHash", "CryptHashData", "CryptEncrypt", "CryptDecrypt", "CryptGenRandom",
                    "BCrypt", "Cert"
                ]),
                ("持久化与自启动", [
                    "SHGetSpecialFolderPath", "CreateService", "StartService", "ControlService", "OpenSCManager", "WMI"
                ]),
            ]
            buckets = {k: v for k, v in bucket_items}

            grouped: Dict[str, List[str]] = {k: [] for k in buckets.keys()}
            other_funcs: List[str] = []
            # 先用已汇总的导入函数
            for raw in merged_imports:
                fn = str(raw)
                low = fn.lower()
                matched = False
                for cap, keys in buckets.items():
                    for kw in keys:
                        if kw.lower() in low:
                            grouped[cap].append(fn)
                            matched = True
                            break
                    if matched:
                        break
                if not matched:
                    other_funcs.append(fn)

            # 再从四个源（MalwareBazaar/VirusTotal/ThreatBook/AlienVault）原始数据中额外抽取 API 证据
            api_sources = {"MalwareBazaar", "VirusTotal", "ThreatBook", "AlienVault"}
            api_regex = re.compile(r"[A-Z0-9_]+\\.dll!?[:]{0,2}[A-Za-z0-9_]+")
            def is_high_risk(name: str) -> bool:
                n = name.lower()
                high_kw = [
                    "writeprocessmemory", "createremotethread", "virtualallocex", "ntwritevirtualmemory", "rtlmovememory",
                    "socket", "connect", "send", "recv", "internet", "winhttp", "wininet", "http",
                    "crypt", "bcrypt", "rsa", "aes", "md5", "sha"
                ]
                return any(k in n for k in high_kw)

            for r in hit_results:
                if r.get("source") not in api_sources:
                    continue
                try:
                    text_blob = json.dumps(r.get("raw") or r, ensure_ascii=False)
                except Exception:
                    continue
                for m in api_regex.findall(text_blob):
                    fn = m
                    low = fn.lower()
                    matched = False
                    for cap, keys in buckets.items():
                        for kw in keys:
                            if kw.lower() in low:
                                ev = fn + (" ⚠️" if is_high_risk(fn) else "")
                                grouped[cap].append(ev)
                                matched = True
                                break
                        if matched:
                            break
                    if not matched:
                        other_funcs.append(fn)

            # 打印导入函数分组表
            print(f"\n{Fore.BLUE}{Style.BRIGHT}导入函数:{Style.RESET_ALL}")
            
            def _print_category_row(title: str, evidences: List[str]):
                # 无上限；空组隐藏
                ev = list(dict.fromkeys(evidences))
                if not ev:
                    return
                
                # 使用多列格式
                formatted_items = format_multi_column(ev, label_width=18)
                if '\n' in formatted_items:
                    # 多行显示
                    lines = formatted_items.split('\n')
                    print(f"{title.ljust(18)}| {lines[0]}")
                    for line in lines[1:]:
                        print(f"{' '.ljust(18)}| {line}")
                else:
                    # 单行显示
                    print(f"{title.ljust(18)}| {formatted_items}")

            for cap, _ in bucket_items:
                _print_category_row(cap, grouped.get(cap, []))

            # 按需求：仅显示命中分类，不展示未匹配的"其它"函数

            # 导出函数：从各源汇总，若无则留空
            merged_exports: List[str] = []
            for r in hit_results:
                # 来自 summary
                _raw = r.get("raw") or {}
                summary = r.get("summary") or (_raw.get("summary") if isinstance(_raw, dict) else {}) or {}
                merged_exports.extend(summary.get("导出函数") or [])
                # 来自 VirusTotal pe_info 原始 raw
                try:
                    raw = r.get("raw") or {}
                    pe_raw = (raw.get("data", {}) or {}).get("attributes", {}).get("pe_info") or raw.get("pe_info") or {}
                    for ex in pe_raw.get("exported_functions", []) or []:
                        if ex:
                            merged_exports.append(str(ex))
                except Exception:
                    pass
            merged_exports = list(dict.fromkeys([str(x) for x in merged_exports]))
            print(f"\n{Fore.BLUE}{Style.BRIGHT}导出函数:{Style.RESET_ALL}")
            if merged_exports:
                formatted_exports = format_multi_column(merged_exports, label_width=0, min_col_width=25)
                print(formatted_exports)
            else:
                print("  无导出函数")
            # 清单（可选）：不再单独打印旧框架的简单清单

        # 外部情报补充（ThreatFox / Triage）
        threatfox_result = next((rr for rr in hit_results if rr.get("source") == "ThreatFox"), None)
        if threatfox_result and isinstance(threatfox_result.get("summary"), dict):
            tf_sum = threatfox_result["summary"]
            extras = []
            if tf_sum.get("Threat Type"):
                val = tf_sum['Threat Type']
                extras.append(f"威胁类型: {', '.join(val) if isinstance(val, list) else val}")
            if tf_sum.get("Malware alias"):
                val = tf_sum['Malware alias']
                extras.append(f"恶意家族别名: {', '.join(val) if isinstance(val, list) else val}")
            if tf_sum.get("Confidence Level"):
                val = tf_sum['Confidence Level']
                extras.append(f"置信度: {', '.join(val) if isinstance(val, list) else val}")
            if tf_sum.get("First seen"):
                extras.append(f"首次发现: {tf_sum['First seen']}")
            if tf_sum.get("Last seen"):
                extras.append(f"最后发现: {tf_sum['Last seen']}")
            if tf_sum.get("Country"):
                val = tf_sum['Country']
                extras.append(f"国家/地区: {', '.join(val) if isinstance(val, list) else val}")
            if tf_sum.get("Tags"):
                tags_val = tf_sum['Tags']
                # 与 VT 模版区分显示
                extras.append(f"ThreatFox_tag: {', '.join(tags_val) if isinstance(tags_val, list) else tags_val}")
            if tf_sum.get("Reference"):
                refs = tf_sum["Reference"] if isinstance(tf_sum["Reference"], list) else [tf_sum["Reference"]]
                extras.append(f"参考链接: {', '.join(refs)}")
                # 自动解析 Triage 样本ID并触发 Triage 查询
                triage_ids = tf_sum.get("TriageIDs") or []
                if triage_ids:
                    # 仅取首个样本ID进行补充
                    tr_id = triage_ids[0]
                    # 允许匿名查询公开样本；若需密钥可通过环境变量 TRIAGEAPI 提供
                    trapi = os.environ.get('TRIAGEAPI', '')
                    tr_res = triage_lookup(tr_id, trapi)
                    if tr_res.get('hit'):
                        # 将 triage 命中也计入 hit_results 语义（用于末尾未命中列表正确统计）
                        hit_results.append(tr_res)
                        # 附带网络连接（包含协议，尽量展示 TCP/UDP）
                        net_ips = tr_res.get('ioc', {}).get('ips') or []
                        net_urls = tr_res.get('ioc', {}).get('urls') or []
                        if net_ips:
                            extras.append(f"Triage IP: {', '.join(net_ips[:10])}")
                        if net_urls:
                            extras.append(f"Triage URL: {', '.join(net_urls[:10])}")
            if extras:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}🌐 外部情报补充:{Style.RESET_ALL}")
                for line in extras:
                    print(f"  - {line}")

    # 展示与 VT 相关的额外字段（导入/导出/落地文件/进程树/行为数据）
    vt_result = next((rr for rr in hit_results if rr.get("source") == "VirusTotal"), None)
    if vt_result:
        if vt_result.get("dropped"):
            print(f"  📁 文件落地(前20): {vt_result['dropped']}")
        if vt_result.get("process_tree"):
            print("  🌳 进程树(前5):", vt_result["process_tree"][:5])
        
        # 显示行为数据
        behavior = vt_result.get("behavior", {})
        if behavior:
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}🔬 行为分析:{Style.RESET_ALL}")
            
            def _print_behavior_section(icon: str, title: str, items: List[str]):
                if items:
                    formatted_items = format_multi_column(items[:15], label_width=18, min_col_width=25)
                    if '\n' in formatted_items:
                        lines = formatted_items.split('\n')
                        print(f"{icon} {title.ljust(16)}| {lines[0]}")
                        for line in lines[1:]:
                            print(f"{' '.ljust(18)}| {line}")
                    else:
                        print(f"{icon} {title.ljust(16)}| {formatted_items}")
            
            _print_behavior_section("🖥️", "Shell命令", behavior.get("shell_commands", []))
            _print_behavior_section("➕", "创建进程", behavior.get("processes_created", []))
            _print_behavior_section("➖", "终止进程", behavior.get("processes_terminated", []))
            _print_behavior_section("🔧", "打开服务", behavior.get("services_opened", []))
            _print_behavior_section("📝", "写入文件", behavior.get("files_written", []))
            
            # 显示进程树
            if vt_result.get("process_tree"):
                print(f"  🌳 进程树:")
                for proc in vt_result["process_tree"][:5]:
                    pid = proc.get("pid", "N/A")
                    ppid = proc.get("ppid", "N/A")
                    name = proc.get("name", "Unknown")
                    print(f"    PID:{pid} PPID:{ppid} {name}")
    
    # 获取 Hybrid Analysis 结果用于风险评估
    hybrid_result = next((rr for rr in hit_results if rr.get("source") == "HybridAnalysis"), None)
    
    # URL/域名模式：统一模板展示（按顺序：标签→子域→相关样本→历史解析→Whois）
    if url_or_domain_mode:
        # 优先使用 VirusTotal 的 summary 字段，其次回退 enhanced
        vt_summary = {}
        for r in hit_results:
            try:
                if r.get("source") != "VirusTotal":
                    continue
                _raw = r.get("raw") or {}
                vt_summary = r.get("summary") or (_raw.get("summary") if isinstance(_raw, dict) else {}) or {}
                if vt_summary:
                    break
            except Exception:
                pass

        enh = agg.get("enhanced") or {}

        def _get_list(key: str, limit: int = 50) -> list:
            vals = []
            if isinstance(vt_summary, dict) and key in vt_summary:
                v = vt_summary.get(key) or []
                if isinstance(v, list):
                    vals = v
            if not vals and isinstance(enh, dict):
                mapping = {
                    "威胁标签": enh.get("threat_tags"),
                    "子域名": enh.get("subdomains"),
                    "相关样本(前20)": enh.get("related_samples"),
                    "历史解析/PassiveDNS": enh.get("passive_dns"),
                }
                v2 = mapping.get(key) or []
                if isinstance(v2, list):
                    vals = v2
            return list(dict.fromkeys([str(x) for x in (vals or [])]))[:limit]

        def _get_whois() -> dict:
            # 仅采用 VirusTotal 提供的 Whois 字段
            whois = {}
            if isinstance(vt_summary, dict):
                whois = vt_summary.get("Whois") or {}
            return {k: v for k, v in (whois or {}).items() if v}

        tags = _get_list("威胁标签", 100)
        subs = _get_list("子域名", 200)
        rels = _get_list("相关样本(前20)", 20)
        pdns = _get_list("历史解析/PassiveDNS", 200)
        whois = _get_whois()

        print(f"\n{Fore.CYAN}{Style.BRIGHT}📚 URL/域名概览:{Style.RESET_ALL}")
        if tags:
            formatted_tags = format_multi_column(tags[:30], label_width=18, min_col_width=25)
            if '\n' in formatted_tags:
                lines = formatted_tags.split('\n')
                print(f"  🔥 {'威胁标签'.ljust(16)}| {lines[0]}")
                for line in lines[1:]:
                    print(f"{' '.ljust(18)}| {line}")
            else:
                print(f"  🔥 {'威胁标签'.ljust(16)}| {formatted_tags}")
        else:
            print(f"  🔥 {'威胁标签'.ljust(16)}| -")
        if subs:
            formatted_subs = format_multi_column(subs[:50], label_width=18, min_col_width=25)
            if '\n' in formatted_subs:
                lines = formatted_subs.split('\n')
                print(f"  🌐 {'子域名(Siblings)'.ljust(16)}| {lines[0]}")
                for line in lines[1:]:
                    print(f"{' '.ljust(18)}| {line}")
            else:
                print(f"  🌐 {'子域名(Siblings)'.ljust(16)}| {formatted_subs}")
        else:
            print(f"  🌐 {'子域名(Siblings)'.ljust(16)}| -")
        if rels:
            formatted_rel = format_multi_column(rels[:20], label_width=18, min_col_width=25)
            if '\n' in formatted_rel:
                lines = formatted_rel.split('\n')
                print(f"  🧩 {'相关样本(前20)'.ljust(16)}| {lines[0]}")
                for line in lines[1:]:
                    print(f"{' '.ljust(18)}| {line}")
            else:
                print(f"  🧩 {'相关样本(前20)'.ljust(16)}| {formatted_rel}")
        else:
            print(f"  🧩 {'相关样本(前20)'.ljust(16)}| -")
        if pdns:
            formatted_dns = format_multi_column(pdns[:50], label_width=18, min_col_width=25)
            if '\n' in formatted_dns:
                lines = formatted_dns.split('\n')
                print(f"  🧭 {'历史解析/PassiveDNS'.ljust(16)}| {lines[0]}")
                for line in lines[1:]:
                    print(f"{' '.ljust(18)}| {line}")
            else:
                print(f"  🧭 {'历史解析/PassiveDNS'.ljust(16)}| {formatted_dns}")
        else:
            print(f"  🧭 {'历史解析/PassiveDNS'.ljust(16)}| -")
        print("  📇 Whois:")
        print(f"    Registrar: {whois.get('Registrar') or '-'}")
        print(f"    Creation Date: {whois.get('Creation Date') or '-'}")
        if whois.get("Registrant Phone"):
            print(f"    注册人电话: {whois.get('Registrant Phone')}")
        else:
            print("    注册人电话: -")
        if whois.get("Registrant Email"):
            print(f"    注册人邮箱: {whois.get('Registrant Email')}")
        else:
            print("    注册人邮箱: -")
        # 第7项：证书信息（若存在）
        try:
            cert = {}
            for r in hit_results:
                if r.get('source') == 'VirusTotal':
                    _raw = r.get('raw') or {}
                    summary_vt = r.get('summary') or (_raw.get('summary') if isinstance(_raw, dict) else {}) or {}
                    cert = summary_vt.get('证书') or {}
                    if cert:
                        break
            print("  🔐 证书:")
            if not cert:
                print("    -")
            else:
                if cert.get('subject_cn'):
                    print(f"    Subject CN: {cert.get('subject_cn')}")
                if cert.get('issuer'):
                    print(f"    Issuer: {cert.get('issuer')}")
                if cert.get('serial_number'):
                    print(f"    Serial: {cert.get('serial_number')}")
                if cert.get('fingerprint_sha256'):
                    print(f"    SHA256: {cert.get('fingerprint_sha256')}")
                if cert.get('valid_not_before'):
                    print(f"    Not Before: {cert.get('valid_not_before')}")
                if cert.get('valid_not_after'):
                    print(f"    Not After: {cert.get('valid_not_after')}")
        except Exception:
            pass

    # IOC 信息显示（过滤与去重）——仅在哈希与 IP 模式展示；URL/域名隐藏
    if agg.get("ioc", {}) and (is_hash or is_ip):
        ioc = agg.get("ioc", {})
        # 过滤内网回环 IP
        ips_filtered = [ip for ip in (ioc.get("ips") or []) if ip != "127.0.0.1"]
        # URL 过滤：去除包含 curl.se / index.php / example.com
        urls_raw = (ioc.get("urls") or [])
        urls_filtered = []
        for u in urls_raw:
            lu = u.lower()
            # 过滤明显非 IOC 的站点
            if ("curl.se" in lu) or ("example.com" in lu):
                continue
            # 仅过滤无主机的伪 URL：http://index.php 或 https://index.php
            try:
                if re.match(r"(?i)^https?://index\.php(?:[?#].*)?$", lu):
                    continue
            except Exception:
                pass
            urls_filtered.append(u)
        # 去重
        ips_filtered = list(dict.fromkeys(ips_filtered))
        urls_filtered = list(dict.fromkeys(urls_filtered))
        print(f"\n{Fore.GREEN}{Style.BRIGHT}🔗 提取到的 IOC:{Style.RESET_ALL}")
        if ips_filtered:
            print(f"  🌐 {Fore.CYAN}IP地址:{Style.RESET_ALL} {', '.join(ips_filtered[:20])}")
        # 无论是否为空，都打印 URL 行，便于用户直观看到过滤结果
        url_text = ', '.join(urls_filtered[:20]) if urls_filtered else ''
        print(f"  🔗 {Fore.MAGENTA}URL:{Style.RESET_ALL} {url_text}")
        if ioc.get("hashes"):
            print(f"  🔐 {Fore.RED}哈希值:{Style.RESET_ALL} {', '.join(ioc['hashes'][:10])}")
    
    # AbuseIPDB 信誉信息（过滤 127.0.0.1）
    if agg.get("abuseipdb"):
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}🛡️  IP 信誉评估:{Style.RESET_ALL}")
        # 动态调整显示数量：超过20个IP显示top20，否则显示全部
        ip_count = len(agg["abuseipdb"])
        display_count = min(20, ip_count) if ip_count > 20 else ip_count
        
        for item in agg["abuseipdb"][:display_count]:
            ip = item.get("ipAddress")
            if ip == "127.0.0.1":
                continue
            score = item.get("abuseConfidenceScore")
            country = item.get("countryCode")
            total = item.get("totalReports")
            
            # 修复 None 值比较错误
            if score is None:
                score = 0
            if total is None:
                total = 0
            if country is None:
                country = "None"
            
            # 根据置信度选择颜色
            if score >= 75:
                score_color = Fore.RED
            elif score >= 25:
                score_color = Fore.YELLOW
            else:
                score_color = Fore.GREEN
            
            print(f"  📍 {ip} | 置信度: {score_color}{score}%{Style.RESET_ALL} | 报告: {total} | 国家: {country}")
    
    # 样本下载信息 - 只显示真正支持下载的引擎
    downloadable_engines = []
    download_engine_map = {
        "Malshare": 1,
        "HybridAnalysis": 2, 
        "URLHaus": 3,
        "InQuest": 4,
        "VirusExchange": 5,
        "MalwareBazaar": 6
    }
    
    for result in hit_results:
        source = result.get("source")
        if source in download_engine_map:
            downloadable_engines.append(source)
    
    if downloadable_engines:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}📥 样本下载:{Style.RESET_ALL}")
        download_info = []
        for engine in downloadable_engines:
            engine_num = download_engine_map[engine]
            if engine == "Malshare":
                download_info.append("Malshare 1")
            elif engine == "HybridAnalysis":
                download_info.append("HybridAnalysis 2")
            elif engine == "URLHaus":
                download_info.append("URLHaus 3")
            elif engine == "InQuest":
                download_info.append("InQuest 4")
            elif engine == "VirusExchange":
                download_info.append("VirusExchange 5")
            elif engine == "MalwareBazaar":
                download_info.append("MalwareBazaar 6")
        print(f"  🔽 可下载引擎: {', '.join(download_info)}")
        # 删除下载命令提示，保持输出更简洁

    # 在 IP 信誉评估之后打印未命中引擎（去重）
    if miss_results:
        # 对未命中引擎进行去重
        unique_miss_sources = list(dict.fromkeys([r.get("source") for r in miss_results]))
        for src in unique_miss_sources:
            print(f"{Fore.RED}❌ {src}: 未命中{Style.RESET_ALL}")

    # 旧的 VirusTotal 明细输出在 URL/域名模式下已被上面的统一模板替代，避免重复


