import requests
import os
import json
import time
import glob
import re
import functools
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

# 内存缓存装饰器
@functools.lru_cache(maxsize=128)
def get_cached_data_memory(indicator: str, engine_name: str) -> Optional[Dict[str, Any]]:
    """内存缓存：检查文件缓存并返回数据，使用LRU缓存避免重复文件I/O"""
    return check_cache_and_load(indicator, engine_name)


def check_cache_and_load(indicator: str, engine_name: str) -> Optional[Dict[str, Any]]:
    """检查缓存文件是否存在且在一个月内，如果存在则加载数据"""
    try:
        tmp_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tmp")
        if not os.path.exists(tmp_dir):
            return None
        
        # 与保存逻辑保持一致：对 indicator 进行安全化与截断
        safe_indicator = re.sub(r'[^\w\-\.]', '_', indicator)
        safe_indicator = safe_indicator[:50]
        # 查找匹配的缓存文件
        pattern = f"{engine_name.lower()}_{safe_indicator}_*.json"
        cache_files = glob.glob(os.path.join(tmp_dir, pattern))
        
        if not cache_files:
            return None
        
        # 获取最新的缓存文件
        latest_file = max(cache_files, key=os.path.getmtime)
        
        # 检查文件时间戳（从文件名中提取）
        filename = os.path.basename(latest_file)
        parts = filename.split('_')
        if len(parts) < 3:
            return None
        
        try:
            timestamp = int(parts[-1].replace('.json', ''))
            file_time = datetime.fromtimestamp(timestamp)
            now = datetime.now()
            
            # 检查是否在一个月内
            if now - file_time <= timedelta(days=30):
                with open(latest_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except (ValueError, OSError):
            return None
            
    except Exception:
        return None
    
    return None


def save_json_data(indicator: str, engine_name: str, data: Dict[str, Any]) -> None:
    """保存各引擎的完整 JSON 数据到 modules/tmp 文件夹，文件名包含时间戳"""
    try:
        # 创建包目录下的 tmp 文件夹
        tmp_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tmp")
        if not os.path.exists(tmp_dir):
            os.makedirs(tmp_dir)
        
        # 对 indicator 进行安全处理，移除特殊字符
        safe_indicator = re.sub(r'[^\w\-\.]', '_', indicator)
        # 限制长度，避免文件名过长
        safe_indicator = safe_indicator[:50]
        
        # 先清理同前缀旧文件，仅保留一个最新时间戳文件（将被新文件替换）
        try:
            pattern = os.path.join(tmp_dir, f"{engine_name.lower()}_{safe_indicator}_*.json")
            old_files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
            for old in old_files:
                try:
                    os.remove(old)
                except Exception:
                    pass
        except Exception:
            pass

        # 生成文件名：引擎名_安全指标_时间戳.json
        timestamp = int(time.time())
        filename = f"{engine_name.lower()}_{safe_indicator}_{timestamp}.json"
        filepath = os.path.join(tmp_dir, filename)
        
        # 保存 JSON 数据
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            
    except Exception as e:
        print(f"保存 JSON 数据失败: {e}")


def detect_type(indicator: str) -> str:
    if indicator.startswith("http://") or indicator.startswith("https://"):
        return "url"
    if ":" in indicator and indicator.count(":") == 1:
        host, port = indicator.split(":", 1)
        indicator = host
    # IPv4
    parts = indicator.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p.isdigit()):
        return "ip"
    # hash
    h = indicator.lower()
    if len(h) == 32 and all(c in "0123456789abcdef" for c in h):
        return "md5"
    if len(h) == 40 and all(c in "0123456789abcdef" for c in h):
        return "sha1"
    if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
        return "sha256"
    return "domain"


def query_threatbook(indicator: str, api_key: str) -> Dict[str, Any]:
    # 没有 API Key 时，不允许尝试（包含缓存也不读取）
    if not api_key:
        return {"source": "ThreatBook", "hit": False, "error": "no api key"}

    # 首先检查内存缓存（仅当存在 API Key 时才允许读取）
    cached_data = get_cached_data_memory(indicator, "threatbook")
    if cached_data:
        print(f"📦 使用 ThreatBook 缓存数据")
        js = cached_data
    else:
        # 没有缓存，进行 API 查询
        t = detect_type(indicator)
        base = "https://api.threatbook.cn"
        headers = {"Accept": "application/json"}
        params = {"apikey": api_key}

        # 尝试常见查询接口（不同类型使用不同 scene），若失败则返回未命中
        try:
            if t == "ip":
                url = f"{base}/v5/ip/reputation"
                params.update({"resource": indicator})
            elif t in ("md5", "sha1", "sha256"):
                url = f"{base}/v5/file/report"
                params.update({"resource": indicator})
            elif t == "url":
                url = f"{base}/v5/url/reputation"
                params.update({"resource": indicator})
            else:  # domain
                url = f"{base}/v5/domain/reputation"
                params.update({"resource": indicator})

            r = requests.get(url, headers=headers, params=params, timeout=30)
            js = r.json() if r.status_code == 200 else {"error": r.text}
            
            # 在API响应时就开始过滤，移除strings等大字段
            js = _filter_threatbook_response(js)
            
            # 保存过滤后的 JSON 数据
            save_json_data(indicator, "threatbook", js)
        except Exception as e:
            return {"source": "ThreatBook", "hit": False, "error": str(e)}

    # 标准化输出
    summary: Dict[str, Any] = {}
    tags = []
    hit = False

    try:
        # ThreatBook v5 API 返回格式解析
        if js.get("response_code") == 0:  # 成功响应
            data = js.get("data", {})
            if isinstance(data, dict):
                # 提取 summary 信息
                summary_data = data.get("summary", {})
                if summary_data:
                    summary["文件名"] = summary_data.get("file_name", "")
                    summary["文件大小"] = f"{summary_data.get('file_size', 0)} bytes"
                    summary["文件类型"] = summary_data.get("file_type", "")
                    summary["威胁等级"] = summary_data.get("threat_level", "")
                    summary["恶意软件类型"] = summary_data.get("malware_type", "")
                    summary["恶意软件家族"] = summary_data.get("malware_family", "")
                    summary["威胁分数"] = summary_data.get("threat_score", "")
                    summary["多引擎检测"] = summary_data.get("multi_engines", "")
                    summary["提交时间"] = summary_data.get("submit_time", "")
                    
                    # 提取标签
                    tag_data = summary_data.get("tag", {})
                    if isinstance(tag_data, dict):
                        # 提取 x 标签（威胁标签）
                        x_tags = tag_data.get("x", [])
                        if isinstance(x_tags, list):
                            tags.extend([str(x) for x in x_tags if x])
                        # 提取 s 标签（系统标签）
                        s_tags = tag_data.get("s", [])
                        if isinstance(s_tags, list):
                            tags.extend([str(x) for x in s_tags if x])
                
                # 提取多引擎检测结果
                multiengines = data.get("multiengines", {})
                if multiengines:
                    engines_result = multiengines.get("result", {})
                    if engines_result:
                        # 统计检测结果
                        malicious_count = 0
                        total_count = len(engines_result)
                        for engine, result in engines_result.items():
                            if result and result.lower() not in ["safe", "clean", "benign"]:
                                malicious_count += 1
                        summary["检测统计"] = f"{malicious_count}/{total_count} 恶意"
                
                # 提取 IOC 信息
                iocs = {"ips": [], "domains": [], "urls": [], "hashes": []}
                
                # 从 static 字段提取 IOC
                static_data = data.get("static", {})
                if static_data:
                    # 提取 URLs (从 static.details.urls)
                    details = static_data.get("details", {})
                    urls = details.get("urls", [])
                    if isinstance(urls, list):
                        iocs["urls"].extend([str(url) for url in urls if url])
                
                # 从 dropped 字段提取 IOC
                dropped_files = data.get("dropped", [])
                if isinstance(dropped_files, list):
                    for dropped in dropped_files:
                        if isinstance(dropped, dict):
                            # 提取 dropped file 的 URLs
                            dropped_urls = dropped.get("urls", [])
                            if isinstance(dropped_urls, list):
                                iocs["urls"].extend([str(url) for url in dropped_urls if url])
                            
                            # 提取 dropped file 的哈希值
                            dropped_hash = dropped.get("sha256", "")
                            if dropped_hash:
                                iocs["hashes"].append(dropped_hash)
                
                # 从 summary 字段提取哈希值
                if summary_data:
                    md5_hash = summary_data.get("md5", "")
                    sha1_hash = summary_data.get("sha1", "")
                    sha256_hash = summary_data.get("sample_sha256", "")
                    
                    if md5_hash:
                        iocs["hashes"].append(f"MD5: {md5_hash}")
                    if sha1_hash:
                        iocs["hashes"].append(f"SHA1: {sha1_hash}")
                    if sha256_hash:
                        iocs["hashes"].append(f"SHA256: {sha256_hash}")
                
                # 去重并保存 IOC 信息
                for ioc_type, ioc_list in iocs.items():
                    if ioc_list:
                        # 去重
                        unique_iocs = list(dict.fromkeys(ioc_list))
                        summary[f"IOC_{ioc_type.upper()}"] = unique_iocs
                
                # 提取导入函数（从 ThreatBook 的静态/细节中尽可能收集）
                def _collect_imports(obj) -> list:
                    collected = []
                    try:
                        if isinstance(obj, dict):
                            # 常见结构：{"dll": "KERNEL32.dll", "imports": ["CreateFileW", ...]}
                            dll_name = obj.get("dll") or obj.get("library") or obj.get("module")
                            imports_list = obj.get("imports") or obj.get("functions") or obj.get("imported_functions")
                            if dll_name and isinstance(imports_list, list):
                                for fn in imports_list:
                                    if isinstance(fn, str) and fn:
                                        collected.append(f"{dll_name}!{fn}")
                            # pe_imports: [ {"dll": "...", "imports": [...]}, ... ]
                            for k, v in obj.items():
                                if k in ("pe_imports", "imports", "static_imports") and isinstance(v, list):
                                    for it in v:
                                        collected.extend(_collect_imports(it))
                                else:
                                    collected.extend(_collect_imports(v))
                        elif isinstance(obj, list):
                            for it in obj:
                                collected.extend(_collect_imports(it))
                    except Exception:
                        pass
                    return collected

                tb_imports = []
                # 可能位置：data.static.details.pe_imports / data.static.pe_imports / data.details.imports 等
                for candidate in [
                    data.get("static", {}),
                    data.get("static", {}).get("details", {}),
                    data.get("details", {}),
                    data.get("multiengines", {}),
                    data
                ]:
                    tb_imports.extend(_collect_imports(candidate))
                if tb_imports:
                    # 去重但不裁剪
                    summary["导入函数"] = list(dict.fromkeys([str(x) for x in tb_imports]))
                
                # 如果有任何有效数据，标记为命中
                if any([summary.get("文件名"), summary.get("威胁等级"), summary.get("恶意软件类型"), tags]):
                    hit = True
                    if tags:
                        summary["威胁标签"] = tags
        else:
            # API 返回错误
            error_msg = js.get("verbose_msg", "未知错误")
            summary["错误信息"] = error_msg
    except Exception as e:
        summary["解析错误"] = str(e)

    return {
        "source": "ThreatBook",
        "hit": bool(hit),
        "summary": summary,
        "raw": js,
    }


def _filter_threatbook_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """在API响应时过滤ThreatBook数据，移除不需要的大字段以提高性能"""
    if not isinstance(data, dict):
        return data
    
    # 创建过滤后的数据副本
    filtered_data = data.copy()
    
    # 移除strings字段（占用大量空间且不需要显示）
    # 优化说明：在API响应时过滤ThreatBook数据，移除strings等大字段以提高性能
    # 这样可以减少缓存文件大小，提高API调用和缓存使用速度
    if "data" in filtered_data and isinstance(filtered_data["data"], dict):
        if "strings" in filtered_data["data"]:
            del filtered_data["data"]["strings"]
    
    return filtered_data


