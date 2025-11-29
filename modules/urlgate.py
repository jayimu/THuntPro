#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import time
import shutil
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import concurrent.futures

# 复用现有能力：打印与增强信息由 aggregate 模块提供
from modules.aggregate import enhanced_url_domain_query
from modules.threatbook import query_threatbook
from modules.aggregate import threatfox_multi_lookup
from modules.aggregate import urlhaus_lookup


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


def format_multi_column_full(items: List[str], label_width: int = 18, min_col_width: int = 30) -> str:
    """将项目列表格式化为多列显示，不截断内容"""
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
        # 不截断内容，保持完整
        formatted_items = []
        for item in row_items:
            formatted_items.append(item)
        
        # 填充到相同宽度
        padded_items = [item.ljust(col_width-2) for item in formatted_items]
        lines.append("  ".join(padded_items))
    
    return "\n".join(lines)


def _fmt_time_field(value: Any) -> str:
    """将不同形式的时间值统一为 YYYY/MM/DD；无法解析则原样返回字符串或 '-'"""
    try:
        if value is None:
            return "-"
        # 数字或数字字符串（epoch 秒）
        if isinstance(value, (int, float)):
            if value <= 0:
                return "-"
            return time.strftime("%Y/%m/%d", time.localtime(int(value)))
        s = str(value).strip()
        if not s:
            return "-"
        if s.isdigit():
            iv = int(s)
            if iv > 0:
                return time.strftime("%Y/%m/%d", time.localtime(iv))
        # 形如 2025-07-14 19:04:53 或 2025-07-14
        m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
        if m:
            return f"{m.group(1)}/{m.group(2)}/{m.group(3)}"
        # 形如 2025/07/14 已是目标格式
        m2 = re.match(r"(\d{4})/(\d{2})/(\d{2})", s)
        if m2:
            return s
        return s
    except Exception:
        return str(value) if value is not None else "-"


@dataclass
class ThreatTags:
    """威胁标签数据结构"""
    tags: List[str] = None
    categories: List[str] = None
    campaigns: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.categories is None:
            self.categories = []
        if self.campaigns is None:
            self.campaigns = []


@dataclass
class Subdomains:
    """子域名数据结构"""
    siblings: List[str] = None
    count: int = 0
    
    def __post_init__(self):
        if self.siblings is None:
            self.siblings = []


@dataclass
class RelatedSamples:
    """相关样本数据结构"""
    extracted_files: List[str] = None
    files_referring: List[str] = None
    contacted_files: List[str] = None
    downloaded_files: List[str] = None
    
    def __post_init__(self):
        if self.extracted_files is None:
            self.extracted_files = []
        if self.files_referring is None:
            self.files_referring = []
        if self.contacted_files is None:
            self.contacted_files = []
        if self.downloaded_files is None:
            self.downloaded_files = []
    
    def get_top_20(self) -> List[str]:
        """获取前20个相关样本"""
        all_files = []
        all_files.extend(self.extracted_files[:10])
        all_files.extend(self.files_referring[:10])
        all_files.extend(self.contacted_files[:5])
        all_files.extend(self.downloaded_files[:5])
        return list(dict.fromkeys(all_files))[:20]


@dataclass
class PassiveDNS:
    """历史解析记录数据结构"""
    resolutions: List[str] = None
    ips: List[str] = None
    domains: List[str] = None
    
    def __post_init__(self):
        if self.resolutions is None:
            self.resolutions = []
        if self.ips is None:
            self.ips = []
        if self.domains is None:
            self.domains = []


@dataclass
class WhoisInfo:
    """Whois信息数据结构"""
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    registrant_phone: Optional[str] = None
    registrant_phone_ext: Optional[str] = None
    registrant_email: Optional[str] = None
    registrant_name: Optional[str] = None
    registrant_organization: Optional[str] = None
    registrant_city: Optional[str] = None
    registrant_country: Optional[str] = None
    expiration_date: Optional[str] = None
    name_servers: List[str] = None
    
    def __post_init__(self):
        if self.name_servers is None:
            self.name_servers = []


@dataclass
class CertificateInfo:
    """证书信息数据结构"""
    subject_cn: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    valid_not_before: Optional[str] = None
    valid_not_after: Optional[str] = None
    signature_algorithm: Optional[str] = None
    subject_alternative_names: List[str] = None
    
    def __post_init__(self):
        if self.subject_alternative_names is None:
            self.subject_alternative_names = []


@dataclass
class StandardURLData:
    """标准化的URL/域名数据结构"""
    indicator: str
    threat_tags: ThreatTags = None
    subdomains: Subdomains = None
    related_samples: RelatedSamples = None
    passive_dns: PassiveDNS = None
    whois: WhoisInfo = None
    certificate: CertificateInfo = None
    source_engines: List[str] = None
    
    def __post_init__(self):
        if self.threat_tags is None:
            self.threat_tags = ThreatTags()
        if self.subdomains is None:
            self.subdomains = Subdomains()
        if self.related_samples is None:
            self.related_samples = RelatedSamples()
        if self.passive_dns is None:
            self.passive_dns = PassiveDNS()
        if self.whois is None:
            self.whois = WhoisInfo()
        if self.certificate is None:
            self.certificate = CertificateInfo()
        if self.source_engines is None:
            self.source_engines = []


def _is_debug_enabled() -> bool:
    try:
        return os.environ.get("DEBUG_URLGATE", "0") in {"1", "true", "True"}
    except Exception:
        return False


def _debug(msg: str) -> None:
    try:
        if _is_debug_enabled():
            print(f"[urlgate][DEBUG] {msg}")
    except Exception:
        pass


def _ensure_url_tmp_dir() -> str:
    """确保 URL/域名缓存目录存在"""
    base_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "url_tmp")
    try:
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
    except Exception:
        pass
    return base_dir


def _safe_name(text: str) -> str:
    """生成安全的文件名"""
    return re.sub(r"[^\w\-\.]", "_", text)[:150]


def _filename_from_indicator(indicator: str) -> str:
    """根据查询值生成更友好的文件名"""
    try:
        if re.match(r"^https?://", indicator, re.I):
            from urllib.parse import urlparse
            p = urlparse(indicator)
            host = p.hostname or ""
            path = (p.path or "").rstrip("/")
            if path and path != "/":
                base = f"{host}{path.replace('/', '_')}"
            else:
                base = host or indicator
            return _safe_name(base)
        return _safe_name(indicator)
    except Exception:
        return _safe_name(indicator)


def _load_standard_cache(indicator: str, engine: str = "virustotal", max_age_days: int = 30) -> Optional[StandardURLData]:
    """加载标准化缓存"""
    try:
        out_dir = _ensure_url_tmp_dir()
        safe_indicator = _filename_from_indicator(indicator)
        fp = os.path.join(out_dir, f"{engine.lower()}_standard_{safe_indicator}.json")
        if not os.path.isfile(fp):
            return None
        mtime = os.path.getmtime(fp)
        if (time.time() - mtime) > (max_age_days * 24 * 3600):
            return None
        with open(fp, "r", encoding="utf-8") as f:
            data = json.load(f)
            return _dict_to_standard_data(data)
    except Exception:
        return None


def _save_engine_cache(indicator: str, engine: str, data: dict) -> None:
    """保存单个引擎的缓存数据"""
    try:
        out_dir = _ensure_url_tmp_dir()
        safe_indicator = _filename_from_indicator(indicator)
        fp = os.path.join(out_dir, f"{engine.lower()}_{safe_indicator}.json")
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        _debug(f"已保存{engine}缓存: {fp}")
    except Exception as e:
        _debug(f"保存{engine}缓存失败: {e}")


def _load_engine_cache(indicator: str, engine: str, max_age_hours: int = 24) -> Optional[dict]:
    """加载单个引擎的缓存数据"""
    try:
        out_dir = _ensure_url_tmp_dir()
        safe_indicator = _filename_from_indicator(indicator)
        fp = os.path.join(out_dir, f"{engine.lower()}_{safe_indicator}.json")
        
        if not os.path.exists(fp):
            return None
        
        # 检查文件年龄
        file_age = time.time() - os.path.getmtime(fp)
        if file_age > max_age_hours * 3600:
            return None
        
        with open(fp, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def _load_all_engine_caches(indicator: str, max_age_hours: int = 24) -> Dict[str, dict]:
    """加载所有引擎的缓存数据（禁用 HybridAnalysis for URL）"""
    engines = ["virustotal", "urlhaus", "alienvault", "threatfox"]
    cached_data = {}
    
    for engine in engines:
        data = _load_engine_cache(indicator, engine, max_age_hours)
        if data:
            cached_data[engine] = data
    
    return cached_data


def _save_standard_cache(indicator: str, data: StandardURLData, engine: str = "virustotal") -> None:
    """保存标准化缓存"""
    try:
        out_dir = _ensure_url_tmp_dir()
        safe_indicator = _filename_from_indicator(indicator)
        fp = os.path.join(out_dir, f"{engine.lower()}_standard_{safe_indicator}.json")
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(_standard_data_to_dict(data), f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _dict_to_standard_data(data: dict) -> StandardURLData:
    """将字典转换为标准化数据结构"""
    try:
        return StandardURLData(
            indicator=data.get("indicator", ""),
            threat_tags=ThreatTags(**data.get("threat_tags", {})),
            subdomains=Subdomains(**data.get("subdomains", {})),
            related_samples=RelatedSamples(**data.get("related_samples", {})),
            passive_dns=PassiveDNS(**data.get("passive_dns", {})),
            whois=WhoisInfo(**data.get("whois", {})),
            certificate=CertificateInfo(**data.get("certificate", {})),
            source_engines=data.get("source_engines", [])
        )
    except Exception:
        return StandardURLData(indicator=data.get("indicator", ""))


def _standard_data_to_dict(data: StandardURLData) -> dict:
    """将标准化数据结构转换为字典"""
    try:
        return {
            "indicator": data.indicator,
            "threat_tags": asdict(data.threat_tags),
            "subdomains": asdict(data.subdomains),
            "related_samples": asdict(data.related_samples),
            "passive_dns": asdict(data.passive_dns),
            "whois": asdict(data.whois),
            "certificate": asdict(data.certificate),
            "source_engines": data.source_engines
        }
    except Exception:
        return {"indicator": data.indicator}


def _merge_standard_data(existing: StandardURLData, new: StandardURLData) -> StandardURLData:
    """合并两个标准化数据结构"""
    try:
        # 合并威胁标签
        merged_tags = ThreatTags(
            tags=list(dict.fromkeys(existing.threat_tags.tags + new.threat_tags.tags)),
            categories=list(dict.fromkeys(existing.threat_tags.categories + new.threat_tags.categories)),
            campaigns=list(dict.fromkeys(existing.threat_tags.campaigns + new.threat_tags.campaigns))
        )
        
        # 合并子域名
        merged_subs = Subdomains(
            siblings=list(dict.fromkeys(existing.subdomains.siblings + new.subdomains.siblings)),
            count=max(existing.subdomains.count, new.subdomains.count)
        )
        
        # 合并相关样本
        merged_samples = RelatedSamples(
            extracted_files=list(dict.fromkeys(existing.related_samples.extracted_files + new.related_samples.extracted_files)),
            files_referring=list(dict.fromkeys(existing.related_samples.files_referring + new.related_samples.files_referring)),
            contacted_files=list(dict.fromkeys(existing.related_samples.contacted_files + new.related_samples.contacted_files)),
            downloaded_files=list(dict.fromkeys(existing.related_samples.downloaded_files + new.related_samples.downloaded_files))
        )
        
        # 合并PassiveDNS
        merged_pdns = PassiveDNS(
            resolutions=list(dict.fromkeys(existing.passive_dns.resolutions + new.passive_dns.resolutions)),
            ips=list(dict.fromkeys(existing.passive_dns.ips + new.passive_dns.ips)),
            domains=list(dict.fromkeys(existing.passive_dns.domains + new.passive_dns.domains))
        )
        
        # 合并Whois（优先使用非空值）
        merged_whois = WhoisInfo()
        for field in ['registrar', 'creation_date', 'registrant_phone', 'registrant_email', 
                     'registrant_name', 'registrant_organization', 'registrant_city', 
                     'registrant_country', 'expiration_date']:
            existing_val = getattr(existing.whois, field)
            new_val = getattr(new.whois, field)
            setattr(merged_whois, field, existing_val or new_val)
        
        merged_whois.name_servers = list(dict.fromkeys(existing.whois.name_servers + new.whois.name_servers))
        
        # 合并证书（优先使用非空值）
        merged_cert = CertificateInfo()
        for field in ['subject_cn', 'issuer', 'serial_number', 'fingerprint_sha256', 
                     'valid_not_before', 'valid_not_after', 'signature_algorithm']:
            existing_val = getattr(existing.certificate, field)
            new_val = getattr(new.certificate, field)
            setattr(merged_cert, field, existing_val or new_val)
        
        merged_cert.subject_alternative_names = list(dict.fromkeys(
            existing.certificate.subject_alternative_names + new.certificate.subject_alternative_names
        ))
        
        # 合并源引擎
        merged_engines = list(dict.fromkeys(existing.source_engines + new.source_engines))
        
        return StandardURLData(
            indicator=existing.indicator,
            threat_tags=merged_tags,
            subdomains=merged_subs,
            related_samples=merged_samples,
            passive_dns=merged_pdns,
            whois=merged_whois,
            certificate=merged_cert,
            source_engines=merged_engines
        )
    except Exception:
        return existing


def _extract_vt_threat_tags(vt_data: dict) -> ThreatTags:
    """从VT数据中提取威胁标签"""
    tags = []
    categories = []
    campaigns = []
    
    try:
        attrs = vt_data.get('data', {}).get('attributes', {})
        
        # 提取tags
        vt_tags = attrs.get('tags', [])
        if isinstance(vt_tags, list):
            tags.extend([str(t) for t in vt_tags if t])
        
        # 提取categories
        vt_categories = attrs.get('categories', {})
        if isinstance(vt_categories, dict):
            categories.extend([str(k) for k in vt_categories.keys() if k])
        
        # 从引擎结果中提取威胁标签
        analysis_results = attrs.get('last_analysis_results', {})
        if isinstance(analysis_results, dict):
            for engine, result in analysis_results.items():
                if isinstance(result, dict):
                    result_val = result.get('result', '')
                    if result_val and result_val not in ('clean', 'unrated'):
                        tags.append(f"{engine}: {result_val}")
        
        # 去重
        tags = list(dict.fromkeys(tags))
        categories = list(dict.fromkeys(categories))
        
    except Exception:
        pass
    
    return ThreatTags(tags=tags, categories=categories, campaigns=campaigns)


def _extract_vt_subdomains(vt_data: dict) -> Subdomains:
    """从VT数据中提取子域名"""
    siblings = []
    
    try:
        rels = vt_data.get('relationships', {})
        subdomains_data = rels.get('subdomains', {}).get('data', [])
        
        for item in subdomains_data:
            if isinstance(item, dict):
                sub_id = item.get('id')
                if sub_id:
                    siblings.append(str(sub_id))

        # 同时合并 siblings 关系（VT 可能将同根域其它子域放在该关系中）
        sib_data = rels.get('siblings', {}).get('data', [])
        for item in sib_data:
            if isinstance(item, dict):
                sib_id = item.get('id')
                if sib_id:
                    siblings.append(str(sib_id))
        
        siblings = list(dict.fromkeys(siblings))
        
    except Exception:
        pass
    
    return Subdomains(siblings=siblings, count=len(siblings))


def _extract_vt_related_samples(vt_data: dict) -> RelatedSamples:
    """从VT数据中提取相关样本"""
    extracted_files = []
    files_referring = []
    contacted_files = []
    downloaded_files = []
    
    try:
        rels = vt_data.get('relationships', {})
        
        # 提取referrer_files
        ref_data = rels.get('referrer_files', {}).get('data', [])
        for item in ref_data[:20]:
            if isinstance(item, dict):
                file_id = item.get('id')
                if file_id:
                    files_referring.append(str(file_id))
        
        # 提取communicating_files (相当于contacted_files)
        comm_data = rels.get('communicating_files', {}).get('data', [])
        for item in comm_data[:20]:
            if isinstance(item, dict):
                file_id = item.get('id')
                if file_id:
                    contacted_files.append(str(file_id))
        
        # 提取downloaded_files
        down_data = rels.get('downloaded_files', {}).get('data', [])
        for item in down_data[:20]:
            if isinstance(item, dict):
                file_id = item.get('id')
                if file_id:
                    downloaded_files.append(str(file_id))
        
        # 去重
        files_referring = list(dict.fromkeys(files_referring))
        contacted_files = list(dict.fromkeys(contacted_files))
        downloaded_files = list(dict.fromkeys(downloaded_files))
        
    except Exception:
        pass
    
    return RelatedSamples(
        extracted_files=extracted_files,
        files_referring=files_referring,
        contacted_files=contacted_files,
        downloaded_files=downloaded_files
    )


def _extract_vt_passive_dns(vt_data: dict) -> PassiveDNS:
    """从VT数据中提取PassiveDNS信息"""
    resolutions = []
    ips = []
    domains = []
    
    try:
        rels = vt_data.get('relationships', {})
        attrs = (vt_data.get('data') or {}).get('attributes') or vt_data.get('attributes') or {}
        
        # 提取resolutions
        res_data = rels.get('resolutions', {}).get('data', [])
        for item in res_data[:200]:
            if isinstance(item, dict):
                res_id = item.get('id')
                if res_id:
                    resolutions.append(str(res_id))
                    # 尝试从ID中提取IP - 修复IP提取逻辑
                    res_str = str(res_id)
                    # 查找IP地址模式
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', res_str)
                    if ip_match:
                        ips.append(ip_match.group(1))
        
        # 提取contacted_ips
        ip_data = rels.get('contacted_ips', {}).get('data', [])
        for item in ip_data:
            if isinstance(item, dict):
                ip_addr = item.get('attributes', {}).get('ip_address') or item.get('id')
                if ip_addr:
                    ips.append(str(ip_addr))
        
        # 提取contacted_domains
        dom_data = rels.get('contacted_domains', {}).get('data', [])
        for item in dom_data:
            if isinstance(item, dict):
                dom_id = item.get('id')
                if dom_id:
                    domains.append(str(dom_id))

        # 额外：从 v3 data.attributes.last_dns_records 提取（官方建议使用）
        try:
            last_dns = attrs.get('last_dns_records') or []
            for rec in last_dns:
                if not isinstance(rec, dict):
                    continue
                rtype = str(rec.get('type') or rec.get('record_type') or '').upper()
                value = str(rec.get('value') or rec.get('rdata') or '').strip()
                if not value:
                    continue
                # A/AAAA 记录视为 IP
                if rtype in ('A', 'AAAA'):
                    ips.append(value)
                    # 若为当前域名的 A 记录，可构造解析文本
                    try:
                        dom_name = str((vt_data.get('data') or {}).get('id') or '')
                        if dom_name and rtype == 'A':
                            resolutions.append(f"{dom_name} {value}")
                    except Exception:
                        pass
                # NS/CNAME/MX/TXT/SOA/PTR 等记录的目标视为域名类
                else:
                    domains.append(value)
        except Exception:
            pass

        # 去重
        resolutions = list(dict.fromkeys(resolutions))
        ips = list(dict.fromkeys(ips))
        domains = list(dict.fromkeys(domains))
        
    except Exception:
        pass
    
    return PassiveDNS(resolutions=resolutions, ips=ips, domains=domains)


def _extract_vt_whois(vt_data: dict) -> WhoisInfo:
    """从VT数据中提取Whois信息"""
    try:
        attrs = vt_data.get('data', {}).get('attributes', {})
        whois_text = str(attrs.get('whois', ''))
        
        # 解析whois文本
        registrar = attrs.get('registrar')
        creation_date = attrs.get('creation_date')
        
        # 从whois文本中提取更多信息
        registrant_phone = None
        registrant_email = None
        registrant_name = None
        registrant_organization = None
        registrant_city = None
        registrant_country = None
        expiration_date = None
        name_servers = []
        
        if whois_text:
            lines = whois_text.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('Registrant Phone:'):
                    registrant_phone = line.split(':', 1)[1].strip()
                elif line.startswith('Registrant Email:'):
                    registrant_email = line.split(':', 1)[1].strip()
                elif line.startswith('Registrant Name:'):
                    registrant_name = line.split(':', 1)[1].strip()
                elif line.startswith('Registrant Organization:'):
                    registrant_organization = line.split(':', 1)[1].strip()
                elif line.startswith('Registrant City:'):
                    registrant_city = line.split(':', 1)[1].strip()
                elif line.startswith('Registrant Country:'):
                    registrant_country = line.split(':', 1)[1].strip()
                elif line.startswith('Registry Expiry Date:'):
                    expiration_date = line.split(':', 1)[1].strip()
                elif line.startswith('Name Server:'):
                    ns = line.split(':', 1)[1].strip()
                    if ns:
                        name_servers.append(ns)
        
        return WhoisInfo(
            registrar=registrar,
            creation_date=creation_date,
            registrant_phone=registrant_phone,
            registrant_email=registrant_email,
            registrant_name=registrant_name,
            registrant_organization=registrant_organization,
            registrant_city=registrant_city,
            registrant_country=registrant_country,
            expiration_date=expiration_date,
            name_servers=name_servers
        )
        
    except Exception:
        return WhoisInfo()


def _extract_vt_certificate(vt_data: dict) -> CertificateInfo:
    """从VT数据中提取证书信息"""
    try:
        attrs = vt_data.get('data', {}).get('attributes', {})
        cert_data = attrs.get('last_https_certificate', {})
        
        if not cert_data:
            return CertificateInfo()
        
        subject = cert_data.get('subject', {})
        issuer = cert_data.get('issuer', {})
        validity = cert_data.get('validity', {})
        
        subject_cn = subject.get('CN') if isinstance(subject, dict) else None
        issuer_str = issuer.get('CN') if isinstance(issuer, dict) else str(issuer) if issuer else None
        
        # 处理SAN
        san_list = []
        extensions = cert_data.get('extensions', {})
        san_data = extensions.get('subject_alternative_name', [])
        if isinstance(san_data, list):
            san_list = [str(san) for san in san_data if san]
        
        return CertificateInfo(
            subject_cn=subject_cn,
            issuer=issuer_str,
            serial_number=cert_data.get('serial_number'),
            fingerprint_sha256=cert_data.get('thumbprint_sha256'),
            valid_not_before=validity.get('not_before') if isinstance(validity, dict) else None,
            valid_not_after=validity.get('not_after') if isinstance(validity, dict) else None,
            signature_algorithm=cert_data.get('cert_signature', {}).get('signature_algorithm') if isinstance(cert_data.get('cert_signature'), dict) else None,
            subject_alternative_names=san_list
        )
        
    except Exception:
        return CertificateInfo()


def _extract_vt_data(indicator: str, vt_data: dict) -> StandardURLData:
    """从VT原始数据中提取标准化数据结构"""
    try:
        return StandardURLData(
            indicator=indicator,
            threat_tags=_extract_vt_threat_tags(vt_data),
            subdomains=_extract_vt_subdomains(vt_data),
            related_samples=_extract_vt_related_samples(vt_data),
            passive_dns=_extract_vt_passive_dns(vt_data),
            whois=_extract_vt_whois(vt_data),
            certificate=_extract_vt_certificate(vt_data),
            source_engines=['VirusTotal']
        )
    except Exception:
        return StandardURLData(indicator=indicator, source_engines=['VirusTotal'])


def _debug(msg: str) -> None:
    try:
        if _is_debug_enabled():
            print(f"[urlgate][DEBUG] {msg}")
    except Exception:
        pass

def _http_get(url: str, headers: dict = None, params: dict = None, timeout: int = 30, verify: bool = True):
    try:
        _debug(f"GET {url} params={bool(params)} verify={verify}")
        r = requests.get(url, headers=headers or {}, params=params or {}, timeout=timeout, verify=verify)
        if r.status_code != 200:
            _debug(f"GET {url} -> HTTP {r.status_code}")
            return None, {"http_status": r.status_code, "text": r.text}
        try:
            return r, r.json()
        except Exception:
            _debug(f"GET {url} -> JSON 解析失败")
            return r, {"http_status": r.status_code, "text": r.text}
    except Exception as e:
        _debug(f"GET {url} 异常: {e}")
        return None, {"error": str(e)}

def _http_post(url: str, headers: dict = None, data: dict = None, files: dict = None, timeout: int = 30, verify: bool = True):
    try:
        _debug(f"POST {url} data={bool(data)} files={bool(files)} verify={verify}")
        r = requests.post(url, headers=headers or {}, data=data or {}, files=files, timeout=timeout, verify=verify)
        if r.status_code != 200:
            _debug(f"POST {url} -> HTTP {r.status_code}")
            return None, {"http_status": r.status_code, "text": r.text}
        try:
            return r, r.json()
        except Exception:
            _debug(f"POST {url} -> JSON 解析失败")
            return r, {"http_status": r.status_code, "text": r.text}
    except Exception as e:
        _debug(f"POST {url} 异常: {e}")
        return None, {"error": str(e)}

def _normalize_creation_date(value):
    try:
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, (int, float)):
            import datetime as _dt
            return _dt.datetime.utcfromtimestamp(int(value)).strftime('%Y-%m-%dT%H:%M:%SZ')
    except Exception:
        pass
    return value

def _parse_whois_fields_from_text(whois_text: str) -> dict:
    fields = {
        "Registrar": None,
        "Creation Date": None,
        "Registrant Phone": None,
        "Registrant Email": None,
        "Registrar Abuse Contact Email": None,
        # 追加字段（按用户要求）
        "Registrant Fax Ext": None,
        "Registrant Fax": None,
        "Registrant Name": None,
        "Registrant Organization": None,
        "Registrant Phone Ext": None,
        "Registrant City": None,
        "Registrant Country": None,
    }
    try:
        import re as _re
        if not whois_text:
            return {k: v for k, v in fields.items() if v}
        m = _re.search(r"^\s*Registrar:\s*(.+)$", whois_text, _re.I | _re.M)
        if m:
            fields["Registrar"] = m.group(1).strip()
        m = _re.search(r"^\s*Creation Date:\s*([0-9T:\-.Z]+)\s*$", whois_text, _re.I | _re.M)
        if m:
            fields["Creation Date"] = m.group(1).strip()
        m = _re.search(r"Registrar Abuse Contact Email:\s*([^\r\n]+)", whois_text, _re.I)
        if m:
            fields["Registrar Abuse Contact Email"] = m.group(1).strip()
        m = _re.search(r"Registrant Phone:\s*([^\r\n]+)", whois_text, _re.I)
        if m:
            fields["Registrant Phone"] = m.group(1).strip()
        m = _re.search(r"Registrant Email:\s*([^\r\n]+)", whois_text, _re.I)
        if m:
            fields["Registrant Email"] = m.group(1).strip()
        # 新增解析项
        m = _re.search(r"Registrant Fax Ext:\s*([^\r\n]+)", whois_text, _re.I)
        if m:
            fields["Registrant Fax Ext"] = m.group(1).strip()
        m = _re.search(r"Registrant Fax:\s*([^\r\n]+)", whois_text, _re.I)
        if m:
            fields["Registrant Fax"] = m.group(1).strip()
        m = _re.search(r"Registrant Name:\s*([^\r\n]+)", whois_text, _re.I)
        if m:
            fields["Registrant Name"] = m.group(1).strip()
        m = _re.search(r"Registrant Organization:\s*([^\r\n]+)", whois_text, _re.I)
        if m:
            fields["Registrant Organization"] = m.group(1).strip()
        m = _re.search(r"Registrant Phone Ext:\s*([^\r\n]+)", whois_text, _re.I)
        if m:
            fields["Registrant Phone Ext"] = m.group(1).strip()
        m = _re.search(r"Registrant City:\s*([^\r\n]+)", whois_text, _re.I)
        if m:
            fields["Registrant City"] = m.group(1).strip()
        m = _re.search(r"Registrant Country:\s*([^\r\n]+)", whois_text, _re.I)
        if m:
            fields["Registrant Country"] = m.group(1).strip()
    except Exception:
        pass
    return {k: v for k, v in fields.items() if v}

def _rebuild_vt_whois_from_cached(vt_cached: dict) -> dict:
    try:
        attrs = ((vt_cached.get('domain_report_from_url') or {}).get('data') or {}).get('attributes')
        if not isinstance(attrs, dict):
            attrs = ((vt_cached.get('domain_report') or {}).get('data') or {}).get('attributes')
        if not isinstance(attrs, dict):
            return {}
        whois_text = str(attrs.get('whois') or '')
        parsed = _parse_whois_fields_from_text(whois_text)
        registrar = parsed.get('Registrar') or attrs.get('registrar')
        creation = parsed.get('Creation Date') or _normalize_creation_date(attrs.get('creation_date'))
        phone = parsed.get('Registrant Phone')
        email = parsed.get('Registrant Email')
        out = {
            'Registrar': registrar,
            'Creation Date': creation,
            'Registrant Phone': phone,
            'Registrant Email': email,
            'Registrar Abuse Contact Email': parsed.get('Registrar Abuse Contact Email'),
        }
        return {k: v for k, v in out.items() if v}
    except Exception:
        return {}

def _extract_last_https_cert_from_attrs(attrs: dict) -> dict:
    try:
        if not isinstance(attrs, dict):
            return {}
        cert = attrs.get('last_https_certificate') or {}
        if not isinstance(cert, dict):
            return {}
        subject = (cert.get('subject') or {})
        issuer = (cert.get('issuer') or {})
        out = {
            'subject_cn': subject.get('CN') or subject.get('cn') or subject.get('common_name'),
            'issuer': issuer if isinstance(issuer, str) else (issuer.get('CN') or issuer.get('O') or issuer.get('organizationName') or str(issuer) if issuer else None),
            'valid_not_before': (cert.get('validity') or {}).get('not_before') or (cert.get('validity') or {}).get('not_before_timestamp'),
            'valid_not_after': (cert.get('validity') or {}).get('not_after') or (cert.get('validity') or {}).get('not_after_timestamp'),
            'serial_number': cert.get('serial_number') or cert.get('serialNumber'),
            'fingerprint_sha256': cert.get('sha256') or ((cert.get('thumbprint') or {}) if isinstance(cert.get('thumbprint'), dict) else {}).get('sha256'),
        }
        return {k: v for k, v in out.items() if v}
    except Exception:
        return {}

def _extract_vt_certificate_fields(attrs: dict) -> dict:
    cert_raw = _extract_last_https_cert_from_attrs(attrs)
    if not cert_raw:
        return {}
    # Signature Algorithm 来源：attributes.last_https_certificate.cert_signature.signature_algorithm
    sig_alg = None
    try:
        sig_alg = (attrs.get('last_https_certificate') or {}).get('cert_signature', {}).get('signature_algorithm')
    except Exception:
        sig_alg = None
    # Issuer 组装为 C=..  O=..  CN=..
    issuer = cert_raw.get('issuer')
    if isinstance(issuer, dict):
        parts = []
        if issuer.get('C'):
            parts.append(f"C={issuer.get('C')}")
        if issuer.get('O'):
            parts.append(f"O={issuer.get('O')}")
        if issuer.get('CN'):
            parts.append(f"CN={issuer.get('CN')}")
        issuer = '  '.join(parts) if parts else str(issuer)
    # Subject: 仅 CN
    subject = None
    try:
        sub = (attrs.get('last_https_certificate') or {}).get('subject') or {}
        cn = sub.get('CN') or sub.get('commonName')
        if cn:
            subject = f"CN={cn}"
    except Exception:
        pass
    # 组织为带 Validity 嵌套的结构，便于下游通用解析
    out = {
        'Signature Algorithm': sig_alg,
        'Issuer': issuer,
        'Validity': {
            'Not Before': _fmt_time_field(cert_raw.get('valid_not_before')),
            'Not After': _fmt_time_field(cert_raw.get('valid_not_after')),
        },
        'Not Before': _fmt_time_field(cert_raw.get('valid_not_before')),  # 兼容平铺读取
        'Not After': _fmt_time_field(cert_raw.get('valid_not_after')),     # 兼容平铺读取
        'Subject': subject,
    }
    return {k: v for k, v in out.items() if v}

def _save_vt_details(indicator: str, kind: str, payload: Dict[str, Any]) -> None:
    try:
        out_dir = _ensure_url_tmp_dir()
        safe_indicator = _filename_from_indicator(indicator)
        name = f"vt_{kind}_details_{safe_indicator}.json"
        fp = os.path.join(out_dir, name)
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def _extract_from_vt_url_raw(raw_url: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        attrs = (raw_url.get('data') or {}).get('attributes') or {}
        # 证书
        cert = _extract_vt_certificate_fields(attrs)
        if cert:
            out['certificate'] = cert
    except Exception:
        pass
    try:
        rels = raw_url.get('relationships') or {}
        files = []
        for rel_name in ('referrer_files', 'contacted_files', 'downloaded_files'):
            rj = rels.get(rel_name) or {}
            for it in (rj.get('data') or [])[:20]:
                fid = (it or {}).get('id')
                if fid:
                    files.append(str(fid))
        if files:
            out['files_referring'] = list(dict.fromkeys(files))[:20]
    except Exception:
        pass
    return out

def _extract_from_vt_domain_raw(raw_domain: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        attrs = (raw_domain.get('data') or {}).get('attributes') or {}
        # whois
        whois_text = str(attrs.get('whois') or '')
        parsed = _parse_whois_fields_from_text(whois_text)
        whois = {
            'Registrar': parsed.get('Registrar') or attrs.get('registrar'),
            'Creation Date': parsed.get('Creation Date') or _normalize_creation_date(attrs.get('creation_date')),
            'Registrant Phone': parsed.get('Registrant Phone'),
            'Registrant Email': parsed.get('Registrant Email'),
            'Registrar Abuse Contact Email': parsed.get('Registrar Abuse Contact Email'),
        }
        whois = {k: v for k, v in whois.items() if v}
        if whois:
            out['whois'] = whois
        # 证书
        cert = _extract_vt_certificate_fields(attrs)
        if cert:
            out['certificate'] = cert
    except Exception:
        pass
    try:
        rels = raw_domain.get('relationships') or {}
        subs = []
        for it in (rels.get('subdomains', {}).get('data') or [])[:200]:
            sid = (it or {}).get('id')
            if sid:
                subs.append(str(sid))
        if subs:
            out['siblings'] = list(dict.fromkeys(subs))
    except Exception:
        pass
    return out

def _ensure_url_tmp_dir() -> str:
    """确保 URL/域名缓存目录存在。按用户要求使用固定绝对路径。"""
    # 改为基于包目录（与 THuntPro.py 同级的 url_tmp）
    base_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "url_tmp")
    try:
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
    except Exception:
        pass
    return base_dir


def _safe_name(text: str) -> str:
    return re.sub(r"[^\w\-\.]", "_", text)[:150]


def _filename_from_indicator(indicator: str) -> str:
    """根据查询值生成更友好的文件名：
    - URL: 使用 host + 路径（不含协议），路径斜杠替换为下划线，去除结尾斜杠
    - 其他：原样清洗
    """
    try:
        if re.match(r"^https?://", indicator, re.I):
            from urllib.parse import urlparse
            p = urlparse(indicator)
            host = p.hostname or ""
            path = (p.path or "").rstrip("/")
            if path and path != "/":
                base = f"{host}{path.replace('/', '_')}"
            else:
                base = host or indicator
            return _safe_name(base)
        return _safe_name(indicator)
    except Exception:
        return _safe_name(indicator)


def _load_url_json(engine_name: str, indicator: str, max_age_days: int = 30) -> Dict[str, Any]:
    """加载稳定缓存文件（未过期则返回 JSON，否则返回空 dict）。"""
    try:
        out_dir = _ensure_url_tmp_dir()
        safe_indicator = _filename_from_indicator(indicator)
        fp = os.path.join(out_dir, f"{engine_name.lower()}_{safe_indicator}.json")
        if not os.path.isfile(fp):
            return {}
        mtime = os.path.getmtime(fp)
        if (time.time() - mtime) > (max_age_days * 24 * 3600):
            return {}
        with open(fp, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _load_combined_cache(indicator: str, max_age_days: int = 30) -> Dict[str, Any]:
    """加载整合缓存（整条结果 out）——每个域名/URL 只查询一次，30 天有效。"""
    try:
        out_dir = _ensure_url_tmp_dir()
        safe_indicator = _safe_name(indicator)
        fp = os.path.join(out_dir, f"combined_{safe_indicator}.json")
        if not os.path.isfile(fp):
            return {}
        mtime = os.path.getmtime(fp)
        if (time.time() - mtime) > (max_age_days * 24 * 3600):
            return {}
        with open(fp, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_combined_cache(indicator: str, out_obj: Dict[str, Any]) -> None:
    """保存整合缓存（整条结果 out）——覆盖写入稳定文件。"""
    try:
        out_dir = _ensure_url_tmp_dir()
        safe_indicator = _safe_name(indicator)
        fp = os.path.join(out_dir, f"combined_{safe_indicator}.json")
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(out_obj, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _clear_old_url_cache(days: int = 30) -> None:
    """清理 url_tmp 目录中超过 days 天的旧缓存（按 mtime）。"""
    try:
        out_dir = _ensure_url_tmp_dir()
        now = time.time()
        cutoff = now - days * 24 * 3600
        for name in os.listdir(out_dir):
            if not name.endswith('.json'):
                continue
            fp = os.path.join(out_dir, name)
            try:
                if os.path.isfile(fp) and os.path.getmtime(fp) < cutoff:
                    os.remove(fp)
            except Exception:
                pass
    except Exception:
        pass


def save_url_json(indicator: str, engine_name: str, data: Dict[str, Any]) -> None:
    """保存 URL/域名查询原始 JSON 到 url_tmp，仅使用稳定文件名（不生成时间戳副本）。"""
    try:
        out_dir = _ensure_url_tmp_dir()
        safe_indicator = _filename_from_indicator(indicator)
        stable = os.path.join(out_dir, f"{engine_name.lower()}_{safe_indicator}.json")
        with open(stable, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _is_ip(indicator: str) -> bool:
    return re.fullmatch(r"(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))(?:\\.(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))){3}", indicator) is not None


def _build_vt_session() -> tuple:
    """构造带重试的 VT 会话。通过环境变量 VT_VERIFY=0 可关闭证书校验。"""
    s = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504))
    adapter = HTTPAdapter(max_retries=retries)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    verify = os.environ.get("VT_VERIFY", "1") not in {"0", "false", "False"}
    return s, verify

def _tb_domain_query_raw(domain: str, api_key: str) -> Dict[str, Any]:
    """ThreatBook v3 域名查询（/v3/domain/query），尽量原样返回原始数据。
    文档参考: https://x.threatbook.com/v5/apiDocs#/domain/query
    实际调用: https://api.threatbook.cn/v3/domain/query?apikey=...&resource=...
    """
    try:
        if not domain or not api_key:
            return {"source": "ThreatBook", "hit": False, "error": "no domain or api key"}
        url = "https://api.threatbook.cn/v3/domain/query"
        exclude = os.environ.get("THREATBOOK_EXCLUDE", "")
        lang = os.environ.get("THREATBOOK_LANG", "zh")
        params = {"apikey": api_key, "resource": domain, "lang": lang}
        if exclude:
            params["exclude"] = exclude
        headers = {"Accept": "application/json"}
        # 优先 GET
        js: Dict[str, Any] = {}
        r = requests.get(url, params=params, headers=headers, timeout=30)
        if r.status_code == 200:
            try:
                js = r.json()
            except Exception:
                js = {"http_status": r.status_code, "text": r.text}
        else:
            js = {"http_status": r.status_code, "text": r.text}
        # 若提示 No Access 或非成功，再尝试 POST
        try_post = (not isinstance(js, dict)) or (js.get("response_code") in (-1, -2))
        if try_post:
            rp = requests.post(url, data=params, headers=headers, timeout=30)
            if rp.status_code == 200:
                try:
                    js = rp.json()
                except Exception:
                    js = {"http_status": rp.status_code, "text": rp.text}
            else:
                js = {"http_status": rp.status_code, "text": rp.text}
        # v3 返回 data 为以 domain 为 key 的对象
        data_obj = {}
        try:
            data_obj = (js.get("data") or {}).get(domain) or {}
        except Exception:
            data_obj = {}
        hit = bool(isinstance(js, dict) and js.get("response_code") == 0 and isinstance(data_obj, dict) and data_obj)
        return {
            "source": "ThreatBook",
            "hit": hit,
            "raw": js,
        }
    except Exception as e:
        return {"source": "ThreatBook", "hit": False, "error": str(e)}


def query_url_or_domain(indicator: str, apis: Dict[str, str]) -> Dict[str, Any]:
    """URL/域名专用聚合查询 - 使用标准化数据结构"""
    
    # 检查是否为IP地址，如果是则返回空结果
    if re.fullmatch(r"(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))(?:\\.(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))){3}", indicator) is not None:
        return {"indicator": indicator, "results": [], "apis": apis, "ioc": {"ips": [], "domains": [], "urls": [], "hashes": []}}
    
    # 尝试加载所有引擎的缓存
    cached_engines = _load_all_engine_caches(indicator, 30)
    
    # 创建初始的标准化数据结构
    standard_data = StandardURLData(indicator=indicator)
    
    # 存储查询结果用于后续展示
    hit_results = []
    miss_results = []
    
    # VirusTotal查询（主要数据源）
    vtapi = apis.get("VIRUSTOTAL") or ""
    if vtapi:
        try:
            if "virustotal" in cached_engines:
                vt_data = cached_engines["virustotal"]
                hit_results.append({"source": "VirusTotal", "hit": True, "cached": True})
            else:
                vt_data = _query_virustotal(indicator, vtapi)
                if vt_data:
                    _save_engine_cache(indicator, "virustotal", vt_data)
                    hit_results.append({"source": "VirusTotal", "hit": True, "cached": False})
                else:
                    miss_results.append({"source": "VirusTotal", "hit": False})
            
            if vt_data:
                vt_standard = _extract_vt_data(indicator, vt_data)
                standard_data = _merge_standard_data(standard_data, vt_standard)
        except Exception as e:
            miss_results.append({"source": "VirusTotal", "hit": False})
            _debug(f"VirusTotal查询失败: {e}")
    
    # AlienVault查询（作为补充数据源）
    avapi = apis.get("ALIENVAULT") or ""
    if avapi:
        try:
            if "alienvault" in cached_engines:
                av_data = cached_engines["alienvault"]
                hit_results.append({"source": "AlienVault", "hit": True, "cached": True})
            else:
                av_data = _query_alienvault(indicator, avapi)
                if av_data:
                    _save_engine_cache(indicator, "alienvault", av_data)
                    hit_results.append({"source": "AlienVault", "hit": True, "cached": False})
                else:
                    miss_results.append({"source": "AlienVault", "hit": False})
            
            if av_data:
                av_standard = _extract_alienvault_data(indicator, av_data)
                standard_data = _merge_standard_data(standard_data, av_standard)
        except Exception as e:
            miss_results.append({"source": "AlienVault", "hit": False})
            _debug(f"AlienVault查询失败: {e}")
    
    # ThreatFox查询（作为补充数据源）
    tfapi = apis.get("THREATFOX") or ""
    if tfapi:
        try:
            if "threatfox" in cached_engines:
                tf_data = cached_engines["threatfox"]
                hit_results.append({"source": "ThreatFox", "hit": True, "cached": True})
            else:
                tf_data = _query_threatfox(indicator, tfapi)
                if tf_data:
                    _save_engine_cache(indicator, "threatfox", tf_data)
                    hit_results.append({"source": "ThreatFox", "hit": True, "cached": False})
                else:
                    miss_results.append({"source": "ThreatFox", "hit": False})
            
            if tf_data:
                tf_standard = _extract_threatfox_data(indicator, tf_data)
                standard_data = _merge_standard_data(standard_data, tf_standard)
        except Exception as e:
            miss_results.append({"source": "ThreatFox", "hit": False})
            _debug(f"ThreatFox查询失败: {e}")
    
    # URLHaus查询
    try:
        if "urlhaus" in cached_engines:
            uh_data = cached_engines["urlhaus"]
            hit_results.append({"source": "URLHaus", "hit": True, "cached": True})
        else:
            uh_data = _query_urlhaus(indicator)
            if uh_data:
                _save_engine_cache(indicator, "urlhaus", uh_data)
                hit_results.append({"source": "URLHaus", "hit": True, "cached": False})
            else:
                miss_results.append({"source": "URLHaus", "hit": False})
        
        if uh_data:
            uh_standard = _extract_urlhaus_data(indicator, uh_data)
            standard_data = _merge_standard_data(standard_data, uh_standard)
    except Exception as e:
        miss_results.append({"source": "URLHaus", "hit": False})
        _debug(f"URLHaus查询失败: {e}")
    
    # HybridAnalysis 查询禁用（URL 模式）
    # 保留占位注释，防止未来误用
    
    # 显示查询结果 - 只显示命中的引擎
    for r in hit_results:
        src = r.get("source")
        if r.get("cached"):
            print(f"📦 {src}: 使用缓存")
        else:
            print(f"✅ {src}: 命中")
    
    # 保存标准化缓存
    _save_standard_cache(indicator, standard_data, "virustotal")
    
    # 转换为传统格式以保持兼容性
    out = _standard_data_to_legacy_format(standard_data, apis)
    
    # 添加未命中结果到输出中
    out['miss_results'] = miss_results
    
    return out

    out: Dict[str, Any] = {"indicator": indicator, "results": [], "apis": apis}

    # 清理过期缓存
    _clear_old_url_cache(30)

    # 仅处理 URL/域名，IP 直接返回空结果（由 THuntPro 决定走原聚合）
    is_url = bool(re.match(r"^https?://", indicator, re.I))
    if _is_ip(indicator):
        out["results"] = []
        return out

    # ThreatFox：URL 取 host 再查；域名直接查（并行 host/apex）
    tfapi = apis.get("THREATFOX") or ""
    host_for_tf = indicator
    if is_url:
        try:
            from urllib.parse import urlparse
            host_for_tf = urlparse(indicator).hostname or indicator
        except Exception:
            pass
    # ThreatFox 仅在 URL 查询时启用
    if is_url and tfapi and host_for_tf:
        try:
            # ThreatFox: 缓存优先
            cached_tf = _load_url_json("threatfox", indicator)
            if cached_tf:
                try:
                    print("📦 使用 ThreatFox 缓存数据")
                except Exception:
                    pass
                out["results"].append({"source": "ThreatFox", "hit": True, "raw": cached_tf})
            else:
                candidates: List[Dict[str, Any]] = []
            apex = ""
            try:
                parts = (host_for_tf or "").split('.')
                if len(parts) >= 2:
                    apex = '.'.join(parts[-2:])
            except Exception:
                apex = ""
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
                futs = [ex.submit(threatfox_multi_lookup, host_for_tf, tfapi)]
                if apex and apex != host_for_tf:
                    futs.append(ex.submit(threatfox_multi_lookup, apex, tfapi))
                for f in concurrent.futures.as_completed(futs):
                    try:
                        r = f.result()
                        if isinstance(r, dict):
                            candidates.append(r)
                    except Exception:
                        pass
            chosen = None
            for r in candidates:
                if r.get("hit"):
                    chosen = r
                    break
            if not chosen and candidates:
                chosen = candidates[0]
            if chosen:
                out["results"].append(chosen)
                raw = chosen.get("raw") or {}
                if raw:
                    save_url_json(indicator, "threatfox", raw)
            # 附加：最近 7 天 IOC（仅缓存附加数据，不改变命中）
            try:
                r = requests.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    headers={"Content-Type": "application/json"},
                    data=json.dumps({"query": "get_iocs", "days": 7}),
                    timeout=30,
                )
                js = r.json() if r.status_code == 200 else {}
                if js:
                    save_url_json(indicator, "threatfox_recent7d", js)
            except Exception:
                pass
        except Exception:
            pass

    # VirusTotal（增强：URL report 与更多 relationships，参考官方文档）
    vtapi = apis.get("VIRUSTOTAL") or ""
    if vtapi:
        try:
            # VirusTotal: 缓存优先
            cached_vt = _load_url_json("virustotal", indicator)
            if cached_vt:
                try:
                    print("📦 使用 VirusTotal 缓存数据")
                except Exception:
                    pass
                # 从缓存中提取 IOC
                urls: List[str] = [indicator] if is_url else []
                domains: List[str] = []
                ips: List[str] = []
                rels = (cached_vt.get("relationships") or {})
                for rel, body in rels.items():
                    for it in (body.get("data") or []):
                        if rel in ("contacted_ips", "last_serving_ip_address"):
                            ip = (it.get("attributes") or {}).get("ip_address") or it.get("id")
                            if ip:
                                ips.append(ip)
                        elif rel == "contacted_domains":
                            dom = it.get("id")
                            if dom:
                                domains.append(dom)
                vt_summary = cached_vt.get("summary") or {}
                # 从缓存 relationships 提取相关样本、子域名、历史解析，补全 summary
                try:
                    related_files: List[str] = []
                    for rel_name in ("contacted_files", "referrer_files", "downloaded_files"):
                        rj = (rels.get(rel_name) or {})
                        for it in (rj.get("data") or [])[:20]:
                            fid = (it or {}).get("id")
                            if fid:
                                related_files.append(str(fid))
                    if related_files:
                        vt_summary = dict(vt_summary)
                        vt_summary.setdefault("相关样本(前20)", list(dict.fromkeys(related_files))[:20])
                except Exception:
                    pass
                try:
                    subs = []
                    for it in ((rels.get("subdomains") or {}).get("data") or [])[:200]:
                        sid = (it or {}).get("id")
                        if sid:
                            subs.append(str(sid))
                    if subs:
                        vt_summary = dict(vt_summary)
                        vt_summary.setdefault("子域名", list(dict.fromkeys(subs)))
                except Exception:
                    pass
                try:
                    p_dns = []
                    for key in ("resolutions", "resolutions_for_host"):
                        for it in ((rels.get(key) or {}).get("data") or [])[:200]:
                            ip = ((it or {}).get("attributes") or {}).get("ip_address") or (it or {}).get("id")
                            if ip:
                                p_dns.append(str(ip))
                    if p_dns:
                        vt_summary = dict(vt_summary)
                        vt_summary.setdefault("历史解析/PassiveDNS", list(dict.fromkeys(p_dns)))
                except Exception:
                    pass
                try:
                    rebuilt = _rebuild_vt_whois_from_cached(cached_vt)
                    if rebuilt:
                        vt_summary = dict(vt_summary)
                        vt_summary["Whois"] = rebuilt
                except Exception:
                    pass
                # 证书信息（来自缓存）
                try:
                    cert = _extract_last_https_cert_from_attrs(((cached_vt.get('url_report') or {}).get('data') or {}).get('attributes') or {})
                    if not cert:
                        cert = _extract_last_https_cert_from_attrs(((cached_vt.get('domain_report_from_url') or {}).get('data') or {}).get('attributes') or {})
                    if not cert:
                        cert = _extract_last_https_cert_from_attrs(((cached_vt.get('domain_report') or {}).get('data') or {}).get('attributes') or {})
                    if cert:
                        vt_summary = dict(vt_summary)
                        vt_summary["证书"] = cert
                except Exception:
                    pass
                out["results"].append({
                    "source": "VirusTotal",
                    "hit": bool(urls or domains or ips),
                    "ioc": {
                        "ips": list(dict.fromkeys(ips)),
                        "domains": list(dict.fromkeys(domains)),
                        "urls": list(dict.fromkeys(urls)),
                    },
                    "summary": vt_summary or None
                })
            else:
                headers = {"x-apikey": vtapi}
            urls: List[str] = []
            domains: List[str] = []
            ips: List[str] = []
            vt_hit = False
            raw = {}
            if is_url:
                create = requests.post("https://www.virustotal.com/api/v3/urls", params=None, data={"url": indicator}, headers=headers, timeout=30)
                cj = {}
                try:
                    cj = create.json()
                except Exception:
                    cj = {}
                rid = (cj.get("data") or {}).get("id")
                if not rid:
                    # 回退使用统一工具方法计算 VT URL ID
                    try:
                        from utils.utils import compute_vt_url_id
                        rid = compute_vt_url_id(indicator)
                    except Exception:
                        rid = None
                if rid:
                    vt_hit = True
                    # 主报告
                    try:
                        s, verify = _build_vt_session()
                        urpt = s.get(f"https://www.virustotal.com/api/v3/urls/{rid}", headers=headers, timeout=30, verify=verify)
                        raw_url = urpt.json() if urpt.status_code == 200 else {"http_status": urpt.status_code}
                        raw["url_report"] = raw_url
                        # 基于 VT 数据构建分类化 summary 模版
                        try:
                            attrs = (raw_url.get("data") or {}).get("attributes") or {}
                            summary = {
                                "基本信息": {
                                    "规范化URL": attrs.get("url"),
                                    "最后分析时间": attrs.get("last_analysis_date"),
                                    "最后提交时间": attrs.get("last_submission_date"),
                                    "威胁评分(判定数)": f"{attrs.get('last_analysis_stats', {}).get('malicious', 0)} / {sum((attrs.get('last_analysis_stats') or {}).values() or [0])}",
                                },
                                "引擎判定": {
                                    # 仅列出非 clean/unrated 的结果
                                    "命中列表": [
                                        f"{eng}: {res.get('result')}" for eng, res in (attrs.get("last_analysis_results") or {}).items()
                                        if isinstance(res, dict) and res.get("result") and res.get("result") not in ("clean", "unrated")
                                    ][:50],
                                },
                                "网络要素": {
                                    "最后服务IP": attrs.get("last_serving_ip_address"),
                                    "网络位置": attrs.get("network_location"),
                                    "TLS": (attrs.get("last_https_certificate") or {}).get("issuer"),
                                },
                                "关联对象概览": {
                                    "联系到的域名数": None,
                                    "联系到的IP数": None,
                                },
                                "威胁标签": [],
                                "子域名": [],
                                "相关样本(前20)": [],
                                "历史解析/PassiveDNS": [],
                                "Whois": {}
                            }
                            # 标签（tags、categories、引擎结果）
                            try:
                                tag_list = []
                                t1 = attrs.get("tags") or []
                                if isinstance(t1, list):
                                    tag_list.extend([str(x) for x in t1 if x])
                                cats = attrs.get("categories") or {}
                                if isinstance(cats, dict):
                                    tag_list.extend([str(k) for k in cats.keys() if k])
                                for eng, res in (attrs.get("last_analysis_results") or {}).items():
                                    if isinstance(res, dict) and res.get("result") and res.get("result") not in ("clean", "unrated"):
                                        tag_list.append(str(res.get("result")))
                                if tag_list:
                                    summary["威胁标签"] = list(dict.fromkeys(tag_list))[:100]
                            except Exception:
                                pass
                            # 统计 relationships 简要数量（若稍后已获取）
                            rels = raw.get("relationships") or {}
                            ci = (rels.get("contacted_ips") or {}).get("data") or []
                            cd = (rels.get("contacted_domains") or {}).get("data") or []
                            summary["关联对象概览"]["联系到的域名数"] = len(cd)
                            summary["关联对象概览"]["联系到的IP数"] = len(ci)
                            # 证书（规整字段）
                            try:
                                cert = _extract_vt_certificate_fields(attrs)
                                if cert:
                                    summary["证书"] = cert
                            except Exception:
                                pass
                            raw["summary"] = summary
                        except Exception:
                            pass
                    except Exception:
                        pass
                    # 关系接口部分账号会 403；尽量容错，仅尝试常见可用项
                    for rel in ("contacted_ips", "contacted_domains"):
                        try:
                            rr = requests.get(f"https://www.virustotal.com/api/v3/urls/{rid}/relationships/{rel}", headers=headers, timeout=30)
                            if rr.status_code == 200:
                                rj = rr.json()
                                raw.setdefault("relationships", {})[rel] = rj
                                for it in rj.get("data", []) or []:
                                    if rel == "contacted_ips":
                                        ip = (it.get("attributes") or {}).get("ip_address") or it.get("id")
                                        if ip:
                                            ips.append(ip)
                                    else:
                                        dom = it.get("id")
                                        if dom:
                                            domains.append(dom)
                            else:
                                # 403/404 等直接记录状态码，不中断
                                raw.setdefault("relationships", {})[rel] = {"http_status": rr.status_code}
                        except Exception:
                            pass
                    # 相关样本（前20）：优先 referrer_files，再补充 contacted_files/downloaded_files
                    try:
                        related_files = []
                        for rel_name in ("referrer_files", "contacted_files", "downloaded_files"):
                            try:
                                rr = requests.get(f"https://www.virustotal.com/api/v3/urls/{rid}/relationships/{rel_name}", headers=headers, timeout=30)
                                if rr.status_code == 200:
                                    rj = rr.json()
                                    raw.setdefault("relationships", {})[rel_name] = rj
                                    for it in (rj.get("data") or [])[:20]:
                                        fid = it.get("id")
                                        if fid:
                                            related_files.append(fid)
                                else:
                                    raw.setdefault("relationships", {})[rel_name] = {"http_status": rr.status_code}
                            except Exception:
                                pass
                        if related_files:
                            raw.setdefault("summary", {})
                            raw["summary"]["相关样本(前20)"] = list(dict.fromkeys(related_files))[:20]
                    except Exception:
                        pass
                    # 从 URL 提取 host，用域名接口补充：子域名、PassiveDNS、Whois
                    try:
                        from urllib.parse import urlparse
                        host = urlparse(indicator).hostname or ""
                    except Exception:
                        host = ""
                    if host:
                        # Whois
                        try:
                            s, verify = _build_vt_session()
                            d_r = s.get(f"https://www.virustotal.com/api/v3/domains/{host}", headers=headers, timeout=30, verify=verify)
                            raw_domain = d_r.json() if d_r.status_code == 200 else {"http_status": d_r.status_code}
                            raw["domain_report_from_url"] = raw_domain
                            dattrs = (raw_domain.get("data") or {}).get("attributes") or {}
                            whois_text = str(dattrs.get("whois") or "")
                            parsed = _parse_whois_fields_from_text(whois_text)
                            registrar = parsed.get("Registrar") or dattrs.get("registrar")
                            creation_date = parsed.get("Creation Date") or _normalize_creation_date(dattrs.get("creation_date"))
                            registrant_phone = parsed.get("Registrant Phone")
                            registrant_email = parsed.get("Registrant Email")
                            raw.setdefault("summary", {})
                            raw["summary"]["Whois"] = {
                                "Registrar": registrar,
                                "Creation Date": creation_date,
                                "Registrant Phone": registrant_phone,
                                "Registrant Email": registrant_email,
                            }
                        except Exception:
                            pass
                        # 子域名
                        try:
                            s, verify = _build_vt_session()
                            rr = s.get(f"https://www.virustotal.com/api/v3/domains/{host}/relationships/subdomains", headers=headers, timeout=30, verify=verify)
                            if rr.status_code == 200:
                                rj = rr.json()
                                raw.setdefault("relationships", {})["subdomains"] = rj
                                subs = []
                                for it in (rj.get("data") or [])[:200]:
                                    sid = it.get("id")
                                    if sid:
                                        subs.append(sid)
                                if subs:
                                    raw.setdefault("summary", {})
                                    raw["summary"]["子域名"] = list(dict.fromkeys(subs))
                            else:
                                raw.setdefault("relationships", {})["subdomains"] = {"http_status": rr.status_code}
                        except Exception:
                            pass
                        # Passive DNS
                        try:
                            s, verify = _build_vt_session()
                            rr = s.get(f"https://www.virustotal.com/api/v3/domains/{host}/relationships/resolutions", headers=headers, timeout=30, verify=verify)
                            if rr.status_code == 200:
                                rj = rr.json()
                                raw.setdefault("relationships", {})["resolutions_for_host"] = rj
                                p_dns = []
                                for it in (rj.get("data") or [])[:200]:
                                    ip = (it.get("attributes") or {}).get("ip_address") or it.get("id")
                                    if ip:
                                        p_dns.append(ip)
                                if p_dns:
                                    raw.setdefault("summary", {})
                                    raw["summary"]["历史解析/PassiveDNS"] = list(dict.fromkeys(p_dns))
                            else:
                                raw.setdefault("relationships", {})["resolutions_for_host"] = {"http_status": rr.status_code}
                        except Exception:
                            pass
                    urls.append(indicator)
            else:
                # 域名：优先基本信息与 resolutions；避免受限的 urls/ip_addresses 关系
                try:
                    s, verify = _build_vt_session()
                    d_r = s.get(f"https://www.virustotal.com/api/v3/domains/{indicator}", headers=headers, timeout=30, verify=verify)
                    raw_domain = d_r.json() if d_r.status_code == 200 else {"http_status": d_r.status_code}
                    raw["domain_report"] = raw_domain
                    try:
                        _save_vt_details(indicator, 'domain', raw_domain)
                    except Exception:
                        pass
                    # 基于域名数据构建分类化 summary 模版
                    try:
                        attrs = (raw_domain.get("data") or {}).get("attributes") or {}
                        summary = {
                            "威胁标签": [],
                            "子域名": [],
                            "相关样本(前20)": [],
                            "历史解析/PassiveDNS": [],
                            "Whois": {}
                        }
                        # 标签: tags + categories key
                        tag_list = []
                        t1 = attrs.get("tags") or []
                        if isinstance(t1, list):
                            tag_list.extend([str(x) for x in t1 if x])
                        cats = attrs.get("categories") or {}
                        if isinstance(cats, dict):
                            tag_list.extend([str(k) for k in cats.keys() if k])
                        if tag_list:
                            summary["威胁标签"] = list(dict.fromkeys(tag_list))
                        # Whois: registrar/creation_date + 从 whois 文本提取电话/邮箱
                        whois_text = str(attrs.get("whois") or "")
                        parsed = _parse_whois_fields_from_text(whois_text)
                        registrar = parsed.get("Registrar") or attrs.get("registrar")
                        creation_date = parsed.get("Creation Date") or _normalize_creation_date(attrs.get("creation_date"))
                        registrant_phone = parsed.get("Registrant Phone")
                        registrant_email = parsed.get("Registrant Email")
                        summary["Whois"] = {
                            "Registrar": registrar,
                            "Creation Date": creation_date,
                            "Registrant Phone": registrant_phone,
                            "Registrant Email": registrant_email,
                        }
                        # 证书（从域名属性的 last_https_certificate 提取指定字段）
                        try:
                            cert = _extract_vt_certificate_fields(attrs)
                            if cert:
                                summary["证书"] = cert
                        except Exception:
                            pass
                        raw.setdefault("summary", {}).update(summary)
                    except Exception:
                        pass
                except requests.exceptions.SSLError as e:
                    raw["domain_report_error"] = {"ssl_error": str(e)}
                except Exception as e:
                    raw["domain_report_error"] = {"error": str(e)}
                try:
                    s, verify = _build_vt_session()
                    rr = s.get(f"https://www.virustotal.com/api/v3/domains/{indicator}/relationships/resolutions", headers=headers, timeout=30, verify=verify)
                    if rr.status_code == 200:
                        rj = rr.json()
                        raw.setdefault("relationships", {})["resolutions"] = rj
                        for it in rj.get("data", []) or []:
                            ip = (it.get("attributes") or {}).get("ip_address") or it.get("id")
                            host_name = (it.get("attributes") or {}).get("host_name")
                            if ip:
                                ips.append(ip)
                            if host_name:
                                urls.append(host_name)
                        # 填充 PassiveDNS 到 summary
                        try:
                            p_dns = []
                            for it in (rj.get("data") or [])[:200]:
                                ip = (it.get("attributes") or {}).get("ip_address") or it.get("id")
                                if ip:
                                    p_dns.append(ip)
                            if p_dns:
                                raw.setdefault("summary", {})
                                raw["summary"]["历史解析/PassiveDNS"] = list(dict.fromkeys(p_dns))
                        except Exception:
                            pass
                    else:
                        raw.setdefault("relationships", {})["resolutions"] = {"http_status": rr.status_code}
                except requests.exceptions.SSLError as e:
                    raw.setdefault("relationships", {})["resolutions_error"] = {"ssl_error": str(e)}
                except Exception as e:
                    raw.setdefault("relationships", {})["resolutions_error"] = {"error": str(e)}
                # 子域名（Siblings）
                try:
                    s, verify = _build_vt_session()
                    rr = s.get(f"https://www.virustotal.com/api/v3/domains/{indicator}/relationships/subdomains", headers=headers, timeout=30, verify=verify)
                    if rr.status_code == 200:
                        rj = rr.json()
                        raw.setdefault("relationships", {})["subdomains"] = rj
                        subs = []
                        for it in (rj.get("data") or [])[:200]:
                            sid = it.get("id")
                            if sid:
                                subs.append(sid)
                        if subs:
                            raw.setdefault("summary", {})
                            raw["summary"]["子域名"] = list(dict.fromkeys(subs))
                    else:
                        raw.setdefault("relationships", {})["subdomains"] = {"http_status": rr.status_code}
                except Exception:
                    pass
                # 相关样本（域名）
                try:
                    s, verify = _build_vt_session()
                    rr = s.get(f"https://www.virustotal.com/api/v3/domains/{indicator}/relationships/contacted_files", headers=headers, timeout=30, verify=verify)
                    if rr.status_code == 200:
                        rj = rr.json()
                        raw.setdefault("relationships", {})["contacted_files"] = rj
                        files = []
                        for it in (rj.get("data") or [])[:20]:
                            fid = it.get("id")
                            if fid:
                                files.append(fid)
                        if files:
                            raw.setdefault("summary", {})
                            raw["summary"]["相关样本(前20)"] = list(dict.fromkeys(files))[:20]
                    else:
                        raw.setdefault("relationships", {})["contacted_files"] = {"http_status": rr.status_code}
                except Exception:
                    pass

                # 相关样本（优先 Files Referring）：通过 URL 报告 relationships/referrer_files 获取
                try:
                    def _ref_files_for_url(u: str) -> list:
                        try:
                            s, verify = _build_vt_session()
                            cj = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": u}, headers=headers, timeout=30)
                            rid = ((cj.json() or {}).get("data") or {}).get("id") if cj.status_code == 200 else None
                            if not rid:
                                from utils.utils import compute_vt_url_id
                                rid = compute_vt_url_id(u)
                            if not rid:
                                return []
                            rr = s.get(f"https://www.virustotal.com/api/v3/urls/{rid}/relationships/referrer_files", headers=headers, timeout=30, verify=verify)
                            if rr.status_code == 200:
                                rj = rr.json()
                                # 落盘 url 明细，便于排查
                                try:
                                    _save_vt_details(indicator, 'url', rj)
                                except Exception:
                                    pass
                                return [ (it or {}).get('id') for it in (rj.get('data') or []) if (it or {}).get('id') ]
                            return []
                        except Exception:
                            return []
                    prefer = []
                    for scheme in ("http://", "https://"):
                        prefer.extend(_ref_files_for_url(f"{scheme}{indicator}"))
                    prefer = list(dict.fromkeys([str(x) for x in prefer]))[:20]
                    if prefer:
                        raw.setdefault("summary", {})
                        raw["summary"]["相关样本(前20)"] = prefer
                except Exception:
                    pass
                domains.append(indicator)

            out["results"].append({
                "source": "VirusTotal",
                "hit": bool(vt_hit or urls or domains or ips),
                "ioc": {
                    "ips": list(dict.fromkeys(ips)),
                    "domains": list(dict.fromkeys(domains)),
                    "urls": list(dict.fromkeys(urls)),
                }
            })
            if raw:
                try:
                    raw.setdefault("summary", {})
                    s = raw["summary"]
                    s.setdefault("威胁标签", [])
                    s.setdefault("子域名", [])
                    s.setdefault("相关样本(前20)", [])
                    s.setdefault("历史解析/PassiveDNS", [])
                    s.setdefault("Whois", {})
                except Exception:
                    pass
                save_url_json(indicator, "virustotal", raw)
        except Exception:
            pass

    # AlienVault OTX（并行 general 与 url_list，首条命中优先 general/pulses）
    avapi = apis.get("ALIENVAULT") or ""
    if avapi and host_for_tf:
        try:
            collected_tags: List[str] = []
            collected_hashes: List[str] = []
            collected_ips: List[str] = []
            # AlienVault: 缓存优先
            cached_g = _load_url_json("alienvault_general", indicator)
            cached_u = _load_url_json("alienvault_url_list", indicator)
            if cached_g or cached_u:
                try:
                    print("📦 使用 AlienVault 缓存数据")
                except Exception:
                    pass
                ips: List[str] = []
                urls: List[str] = []
                domains: List[str] = [host_for_tf] if not _is_ip(host_for_tf) else []
                pulses = (cached_g.get("pulse_info") or {}).get("pulses") if cached_g else []
                for p in (pulses or []):
                    for ind in p.get("indicators", []) or []:
                        val = ind.get("indicator") or ""
                        t = (ind.get("type") or "").lower()
                        if t in {"ipv4", "ipv6", "ip"}:
                            ips.append(val)
                            collected_ips.append(val)
                        elif t in {"url", "uri"}:
                            urls.append(val)
                        elif t in {"domain", "hostname"}:
                            domains.append(val)
                        elif t.startswith("filehash") or t.startswith("sha"):
                            collected_hashes.append(val)
                    # 收集标签与 Related Tags
                    try:
                        for tg in (p.get("tags") or []):
                            if tg:
                                collected_tags.append(str(tg))
                        for tg in (p.get("related_tags") or []):
                            if tg:
                                collected_tags.append(str(tg))
                    except Exception:
                        pass
                for e in (cached_u.get("url_list") or []) if cached_u else []:
                    u = (e or {}).get("url")
                    if u:
                        urls.append(u)
                if ips or urls or domains:
                    out["results"].append({
                        "source": "AlienVault",
                        "hit": True,
                        "ioc": {
                            "ips": list(dict.fromkeys(ips)),
                            "domains": list(dict.fromkeys(domains)),
                            "urls": list(dict.fromkeys(urls)),
                        },
                        "summary": ({
                            "威胁标签": list(dict.fromkeys(collected_tags)) if collected_tags else [],
                            "相关样本(前20)": list(dict.fromkeys(collected_hashes))[:20] if collected_hashes else [],
                            "历史解析/PassiveDNS": list(dict.fromkeys(collected_ips)) if collected_ips else [],
                        })
                    })
            else:
                def _otx_general(host: str) -> Dict[str, Any]:
                    if _is_ip(host):
                        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{host}/general"
                    else:
                        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/general"
                    r = requests.get(url, headers={"X-OTX-API-KEY": avapi}, timeout=30)
                    return {"kind": "general", "raw": (r.json() if r.status_code == 200 else {})}

                def _otx_url_list(host: str) -> Dict[str, Any]:
                    if _is_ip(host):
                        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{host}/url_list"
                    else:
                        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/url_list"
                    r = requests.get(url, headers={"X-OTX-API-KEY": avapi}, timeout=30)
                    return {"kind": "url_list", "raw": (r.json() if r.status_code == 200 else {})}

                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
                    futs = [ex.submit(_otx_general, host_for_tf), ex.submit(_otx_url_list, host_for_tf)]
                    results_otx: List[Dict[str, Any]] = []
                    for f in concurrent.futures.as_completed(futs):
                        try:
                            results_otx.append(f.result())
                        except Exception:
                            pass

                ips: List[str] = []
                urls: List[str] = []
                domains: List[str] = ([host_for_tf] if not _is_ip(host_for_tf) else [])
                chosen = None
                for r in results_otx:
                    raw = r.get("raw") or {}
                    if r.get("kind") == "general":
                        pulses = (raw.get("pulse_info") or {}).get("pulses") or []
                        if pulses and not chosen:
                            chosen = r
                            for p in pulses:
                                for ind in p.get("indicators", []) or []:
                                    val = ind.get("indicator") or ""
                                    t = (ind.get("type") or "").lower()
                                    if t in {"ipv4", "ipv6", "ip"}:
                                        ips.append(val)
                                        collected_ips.append(val)
                                    elif t in {"url", "uri"}:
                                        urls.append(val)
                                    elif t in {"domain", "hostname"}:
                                        domains.append(val)
                                    elif t.startswith("filehash") or t.startswith("sha"):
                                        collected_hashes.append(val)
                                # 收集标签与 Related Tags
                                try:
                                    for tg in (p.get("tags") or []):
                                        if tg:
                                            collected_tags.append(str(tg))
                                    for tg in (p.get("related_tags") or []):
                                        if tg:
                                            collected_tags.append(str(tg))
                                except Exception:
                                    pass
                    elif r.get("kind") == "url_list":
                        lst = (raw.get("url_list") or [])
                        if lst and not chosen:
                            chosen = r
                            for e in lst:
                                u = (e or {}).get("url")
                                if u:
                                    urls.append(u)
                if chosen:
                    out["results"].append({
                        "source": "AlienVault",
                        "hit": True,
                        "ioc": {
                            "ips": list(dict.fromkeys(ips)),
                            "domains": list(dict.fromkeys(domains)),
                            "urls": list(dict.fromkeys(urls)),
                        },
                        "summary": ({
                            "威胁标签": list(dict.fromkeys(collected_tags)) if collected_tags else [],
                            "相关样本(前20)": list(dict.fromkeys(collected_hashes))[:20] if collected_hashes else [],
                            "历史解析/PassiveDNS": list(dict.fromkeys(collected_ips)) if collected_ips else [],
                        })
                    })
                for r in results_otx:
                    raw = r.get("raw") or {}
                    if raw:
                        save_url_json(indicator, f"alienvault_{r.get('kind')}", raw)
                # 将 AlienVault 标签注入 enhanced.threat_tags 以便统一模板合并展示
                if collected_tags:
                    try:
                        if isinstance(out.get("enhanced"), dict):
                            out["enhanced"].setdefault("threat_tags", [])
                            out["enhanced"]["threat_tags"].extend(list(dict.fromkeys(collected_tags)))
                            out["enhanced"]["threat_tags"] = list(dict.fromkeys(out["enhanced"]["threat_tags"]))
                    except Exception:
                        pass
                # 注入相关样本与 PassiveDNS 到 enhanced
                try:
                    if collected_hashes:
                        out.setdefault("enhanced", {})
                        out["enhanced"].setdefault("related_samples", [])
                        out["enhanced"]["related_samples"].extend(list(dict.fromkeys(collected_hashes))[:20])
                        out["enhanced"]["related_samples"] = list(dict.fromkeys(out["enhanced"]["related_samples"]))
                    if collected_ips:
                        out.setdefault("enhanced", {})
                        out["enhanced"].setdefault("passive_dns", [])
                        out["enhanced"]["passive_dns"].extend(list(dict.fromkeys(collected_ips)))
                        out["enhanced"]["passive_dns"] = list(dict.fromkeys(out["enhanced"]["passive_dns"]))
                except Exception:
                    pass
        except Exception:
            pass

    # ThreatBook：权限不足，URL 查询路径禁用 ThreatBook，仅域名时可考虑（此处整体关闭）
    tbapi = apis.get("THREATBOOK") or ""
    if False and tbapi and host_for_tf:
        try:
            # ThreatBook: 缓存优先
            cached_tb_raw = _load_url_json("threatbook", indicator)
            if cached_tb_raw and isinstance(cached_tb_raw, dict):
                try:
                    print("📦 使用 ThreatBook 缓存数据")
                except Exception:
                    pass
                raw = cached_tb_raw
            else:
                # 1) v3 domain/query
                tb_v3 = _tb_domain_query_raw(host_for_tf, tbapi)
                raw = tb_v3.get("raw") or {}
            # 兼容两种返回结构：
            # 1) data[domain]
            # 2) data.domains[domain]
            data_obj = {}
            if isinstance(raw, dict):
                d = raw.get("data") or {}
                if isinstance(d, dict):
                    data_obj = d.get(host_for_tf) or {}
                    if not data_obj:
                        data_obj = (d.get("domains") or {}).get(host_for_tf) or {}
            summary: Dict[str, Any] = {}
            ioc = {"ips": [], "domains": [], "urls": [], "hashes": []}
            if isinstance(data_obj, dict) and data_obj:
                # judgments
                judgments = data_obj.get("judgments") or []
                if isinstance(judgments, list) and judgments:
                    summary["威胁类型"] = list(dict.fromkeys([str(x) for x in judgments if x]))
                # severity / confidence / is_malicious / permalink / categories
                sev = data_obj.get("severity")
                if sev:
                    summary["严重性"] = str(sev)
                conf = data_obj.get("confidence_level")
                if conf:
                    summary["可信度"] = str(conf)
                if data_obj.get("is_malicious") is True:
                    summary["恶意标记"] = True
                link = data_obj.get("permalink")
                if link:
                    summary["详情链接"] = str(link)
                cats = data_obj.get("categories") or {}
                if isinstance(cats, dict):
                    first = cats.get("first_cats")
                    second = cats.get("second_cats")
                    if first:
                        if isinstance(first, list):
                            summary["一级分类"] = ",".join([str(x) for x in first if x])
                        else:
                            summary["一级分类"] = str(first)
                    if second:
                        summary["二级分类"] = str(second)
                # tags_classes
                tags_classes = data_obj.get("tags_classes") or []
                if isinstance(tags_classes, list) and tags_classes:
                    flat_tags: List[str] = []
                    for tag_grp in tags_classes:
                        try:
                            ts = tag_grp.get("tags") if isinstance(tag_grp, dict) else None
                            if isinstance(ts, list):
                                flat_tags.extend([str(x) for x in ts if x])
                        except Exception:
                            pass
                    if flat_tags:
                        summary["威胁标签"] = list(dict.fromkeys(flat_tags))
                # cur_ips
                for it in data_obj.get("cur_ips") or []:
                    try:
                        ip = (it or {}).get("ip")
                        if ip:
                            ioc["ips"].append(str(ip))
                    except Exception:
                        pass
                ioc["ips"] = list(dict.fromkeys(ioc["ips"]))
                # samples
                for it in data_obj.get("samples") or []:
                    try:
                        sha256 = (it or {}).get("sha256")
                        if sha256:
                            ioc["hashes"].append(str(sha256))
                    except Exception:
                        pass
                ioc["hashes"] = list(dict.fromkeys(ioc["hashes"]))
            # 2) 若 v3 无权限或空，则回退 scene/dns
            need_scene_dns = (not tb_v3.get("hit")) or (not isinstance(data_obj, dict) or not data_obj)
            if need_scene_dns:
                try:
                    scene_url = "https://api.threatbook.cn/v3/scene/dns"
                    scene_params = {"apikey": tbapi, "resource": host_for_tf, "lang": os.environ.get("THREATBOOK_LANG", "zh")}
                    rs = requests.get(scene_url, params=scene_params, headers={"Accept": "application/json"}, timeout=30)
                    js_s = rs.json() if rs.status_code == 200 else {"http_status": rs.status_code, "text": rs.text}
                    save_url_json(indicator, "threatbook_scene_dns", js_s)
                    # 选取可解析字段：A 记录 -> IPs
                    try:
                        answers = (js_s.get("data") or {}).get("answers") or []
                        for ans in answers:
                            if isinstance(ans, dict) and ans.get("type") == "A":
                                v = ans.get("value")
                                if v:
                                    ioc["ips"].append(str(v))
                        ioc["ips"] = list(dict.fromkeys(ioc["ips"]))
                        if ioc["ips"] and "威胁类型" not in summary:
                            summary["威胁类型"] = ["DNS"]
                    except Exception:
                        pass
                except Exception:
                    pass
            # 合入结果条目
            # 将 tb_v3 的 raw 作为主 raw；scene/dns 已单独缓存
            entry = {"source": "ThreatBook", "hit": bool(tb_v3.get("hit") or ioc["ips"] or ioc["hashes"])}
            if summary:
                entry["summary"] = summary
            if any(ioc.values()):
                entry["ioc"] = ioc
            entry["raw"] = raw
            out["results"].append(entry)
            if raw:
                save_url_json(indicator, "threatbook", raw)
        except Exception:
            pass

    # Hybrid Analysis：仅 URL 支持 quick-scan/url；若是域名，转为 http://domain
    haapi = apis.get("HYBRID-ANALYSIS") or apis.get("HAAPI") or ""
    if haapi:
        try:
            submit_url = indicator if is_url else (f"http://{host_for_tf}" if host_for_tf and not host_for_tf.startswith(('http://','https://')) else host_for_tf)
            if submit_url:
                headers = {
                    'api-key': haapi,
                    'X-Api-Key': haapi,
                    'user-agent': 'Falcon Sandbox',
                    'accept': 'application/json'
                }
                r = requests.post('https://www.hybrid-analysis.com/api/v2/quick-scan/url', headers=headers, data={'url': submit_url}, timeout=30)
                js = {}
                try:
                    js = r.json()
                except Exception:
                    js = {}
                hit = False
                summary: Dict[str, Any] = {}
                urls: List[str] = []
                domains: List[str] = []
                if isinstance(js, dict) and js:
                    # 经验：当返回含有 verdict/scan_id 等字段可视为命中
                    verdict = str(js.get('verdict') or js.get('threat_score') or '')
                    hit = bool(verdict or js.get('scan_id') or js.get('job_id'))
                    summary = {
                        'verdict': js.get('verdict'),
                        'threat_score': js.get('threat_score'),
                        'scan_id': js.get('scan_id') or js.get('job_id'),
                    }
                    urls.append(submit_url)
                    try:
                        from urllib.parse import urlparse
                        h = urlparse(submit_url).hostname
                        if h:
                            domains.append(h)
                    except Exception:
                        pass
                out["results"].append({
                    'source': 'HybridAnalysis',
                    'hit': hit,
                    'summary': summary,
                    'ioc': {
                        'ips': [],
                        'domains': list(dict.fromkeys(domains)),
                        'urls': list(dict.fromkeys(urls)),
                        'hashes': []
                    },
                    'raw': js
                })
                if js:
                    save_url_json(indicator, 'hybrid', js)
                    # 将 HA 的 Contacted Hosts 作为 PassiveDNS 的后补数据注入 enhanced
                    try:
                        def _collect_hosts(obj):
                            acc = []
                            ip_re = re.compile(r"^(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))(?:\\.(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))){3}$")
                            dom_re = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}$", re.I)
                            def walk(x):
                                if isinstance(x, dict):
                                    for k, v in x.items():
                                        kl = str(k).lower()
                                        # 常见字段快速路径
                                        if kl in {"contacted_hosts", "hosts", "domains", "resolved_ips", "contacted_ips"}:
                                            if isinstance(v, list):
                                                for it in v:
                                                    if isinstance(it, str):
                                                        s = it.strip()
                                                        if ip_re.match(s) or dom_re.match(s):
                                                            acc.append(s)
                                                    elif isinstance(it, dict):
                                                        # 常见子结构 {host: , ip: }
                                                        h = str(it.get("host") or it.get("domain") or it.get("value") or it.get("name") or "").strip()
                                                        ip = str(it.get("ip") or it.get("ip_address") or "").strip()
                                                        for cand in (h, ip):
                                                            if cand and (ip_re.match(cand) or dom_re.match(cand)):
                                                                acc.append(cand)
                                            elif isinstance(v, str):
                                                s = v.strip()
                                                if ip_re.match(s) or dom_re.match(s):
                                                    acc.append(s)
                                        # 继续递归遍历
                                        walk(v)
                                elif isinstance(x, list):
                                    for e in x:
                                        walk(e)
                            walk(obj)
                            return list(dict.fromkeys(acc))

                        ha_hosts = _collect_hosts(js)
                        if ha_hosts:
                            out.setdefault("enhanced", {})
                            out["enhanced"].setdefault("passive_dns", [])
                            # 合并并去重
                            out["enhanced"]["passive_dns"].extend(ha_hosts)
                            out["enhanced"]["passive_dns"] = list(dict.fromkeys(out["enhanced"]["passive_dns"]))
                    except Exception:
                        pass
        except Exception:
            pass

    # HA 缓存后补：即使本次未命中 HA，也尝试从 hybrid 缓存提取 Contacted Hosts 补全 PassiveDNS
    try:
        cached_hybrid = _load_url_json("hybrid", indicator)
        if isinstance(cached_hybrid, dict) and cached_hybrid:
            def _collect_hosts_cache(obj):
                acc = []
                ip_re = re.compile(r"^(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))(?:\\.(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))){3}$")
                dom_re = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}$", re.I)
                def walk(x):
                    if isinstance(x, dict):
                        for k, v in x.items():
                            kl = str(k).lower()
                            if kl in {"contacted_hosts", "hosts", "domains", "resolved_ips", "contacted_ips"}:
                                if isinstance(v, list):
                                    for it in v:
                                        if isinstance(it, str):
                                            s = it.strip()
                                            if ip_re.match(s) or dom_re.match(s):
                                                acc.append(s)
                                        elif isinstance(it, dict):
                                            h = str(it.get("host") or it.get("domain") or it.get("value") or it.get("name") or "").strip()
                                            ip = str(it.get("ip") or it.get("ip_address") or "").strip()
                                            for cand in (h, ip):
                                                if cand and (ip_re.match(cand) or dom_re.match(cand)):
                                                    acc.append(cand)
                                elif isinstance(v, str):
                                    s = v.strip()
                                    if ip_re.match(s) or dom_re.match(s):
                                        acc.append(s)
                            walk(v)
                    elif isinstance(x, list):
                        for e in x:
                            walk(e)
                walk(obj)
                return list(dict.fromkeys(acc))

            ha_hosts_cache = _collect_hosts_cache(cached_hybrid)
            if ha_hosts_cache:
                out.setdefault("enhanced", {})
                out["enhanced"].setdefault("passive_dns", [])
                out["enhanced"]["passive_dns"].extend(ha_hosts_cache)
                out["enhanced"]["passive_dns"] = list(dict.fromkeys(out["enhanced"]["passive_dns"]))
    except Exception:
        pass

    # URLHaus：并行 host 与 url，选择首条命中（不更改返回 hit 语义）
    uhapi = apis.get("URLHAUS") or ""
    if (uhapi or True):
        try:
            candidates: List[Dict[str, Any]] = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
                futs = [ex.submit(urlhaus_lookup, host_for_tf, uhapi)]
                if is_url:
                    futs.append(ex.submit(urlhaus_lookup, indicator, uhapi))
                for f in concurrent.futures.as_completed(futs):
                    try:
                        r = f.result()
                        if isinstance(r, dict):
                            candidates.append(r)
                    except Exception:
                        pass
            chosen = None
            for r in candidates:
                if r.get("hit"):
                    chosen = r
                    break
            if not chosen and candidates:
                chosen = candidates[0]
            if chosen:
                out["results"].append(chosen)
                raw = chosen.get("raw") or {}
                if raw:
                    save_url_json(indicator, "urlhaus", raw)
        except Exception:
            pass

    # 合并增强数据（与 aggregate 保持一致字段名）
    try:
        enhanced = enhanced_url_domain_query(indicator, apis)
        if any(enhanced.values()):
            out["enhanced"] = enhanced
    except Exception:
        pass

    # 合并 IOC：仅基于已查询结果
    ips: List[str] = []
    domains: List[str] = []
    urls: List[str] = []
    for r in out["results"]:
        ioc = r.get("ioc") or {}
        ips.extend(ioc.get("ips") or [])
        domains.extend(ioc.get("domains") or [])
        urls.extend(ioc.get("urls") or [])
    out["ioc"] = {
        "ips": list(dict.fromkeys(ips)),
        "domains": list(dict.fromkeys(domains)),
        "urls": list(dict.fromkeys(urls)),
        "hashes": [],
    }

    # 去重与排序：同一来源保留一条，优先保留命中 True 的结果
    dedup: Dict[str, Dict[str, Any]] = {}
    for r in out["results"]:
        try:
            src = (r.get("source") or "").strip()
            if not src:
                continue
            if src not in dedup:
                dedup[src] = r
            else:
                # 若新结果命中而旧结果未命中，则替换；否则保持已有
                if (r.get("hit") and not dedup[src].get("hit")):
                    dedup[src] = r
        except Exception:
            pass
    out["results"] = sorted(dedup.values(), key=lambda r: (0 if r.get("hit") else 1, r.get("source")))
    # 保存整合缓存
    _save_combined_cache(indicator, out)
    return out


def _query_virustotal(indicator: str, api_key: str) -> Optional[dict]:
    """查询VirusTotal"""
    try:
        headers = {"x-apikey": api_key}
        is_url = bool(re.match(r"^https?://", indicator, re.I))
        
        if is_url:
            # URL查询
            create_resp = requests.post("https://www.virustotal.com/api/v3/urls", 
                                      data={"url": indicator}, headers=headers, timeout=30)
            if create_resp.status_code == 200:
                url_id = create_resp.json().get("data", {}).get("id")
                if url_id:
                    url_resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", 
                                          headers=headers, timeout=30)
                    if url_resp.status_code == 200:
                        url_data = url_resp.json()
                        # 获取relationships数据
                        relationships = {}
                        for rel in ["contacted_ips", "contacted_domains", "referrer_files", "contacted_files", "downloaded_files"]:
                            try:
                                rel_resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}/relationships/{rel}", 
                                                      headers=headers, timeout=30)
                                if rel_resp.status_code == 200:
                                    relationships[rel] = rel_resp.json()
                            except Exception:
                                pass
                        url_data["relationships"] = relationships
                        return url_data
        else:
            # 域名查询
            domain_resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{indicator}", 
                                     headers=headers, timeout=30)
            if domain_resp.status_code == 200:
                domain_data = domain_resp.json()
                # 获取relationships数据
                relationships = {}
                
                # 内部函数：带分页抓取 VT 关系数据，合并所有页
                def _vt_fetch_relations_all(domain: str, rel: str, headers: dict, max_pages: int = 10) -> dict:
                    merged = {"data": []}
                    cursor = None
                    pages = 0
                    while pages < max_pages:
                        try:
                            url = f"https://www.virustotal.com/api/v3/domains/{domain}/relationships/{rel}?limit=40"
                            if cursor:
                                url += f"&cursor={cursor}"
                            resp = requests.get(url, headers=headers, timeout=30)
                            if resp.status_code != 200:
                                break
                            js = resp.json() or {}
                            data = js.get("data") or []
                            merged["data"].extend(data)
                            meta = js.get("meta") or {}
                            cursor = meta.get("next_cursor")
                            if cursor:
                                merged["meta"] = meta
                            pages += 1
                            if not cursor or not data:
                                break
                        except Exception:
                            break
                    # 去重
                    try:
                        seen = set()
                        dedup = []
                        for it in merged.get("data", []):
                            iid = (it or {}).get("id")
                            if iid and iid not in seen:
                                seen.add(iid)
                                dedup.append(it)
                        merged["data"] = dedup
                    except Exception:
                        pass
                    return merged
                # 对于子域名查询，使用根域名（尽量提取最后两段，兼容 www 与多级子域）
                root_domain = indicator
                try:
                    parts = indicator.split('.')
                    if len(parts) >= 3:
                        root_domain = '.'.join(parts[-2:])
                    if indicator.startswith("www."):
                        root_domain = indicator[4:]
                except Exception:
                    pass
                
                for rel in ["resolutions", "subdomains", "siblings", "contacted_ips", "contacted_domains", "communicating_files", "referrer_files"]:
                    try:
                        if rel in ("subdomains", "siblings"):
                            # 优先根域名拉全量（分页）
                            relationships[rel] = _vt_fetch_relations_all(root_domain, rel, headers)
                            # 如果为空，再尝试原始域名（某些场景 VT 仅在原域返回）
                            if not relationships[rel].get("data"):
                                relationships[rel] = _vt_fetch_relations_all(indicator, rel, headers)
                        elif rel == "resolutions":
                            # 分别对原始域与根域抓取并合并（一些记录可能挂在根域名）
                            merged = {"data": []}
                            a = _vt_fetch_relations_all(indicator, rel, headers)
                            b = _vt_fetch_relations_all(root_domain, rel, headers)
                            merged["data"].extend((a.get("data") or []))
                            merged["data"].extend((b.get("data") or []))
                            # 去重
                            try:
                                seen = set()
                                ded = []
                                for it in merged["data"]:
                                    iid = (it or {}).get("id")
                                    if iid and iid not in seen:
                                        seen.add(iid)
                                        ded.append(it)
                                merged["data"] = ded
                            except Exception:
                                pass
                            relationships[rel] = merged
                        else:
                            # 其他关系：单页即可（通常量较小）
                            url = f"https://www.virustotal.com/api/v3/domains/{indicator}/relationships/{rel}?limit=40"
                            rel_resp = requests.get(url, headers=headers, timeout=30)
                            if rel_resp.status_code == 200:
                                relationships[rel] = rel_resp.json()
                    except Exception:
                        pass
                domain_data["relationships"] = relationships
                return domain_data
        
        return None
    except Exception as e:
        _debug(f"VirusTotal查询异常: {e}")
        return None


def _query_alienvault(indicator: str, api_key: str) -> Optional[dict]:
    """查询AlienVault OTX"""
    try:
        headers = {"X-OTX-API-KEY": api_key}
        is_ip = re.fullmatch(r"(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))(?:\\.(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))){3}", indicator) is not None
        
        if is_ip:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general"
        else:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general"
        
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None


def _query_threatfox(indicator: str, api_key: str) -> Optional[dict]:
    """查询ThreatFox"""
    try:
        # 使用现有的threatfox_multi_lookup函数
        result = threatfox_multi_lookup(indicator, api_key)
        if result and result.get("hit"):
            return result.get("raw", {})
        return None
    except Exception:
        return None


def _query_urlhaus(indicator: str) -> Optional[dict]:
    """查询URLHaus"""
    try:
        # 使用现有的urlhaus_lookup函数
        result = urlhaus_lookup(indicator, "")
        if result and result.get("hit"):
            return result.get("raw", {})
        return None
    except Exception:
        return None


def _query_hybrid_analysis(indicator: str, api_key: str) -> Optional[dict]:
    """查询HybridAnalysis - 暂时禁用，API端点不支持URL查询"""
    try:
        if not api_key:
            _debug("HybridAnalysis API密钥未配置")
            return None
        
        _debug("HybridAnalysis URL查询暂时禁用 - API端点不支持URL直接查询")
        return None
        
        # 以下代码暂时注释，因为Hybrid Analysis API不支持URL直接查询
        """
        headers = {
            "accept": "application/json",
            "api-key": api_key
        }
        
        # 确保URL格式正确
        is_url = bool(re.match(r"^https?://", indicator, re.I))
        submit_url = indicator if is_url else f"http://{indicator}"
        
        _debug(f"HybridAnalysis查询URL: {submit_url}")
        
        payload = {
            "url": submit_url
        }
        
        # 使用JSON格式发送请求
        resp = requests.post('https://www.hybrid-analysis.com/api/v2/quick-scan/url', 
                           headers=headers, json=payload, timeout=30)
        
        _debug(f"HybridAnalysis响应状态码: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            _debug(f"HybridAnalysis数据获取成功: {data}")
            return data
        else:
            _debug(f"HybridAnalysis查询失败: {resp.status_code}, {resp.text}")
            return None
        """
            
    except Exception as e:
        _debug(f"HybridAnalysis查询异常: {e}")
        return None


def _extract_alienvault_data(indicator: str, av_data: dict) -> StandardURLData:
    """从AlienVault数据中提取标准化数据结构"""
    try:
        threat_tags = ThreatTags()
        related_samples = RelatedSamples()
        passive_dns = PassiveDNS()
        subdomains = Subdomains()
        
        # 提取威胁标签
        pulses = av_data.get("pulse_info", {}).get("pulses", [])
        for pulse in pulses:
            # 提取标签
            tags = pulse.get("tags", [])
            if isinstance(tags, list):
                threat_tags.tags.extend([str(t) for t in tags if t])
            
            # 提取相关样本
            indicators = pulse.get("indicators", [])
            for ind in indicators:
                ind_type = (ind.get("type") or "").lower()
                if ind_type.startswith("filehash") or ind_type.startswith("sha"):
                    related_samples.extracted_files.append(str(ind.get("indicator", "")))
                elif ind_type in {"ipv4", "ipv6", "ip"}:
                    passive_dns.ips.append(str(ind.get("indicator", "")))
                elif ind_type in {"hostname", "domain", "fqdn"}:
                    host = str(ind.get("indicator", ""))
                    if host:
                        subdomains.siblings.append(host)

        # 提取 general 的 passive_dns（若存在）
        try:
            pdns_list = av_data.get("passive_dns") or []
            for rec in pdns_list:
                if not isinstance(rec, dict):
                    continue
                host = str(rec.get("hostname") or rec.get("record") or rec.get("query") or "").strip()
                addr = str(rec.get("address") or rec.get("value") or rec.get("ip") or "").strip()
                if addr:
                    passive_dns.ips.append(addr)
                if host:
                    passive_dns.domains.append(host)
                if host and addr:
                    passive_dns.resolutions.append(f"{host} {addr}")
                # 将 hostname 也计作子域名补充
                if host:
                    subdomains.siblings.append(host)
        except Exception:
            pass
        
        # 去重
        threat_tags.tags = list(dict.fromkeys(threat_tags.tags))
        related_samples.extracted_files = list(dict.fromkeys(related_samples.extracted_files))[:20]
        passive_dns.ips = list(dict.fromkeys(passive_dns.ips))
        passive_dns.domains = list(dict.fromkeys(passive_dns.domains))
        passive_dns.resolutions = list(dict.fromkeys(passive_dns.resolutions))
        subdomains.siblings = list(dict.fromkeys(subdomains.siblings))
        
        return StandardURLData(
            indicator=indicator,
            threat_tags=threat_tags,
            subdomains=subdomains,
            related_samples=related_samples,
            passive_dns=passive_dns,
            whois=WhoisInfo(),
            certificate=CertificateInfo(),
            source_engines=['AlienVault']
        )
    except Exception:
        return StandardURLData(indicator=indicator, source_engines=['AlienVault'])


def _extract_threatfox_data(indicator: str, tf_data: dict) -> StandardURLData:
    """从ThreatFox数据中提取标准化数据结构"""
    try:
        threat_tags = ThreatTags()
        
        # 提取威胁标签
        malware = tf_data.get("malware", [])
        for mal in malware:
            malware_family = mal.get("malware_family")
            if malware_family:
                threat_tags.tags.append(str(malware_family))
        
        threat_tags.tags = list(dict.fromkeys(threat_tags.tags))
        
        return StandardURLData(
            indicator=indicator,
            threat_tags=threat_tags,
            subdomains=Subdomains(),
            related_samples=RelatedSamples(),
            passive_dns=PassiveDNS(),
            whois=WhoisInfo(),
            certificate=CertificateInfo(),
            source_engines=['ThreatFox']
        )
    except Exception:
        return StandardURLData(indicator=indicator, source_engines=['ThreatFox'])


def _extract_urlhaus_data(indicator: str, uh_data: dict) -> StandardURLData:
    """从URLHaus数据中提取标准化数据结构"""
    try:
        threat_tags = ThreatTags()
        
        # 提取威胁标签
        tags = uh_data.get("tags", [])
        if isinstance(tags, list):
            threat_tags.tags.extend([str(t) for t in tags if t])
        
        threat_tags.tags = list(dict.fromkeys(threat_tags.tags))
        
        return StandardURLData(
            indicator=indicator,
            threat_tags=threat_tags,
            subdomains=Subdomains(),
            related_samples=RelatedSamples(),
            passive_dns=PassiveDNS(),
            whois=WhoisInfo(),
            certificate=CertificateInfo(),
            source_engines=['URLHaus']
        )
    except Exception:
        return StandardURLData(indicator=indicator, source_engines=['URLHaus'])


def _extract_hybrid_analysis_data(indicator: str, ha_data: dict) -> StandardURLData:
    """从HybridAnalysis数据中提取标准化数据结构"""
    try:
        threat_tags = ThreatTags()
        related_samples = RelatedSamples()
        passive_dns = PassiveDNS()
        
        # 提取威胁标签
        verdict = ha_data.get('verdict')
        if verdict:
            threat_tags.tags.append(f"HA: {verdict}")
        
        threat_level = ha_data.get('threat_level')
        if threat_level:
            threat_tags.tags.append(f"HA Threat Level: {threat_level}")
        
        # 提取SHA256哈希作为相关样本
        sha256 = ha_data.get('sha256')
        if sha256:
            related_samples.extracted_files.append(sha256)
        
        # 提取其他有用信息
        av_detect = ha_data.get('av_detect')
        if av_detect:
            threat_tags.tags.append(f"AV Detection: {av_detect}")
        
        total_signatures = ha_data.get('total_signatures')
        if total_signatures:
            threat_tags.tags.append(f"Signatures: {total_signatures}")
        
        # 去重
        threat_tags.tags = list(dict.fromkeys(threat_tags.tags))
        related_samples.extracted_files = list(dict.fromkeys(related_samples.extracted_files))[:20]
        
        return StandardURLData(
            indicator=indicator,
            threat_tags=threat_tags,
            subdomains=Subdomains(),
            related_samples=related_samples,
            passive_dns=passive_dns,
            whois=WhoisInfo(),
            certificate=CertificateInfo(),
            source_engines=['HybridAnalysis']
        )
    except Exception as e:
        _debug(f"HybridAnalysis数据提取异常: {e}")
        return StandardURLData(indicator=indicator, source_engines=['HybridAnalysis'])


def _standard_data_to_legacy_format(standard_data: StandardURLData, apis: dict) -> Dict[str, Any]:
    """将标准化数据结构转换为传统格式以保持兼容性"""
    try:
        # 构建传统格式的结果
        results = []
        
        # 为每个源引擎创建结果条目
        for engine in standard_data.source_engines:
            result = {
                "source": engine,
                "hit": True,
                "summary": {
                    "威胁标签": standard_data.threat_tags.tags[:50],
                    "子域名": standard_data.subdomains.siblings[:100],
                    "相关样本(前20)": standard_data.related_samples.get_top_20(),
                    "历史解析/PassiveDNS": standard_data.passive_dns.ips[:100],
                    "Whois": {
                        "Registrar": standard_data.whois.registrar,
                        "Creation Date": standard_data.whois.creation_date,
                        "Registrant Phone": standard_data.whois.registrant_phone,
                        "Registrant Phone Ext": standard_data.whois.registrant_phone_ext,
                        "Registrant Email": standard_data.whois.registrant_email,
                        "Registrant Organization": standard_data.whois.registrant_organization,
                        "Registrant City": standard_data.whois.registrant_city,
                        "Registrant Country": standard_data.whois.registrant_country,
                        "Expiration Date": standard_data.whois.expiration_date,
                        "Name Servers": standard_data.whois.name_servers,
                    },
                    "证书": {
                        "Subject CN": standard_data.certificate.subject_cn,
                        "Issuer": standard_data.certificate.issuer,
                        "Serial Number": standard_data.certificate.serial_number,
                        "Fingerprint SHA256": standard_data.certificate.fingerprint_sha256,
                        "Valid Not Before": standard_data.certificate.valid_not_before,
                        "Valid Not After": standard_data.certificate.valid_not_after,
                        "Signature Algorithm": standard_data.certificate.signature_algorithm,
                    }
                },
                "ioc": {
                    "ips": standard_data.passive_dns.ips[:50],
                    "domains": standard_data.passive_dns.domains[:50],
                    "urls": [standard_data.indicator] if re.match(r"^https?://", standard_data.indicator, re.I) else [],
                    "hashes": standard_data.related_samples.get_top_20()
                }
            }
            results.append(result)
        
        # 如果没有结果，创建一个默认的VirusTotal结果
        if not results:
            results.append({
                "source": "VirusTotal",
                "hit": False,
                "summary": {},
                "ioc": {"ips": [], "domains": [], "urls": [], "hashes": []}
            })
        
        # 合并IOC
        all_ips = []
        all_domains = []
        all_urls = []
        all_hashes = []
        
        for result in results:
            ioc = result.get("ioc", {})
            all_ips.extend(ioc.get("ips", []))
            all_domains.extend(ioc.get("domains", []))
            all_urls.extend(ioc.get("urls", []))
            all_hashes.extend(ioc.get("hashes", []))
        
        return {
            "indicator": standard_data.indicator,
            "results": results,
            "apis": apis,
            "ioc": {
                "ips": list(dict.fromkeys(all_ips)),
                "domains": list(dict.fromkeys(all_domains)),
                "urls": list(dict.fromkeys(all_urls)),
                "hashes": list(dict.fromkeys(all_hashes))
            }
        }
    except Exception:
        return {
            "indicator": standard_data.indicator,
            "results": [],
            "apis": apis,
            "ioc": {"ips": [], "domains": [], "urls": [], "hashes": []}
        }


# URL/域名打印：完全在 urlgate 渲染，不依赖 aggregate
def print_url_report(agg: Dict[str, Any]) -> None:
    """打印URL/域名报告 - 使用标准化数据结构展示"""
    try:
        from colorama import Fore, Style, init
        init(autoreset=True)
    except Exception:
        class Fore:
            BLUE='\033[94m'; CYAN='\033[96m'; GREEN='\033[92m'; YELLOW='\033[93m'; MAGENTA='\033[95m'
        class Style:
            BRIGHT='\033[1m'; RESET_ALL='\033[0m'

    indicator = agg.get('indicator') or ''
    print(f"\n🎯 目标指标: {indicator}")
    results = agg.get('results') or []
    hit_results = [r for r in results if r.get('hit')]
    miss_results = agg.get('miss_results') or []

    print(f"\n{Fore.BLUE}{Style.BRIGHT}📊 检测结果:{Style.RESET_ALL}")
    for r in hit_results:
        print(f"{Fore.GREEN}✅ {r.get('source')}: 命中{Style.RESET_ALL}")

    # 从结果中提取标准化数据
    threat_tags = []
    subdomains = []
    related_samples = []
    passive_dns = []
    whois_info = {}
    certificate_info = {}

    for r in hit_results:
        summary = r.get('summary', {})
        
        # 合并威胁标签
        tags = summary.get('威胁标签', [])
        if isinstance(tags, list):
            threat_tags.extend(tags)
        
        # 合并子域名
        subs = summary.get('子域名', [])
        if isinstance(subs, list):
            subdomains.extend(subs)
        
        # 合并相关样本
        samples = summary.get('相关样本(前20)', [])
        if isinstance(samples, list):
            related_samples.extend(samples)
        
        # 合并PassiveDNS
        pdns = summary.get('历史解析/PassiveDNS', [])
        if isinstance(pdns, list):
            passive_dns.extend(pdns)
        
        # 合并Whois（优先使用非空值）
        whois = summary.get('Whois', {})
        if isinstance(whois, dict):
            for k, v in whois.items():
                if v and not whois_info.get(k):
                    whois_info[k] = v
        
        # 合并证书（优先使用非空值）
        cert = summary.get('证书', {})
        if isinstance(cert, dict):
            for k, v in cert.items():
                if v and not certificate_info.get(k):
                    certificate_info[k] = v

    # 去重
    threat_tags = list(dict.fromkeys(threat_tags))[:50]
    subdomains = list(dict.fromkeys(subdomains))[:100]
    related_samples = list(dict.fromkeys(related_samples))[:10]
    passive_dns = list(dict.fromkeys(passive_dns))[:100]

    print(f"\n{Fore.CYAN}{Style.BRIGHT}📚 URL/域名概览:{Style.RESET_ALL}")
    
    # 使用多列格式显示威胁标签
    if threat_tags:
        formatted_tags = format_multi_column(threat_tags[:30], label_width=18, min_col_width=25)
        if '\n' in formatted_tags:
            lines = formatted_tags.split('\n')
            print(f"  🔥 {'威胁标签'.ljust(16)}")
            print(f"{' '.ljust(18)} {lines[0]}")
            for line in lines[1:]:
                print(f"{' '.ljust(18)} {line}")
        else:
            print(f"  🔥 {'威胁标签'.ljust(16)}")
            print(f"{' '.ljust(18)} {formatted_tags}")
    else:
        print(f"  🔥 {'威胁标签'.ljust(16)} -")
    
    # 使用多列格式显示子域名
    if subdomains:
        formatted_subs = format_multi_column_full(subdomains[:50], label_width=18, min_col_width=25)
        if '\n' in formatted_subs:
            lines = formatted_subs.split('\n')
            print(f"  🌐 {'子域名(Siblings)'.ljust(16)}")
            print(f"{' '.ljust(18)} {lines[0]}")
            for line in lines[1:]:
                print(f"{' '.ljust(18)} {line}")
        else:
            print(f"  🌐 {'子域名(Siblings)'.ljust(16)}")
            print(f"{' '.ljust(18)} {formatted_subs}")
    else:
        print(f"  🌐 {'子域名(Siblings)'.ljust(16)} -")
    
    # 使用多列格式显示相关样本
    if related_samples:
        formatted_rel = format_multi_column_full(related_samples[:10], label_width=18, min_col_width=25)
        if '\n' in formatted_rel:
            lines = formatted_rel.split('\n')
            print(f"  🧩 {'相关样本(前10)'.ljust(16)}")
            print(f"{' '.ljust(18)} {lines[0]}")
            for line in lines[1:]:
                print(f"{' '.ljust(18)} {line}")
        else:
            print(f"  🧩 {'相关样本(前10)'.ljust(16)}")
            print(f"{' '.ljust(18)} {formatted_rel}")
    else:
        print(f"  🧩 {'相关样本(前10)'.ljust(16)} -")
    
    # 使用多列格式显示PassiveDNS
    if passive_dns:
        formatted_dns = format_multi_column(passive_dns[:50], label_width=18, min_col_width=25)
        if '\n' in formatted_dns:
            lines = formatted_dns.split('\n')
            print(f"  🧭 {'历史解析/PassiveDNS'.ljust(16)}")
            print(f"{' '.ljust(18)} {lines[0]}")
            for line in lines[1:]:
                print(f"{' '.ljust(18)} {line}")
        else:
            print(f"  🧭 {'历史解析/PassiveDNS'.ljust(16)}")
            print(f"{' '.ljust(18)} {formatted_dns}")
    else:
        print(f"  🧭 {'历史解析/PassiveDNS'.ljust(16)} -")
    
    print("  📇 Whois:")
    print(f"    Registrar: {whois_info.get('Registrar') or '-'}")
    print(f"    Creation Date: {_fmt_time_field(whois_info.get('Creation Date'))}")
    if whois_info.get('Registrar Abuse Contact Email'):
        print(f"    Registrar Abuse Contact Email: {whois_info.get('Registrar Abuse Contact Email')}")
    print(f"    注册人电话: {whois_info.get('Registrant Phone') or '-'}")
    print(f"    Registrant Phone Ext: {whois_info.get('Registrant Phone Ext') or '-'}")
    print(f"    注册人邮箱: {whois_info.get('Registrant Email') or '-'}")
    print(f"    Registrant Organization: {whois_info.get('Registrant Organization') or '-'}")
    print(f"    Registrant City: {whois_info.get('Registrant City') or '-'}")
    
    print("  🔐 证书:")
    if not certificate_info:
        print("    -")
    else:
        if certificate_info.get('Subject CN'):
            print(f"    Subject CN: {certificate_info.get('Subject CN')}")
        if certificate_info.get('Issuer'):
            print(f"    Issuer: {certificate_info.get('Issuer')}")
        if certificate_info.get('Serial Number'):
            print(f"    Serial: {certificate_info.get('Serial Number')}")
        if certificate_info.get('Fingerprint SHA256'):
            print(f"    SHA256: {certificate_info.get('Fingerprint SHA256')}")
        if certificate_info.get('Valid Not Before'):
            print(f"    Not Before: {_fmt_time_field(certificate_info.get('Valid Not Before'))}")
        if certificate_info.get('Valid Not After'):
            print(f"    Not After: {_fmt_time_field(certificate_info.get('Valid Not After'))}")

    for r in miss_results:
        print(f"{Fore.YELLOW}❌ {r.get('source')}: 未命中{Style.RESET_ALL}")

