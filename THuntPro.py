#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import configparser
import signal
import platform
import json
import re
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# 固定版本标题（保留图标）
TITLE = "🎯 THuntPro v2025.09.12.055 - 专业威胁狩猎工具"
from colorama import init
# 允许作为脚本直接运行：修正 sys.path 以支持包内绝对导入
try:
    __THUNTPRO_BOOTSTRAP__
except NameError:
    import os, sys
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    __THUNTPRO_BOOTSTRAP__ = True

from modules.aggregate import aggregate_indicator, print_chinese_report
from utils.colors import printr

__author__ = "Alexandre Borges"
__copyright__ = "Copyright 2018-2025, Alexandre Borges"
__license__ = "GNU General Public License v3.0"
__version__ = "2025.09.05.002"
__email__ = "reverseexploit at proton.me"

def finish_hook(signum, frame):
    printr()
    exit(1)

def main():
    FINISH_SIGNALS = [signal.SIGINT, signal.SIGTERM]
    for signal_to_hook in FINISH_SIGNALS:
        signal.signal(signal_to_hook, finish_hook)

    # 初始化颜色支持
    if platform.system() == 'Windows':
        init(convert=True)
    else:
        init()

    # 配置文件默认查找顺序
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    from pathlib import Path as _Path
    _home_conf = str(_Path.home() / '.malwapi.conf')
    _local_conf = os.path.join(current_dir, '.malwapi.conf')
    _root_conf = os.path.join(project_root, '.malwapi.conf')
    
    # 优先使用本地与项目根目录下的配置，最后才回退到 $HOME
    _default_conf = _local_conf if os.path.isfile(_local_conf) else (_root_conf if os.path.isfile(_root_conf) else _home_conf)
    for _cand in (_local_conf, _root_conf, _home_conf):
        try:
            if os.path.isfile(_cand):
                _default_conf = _cand
                break
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        prog="THuntPro", 
        description=TITLE, 
        usage="python THuntPro.py [hash|ip|url|domain] -c <配置文件>"
    )
    
    parser.add_argument('-c', '--config', dest='config', type=str, metavar="配置文件", default=_default_conf, help='指定 API 配置文件路径')
    parser.add_argument('-d', '--download', dest='download', type=int, metavar="引擎编号", help='下载样本：1=Malshare, 2=HA, 3=URLHaus, 4=InQuest, 5=VX, 6=Bazaar')
    parser.add_argument('-u', '--upload', dest='upload', type=str, metavar='文件路径', help='上传样本文件到多个引擎（计算并回显 SHA256）')
    # 隐藏上传目标开关在帮助中的显示（仍然可用）
    parser.add_argument('--to', dest='upload_to', type=str, default='vt,ha,triage,bazaar,otx', help=argparse.SUPPRESS)
    parser.add_argument('-t', '--target', dest='target', type=str, metavar='指标', help='目标指标：MD5/SHA256/IP地址/URL/域名')
    parser.add_argument('positional_target', nargs='?', default='', help=argparse.SUPPRESS)
    def _sha256_of_file(fp: str) -> str:
        import hashlib
        h = hashlib.sha256()
        with open(fp, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()

    def _upload_to_engines(filepath: str, apis: dict, targets: list) -> None:
        import requests
        sha256 = _sha256_of_file(filepath)
        print(f"\n📤 准备上传: {filepath}")
        print(f"🔐 SHA256: {sha256}")

        results = []

        if 'vt' in targets:
            key = apis.get('VIRUSTOTAL') or apis.get('VTAPI') or ''
            if key:
                try:
                    with open(filepath, 'rb') as f:
                        r = requests.post('https://www.virustotal.com/api/v3/files', headers={'x-apikey': key}, files={'file': (Path(filepath).name, f)})
                    fail_body = ''
                    if int(r.status_code) // 100 != 2:
                        try:
                            fail_body = (r.text or '')[:800]
                        except Exception:
                            pass
                    results.append({'engine': 'VirusTotal', 'status': r.status_code, 'id': (r.json().get('data', {}) or {}).get('id') if r.headers.get('content-type','').startswith('application/json') else '', 'body': fail_body})
                except Exception as e:
                    results.append({'engine': 'VirusTotal', 'error': str(e)})
            else:
                results.append({'engine': 'VirusTotal', 'error': '缺少 API Key'})

        if 'ha' in targets:
            key = apis.get('HYBRID-ANALYSIS') or apis.get('HAAPI') or ''
            if key:
                try:
                    headers = {
                        'api-key': key,
                        'X-Api-Key': key,
                        'user-agent': 'Falcon Sandbox',
                        'accept': 'application/json'
                    }
                    ha_stage = 'submit'
                    # 先检查 Key 权限，便于诊断
                    try:
                        rk = requests.get('https://www.hybrid-analysis.com/api/v2/key/current', headers=headers, timeout=15)
                        if int(rk.status_code) // 100 == 2:
                            try:
                                kj = rk.json()
                                klevel = kj.get('authorization_level') or kj.get('level') or ''
                                results.append({'engine': 'HybridAnalysis(Key)', 'status': rk.status_code, 'id': klevel})
                            except Exception:
                                results.append({'engine': 'HybridAnalysis(Key)', 'status': rk.status_code})
                        else:
                            results.append({'engine': 'HybridAnalysis(Key)', 'status': rk.status_code, 'body': (rk.text or '')[:400]})
                    except Exception:
                        pass

                    # 如果是 URL，改用 quick-scan/url
                    if str(filepath).startswith('http://') or str(filepath).startswith('https://'):
                        r = requests.post(
                            'https://www.hybrid-analysis.com/api/v2/quick-scan/url',
                            headers=headers,
                            data={'url': filepath}
                        )
                    else:
                        with open(filepath, 'rb') as f:
                            r = requests.post(
                                'https://www.hybrid-analysis.com/api/v2/submit/file',
                                headers=headers,
                                files={'file': (Path(filepath).name, f)},
                                data={'environment_id': 100}
                            )
                            # 若端点不可用则尝试 quick-scan
                            if int(r.status_code) == 404:
                                f.seek(0)
                                ha_stage = 'quick-scan/file'
                                r = requests.post(
                                    'https://www.hybrid-analysis.com/api/v2/quick-scan/file',
                                    headers=headers,
                                    files={'file': (Path(filepath).name, f)}
                                )
                            # 若 quick-scan 仍然 4xx，尝试 File Collection 流程
                            if int(r.status_code) // 100 != 2:
                                # 1) 创建 collection
                                rc = requests.post(
                                    'https://www.hybrid-analysis.com/api/v2/file-collection/create',
                                    headers=headers,
                                    json={'name': f'THuntPro {Path(filepath).name}'}
                                )
                                coll_id = ''
                                try:
                                    cj = rc.json()
                                    coll_id = cj.get('id') or cj.get('collection_id') or ''
                                except Exception:
                                    pass
                                if coll_id:
                                    # 2) 添加文件到 collection
                                    f.seek(0)
                                    ha_stage = f'file-collection/{coll_id}/files/add'
                                    r = requests.post(
                                        f'https://www.hybrid-analysis.com/api/v2/file-collection/{coll_id}/files/add',
                                        headers=headers,
                                        files={'file': (Path(filepath).name, f)}
                                    )
                    jid = ''
                    try:
                        jj = r.json()
                        jid = jj.get('job_id') or jj.get('sha256') or jj.get('id') or jj.get('report_id')
                    except Exception:
                        pass
                    fail_body = ''
                    if int(r.status_code) // 100 != 2:
                        try:
                            fail_body = (r.text or '')[:800]
                        except Exception:
                            pass
                    results.append({'engine': 'HybridAnalysis', 'status': r.status_code, 'id': jid, 'body': fail_body, 'stage': ha_stage})
                except Exception as e:
                    results.append({'engine': 'HybridAnalysis', 'error': str(e)})
            else:
                results.append({'engine': 'HybridAnalysis', 'error': '缺少 API Key'})

        if 'triage' in targets:
            key = apis.get('TRIAGE') or apis.get('TRIAGEAPI') or ''
            if key:
                try:
                    with open(filepath, 'rb') as f:
                        r = requests.post('https://api.tria.ge/v0/samples', headers={'Authorization': f'Bearer {key}'}, files={'file': (Path(filepath).name, f)})
                    sid = ''
                    try:
                        jj = r.json()
                        sid = (jj.get('data') or {}).get('id') or jj.get('id')
                    except Exception:
                        pass
                    fail_body = ''
                    if int(r.status_code) // 100 != 2:
                        try:
                            fail_body = (r.text or '')[:800]
                        except Exception:
                            pass
                    results.append({'engine': 'Triage', 'status': r.status_code, 'id': sid, 'body': fail_body})
                except Exception as e:
                    results.append({'engine': 'Triage', 'error': str(e)})
            else:
                results.append({'engine': 'Triage', 'error': '缺少 API Key'})

        if 'bazaar' in targets:
            key = apis.get('BAZAAR') or apis.get('BAZAARAPI') or ''
            if key:
                try:
                    with open(filepath, 'rb') as f:
                        r = requests.post('https://mb-api.abuse.ch/api/v1/', headers={'Auth-Key': key}, data={'query': 'upload'}, files={'file': (Path(filepath).name, f)})
                    rid = ''
                    try:
                        jj = r.json()
                        rid = jj.get('status')
                    except Exception:
                        pass
                    fail_body = ''
                    if int(r.status_code) // 100 != 2:
                        try:
                            fail_body = (r.text or '')[:800]
                        except Exception:
                            pass
                    results.append({'engine': 'MalwareBazaar', 'status': r.status_code, 'id': rid, 'body': fail_body})
                except Exception as e:
                    results.append({'engine': 'MalwareBazaar', 'error': str(e)})
            else:
                results.append({'engine': 'MalwareBazaar', 'error': '缺少 API Key'})

        if 'otx' in targets:
            # AlienVault OTX: 创建最小脉冲（胚子）并添加 SHA256 指标
            key = apis.get('ALIENVAULT') or apis.get('ALIENAPI') or ''
            if key:
                try:
                    pulse = {
                        'name': f'THuntPro {sha256}',
                        'description': f'Uploaded by THuntPro for file {Path(filepath).name}',
                        'public': False,
                        'tlp': 'white',
                        'indicators': [
                            {'indicator': sha256, 'type': 'FileHash-SHA256', 'title': Path(filepath).name}
                        ]
                    }
                    r = requests.post('https://otx.alienvault.com/api/v1/pulses/create',
                                     headers={'X-OTX-API-KEY': key, 'Content-Type': 'application/json'},
                                     data=json.dumps(pulse))
                    pid = ''
                    try:
                        jj = r.json()
                        pid = jj.get('id') or jj.get('pulse', {}).get('id')
                    except Exception:
                        pass
                    fail_body = ''
                    if int(r.status_code) // 100 != 2:
                        try:
                            fail_body = (r.text or '')[:800]
                        except Exception:
                            pass
                    results.append({'engine': 'AlienVault(OTX)', 'status': r.status_code, 'id': pid, 'body': fail_body})
                except Exception as e:
                    results.append({'engine': 'AlienVault(OTX)', 'error': str(e)})
            else:
                results.append({'engine': 'AlienVault(OTX)', 'error': '缺少 API Key'})

        print("\n📬 上传结果:")
        for it in results:
            eng = it.get('engine', 'Unknown')
            status = it.get('status')
            if it.get('error'):
                print(f"  ❌ {eng}: 上传失败 ({it.get('error')})")
                continue
            # 统一判定 2xx 为成功
            try:
                ok = (int(status) // 100 == 2)
            except Exception:
                ok = False
            if ok:
                print(f"  ✅ {eng}: 上传成功，SHA256: {sha256}")
            else:
                body = it.get('body') or ''
                if body:
                    print(f"  ❌ {eng}: 上传失败 (HTTP {status})，返回体: {body}")
                else:
                    print(f"  ❌ {eng}: 上传失败 (HTTP {status})")
        print("\n💡 可用该 SHA256 直接查询: python THuntPro.py " + sha256)

    args = parser.parse_args()

    # 兼容旧的“位置参数”作为 target
    if not args.target:
        args.target = args.positional_target or ''

    # 检查是否提供了目标；当未提供 target 且未使用 -u 时才报错
    if not args.target and not args.upload:
        parser.print_help()
        print("\n❌ 错误：请使用 -t 提供目标指标或使用 -u 进行上传")
        print("示例：")
        print("  python THuntPro.py -t da095241b82ced1d375181e67a72696703f894ae74e8d98fe43576544981cb50")
        print("  python THuntPro.py -t 45.204.215.15")
        print("  python THuntPro.py -t http://example.com/malware.exe")
        print("  python THuntPro.py -t example.com")
        print("  python THuntPro.py -u /path/to/sample.exe")
        exit(1)

    # 加载配置文件
    config_file = configparser.ConfigParser()
    conf_path_candidates = [args.config, _home_conf, _local_conf, _root_conf]
    _conf_used = ''
    
    for _cand in conf_path_candidates:
        try:
            if os.path.isfile(_cand):
                config_file.read(_cand, encoding='utf-8')
                _conf_used = _cand
                break
        except Exception:
            continue
    
    if not _conf_used:
        print("❌ 错误：找不到配置文件")
        print("请确保以下位置之一存在 .malwapi.conf 文件：")
        for _cand in conf_path_candidates:
            print(f"  - {_cand}")
        exit(1)

    # 显示炫酷的 ASCII Logo
    print("\n" + "="*80)
    print("""
    ████████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗    ██████╗ ██████╗  ██████╗ 
    ╚══██╔══╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝    ██╔══██╗██╔══██╗██╔═══██╗
       ██║   ███████║██║   ██║██╔██╗ ██║   ██║       ██████╔╝██████╔╝██║   ██║
       ██║   ██╔══██║██║   ██║██║╚██╗██║   ██║       ██╔═══╝ ██╔══██╗██║   ██║
       ██║   ██║  ██║╚██████╔╝██║ ╚████║   ██║       ██║     ██║  ██║╚██████╔╝
       ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝       ╚═╝     ╚═╝  ╚═╝ ╚═════╝ 
    """)
    print(TITLE.center(80))
    print("="*80 + "\n")

    print(f"✅ 已加载配置: {_conf_used}")

    # 提取 API 密钥
    apis = {}
    # 仅列出当前受支持且在代码中实际使用的引擎
    api_sections = {
        'VIRUSTOTAL': 'VTAPI',
        'BAZAAR': 'BAZAARAPI', 
        'THREATFOX': 'THREATFOXAPI',
        'THREATBOOK': 'THREATBOOKAPI',
        'ALIENVAULT': 'ALIENAPI',
        'ABUSEIPDB': 'APIKEY',
        'HYBRID-ANALYSIS': 'HAAPI',
        'TRIAGE': 'TRIAGEAPI',
        'MALSHARE': 'MALSHAREAPI',
    }

    available_apis = []
    for section, key in api_sections.items():
        try:
            if config_file.has_section(section) and config_file.get(section, key, fallback='').strip():
                apis[section] = config_file.get(section, key).strip()
                available_apis.append(section)
        except Exception:
            pass

    if available_apis:
        print(f"🔑 API 可用: {', '.join(available_apis)}")
    else:
        print("⚠️  警告：未找到可用的 API 密钥")

    # 处理上传功能
    if args.upload:
        # 兼容含空格路径：从 sys.argv 中拼接 -u/--upload 后的连续非开关参数
        up_path = args.upload
        try:
            import sys as _sys
            argv = _sys.argv[:]
            if '-u' in argv:
                i = argv.index('-u')
            elif '--upload' in argv:
                i = argv.index('--upload')
            else:
                i = -1
            if i >= 0:
                collected = []
                for token in argv[i+1:]:
                    if token.startswith('-'):
                        break
                    collected.append(token)
                if collected:
                    joined = ' '.join(collected)
                    if os.path.isfile(joined):
                        up_path = joined
        except Exception:
            pass
        if not os.path.isfile(up_path):
            print(f"❌ 错误：文件不存在: {up_path}")
            exit(1)
        targets = [t.strip().lower() for t in (args.upload_to or '').split(',') if t.strip()]
        _upload_to_engines(up_path, apis, targets)
        exit(0)

    # 处理下载功能
    if args.download:
        if not args.target:
            print("❌ 错误：下载功能需要提供目标哈希值")
            exit(1)
        
        # 检查目标是否为哈希值
        if len(args.target) not in [32, 40, 64]:
            print("❌ 错误：下载功能仅支持MD5(32)、SHA1(40)或SHA256(64)哈希值")
            exit(1)
        
        # 根据引擎编号执行下载
        if args.download == 1:  # Malshare
            msapi = apis.get("MALSHARE") or ""
            if not msapi:
                print("❌ 错误：未配置Malshare API密钥")
                exit(1)
            print(f"📥 正在从Malshare下载样本: {args.target}")
            try:
                from modules.malshare import MalshareExtractor
                malshare = MalshareExtractor(msapi)
                malshare.malsharedown(args.target)
            except Exception as e:
                print(f"❌ Malshare下载失败: {e}")
                exit(1)
                
        elif args.download == 2:  # Hybrid Analysis
            haapi = apis.get("HYBRID-ANALYSIS") or apis.get("HYBRID") or apis.get("HAAPI") or ""
            if not haapi:
                print("❌ 错误：未配置Hybrid Analysis API密钥")
                exit(1)
            print(f"📥 正在从Hybrid Analysis下载样本: {args.target}")
            try:
                from modules.hybrid import HybridAnalysisExtractor
                ha = HybridAnalysisExtractor(haapi)
                ha.downhash(args.target)
            except Exception as e:
                print(f"❌ Hybrid Analysis下载失败: {e}")
                exit(1)
                
        elif args.download == 3:  # URLHaus
            uhapi = apis.get("URLHAUS") or ""
            if not uhapi:
                print("❌ 错误：未配置URLHaus API密钥")
                exit(1)
            print(f"📥 正在从URLHaus下载样本: {args.target}")
            try:
                from modules.urlhaus import URLHausExtractor
                urlhaus = URLHausExtractor(uhapi)
                urlhaus.haussample(args.target)
            except Exception as e:
                print(f"❌ URLHaus下载失败: {e}")
                exit(1)
                
        elif args.download == 4:  # InQuest
            iqapi = apis.get("INQUEST") or ""
            if not iqapi:
                print("❌ 错误：未配置InQuest API密钥")
                exit(1)
            print(f"📥 正在从InQuest下载样本: {args.target}")
            try:
                from modules.inquest import InQuestExtractor
                inquest = InQuestExtractor(iqapi)
                inquest.inquest_download(args.target)
            except Exception as e:
                print(f"❌ InQuest下载失败: {e}")
                exit(1)
                
        elif args.download == 5:  # VirusExchange
            vxapi = apis.get("VIRUSEXCHANGE") or ""
            if not vxapi:
                print("❌ 错误：未配置VirusExchange API密钥")
                exit(1)
            print(f"📥 正在从VirusExchange下载样本: {args.target}")
            try:
                from modules.virusexchange import VirusExchangeExtractor
                vx = VirusExchangeExtractor(vxapi)
                vx.download_sample(args.target)
            except Exception as e:
                print(f"❌ VirusExchange下载失败: {e}")
                exit(1)
                
        elif args.download == 6:  # MalwareBazaar
            bazapi = apis.get("BAZAAR") or ""
            if not bazapi:
                print("❌ 错误：未配置MalwareBazaar API密钥")
                exit(1)
            print(f"📥 正在从MalwareBazaar下载样本: {args.target}")
            try:
                from modules.bazaar import BazaarExtractor
                bazaar = BazaarExtractor(bazapi)
                bazaar.bazaar_download(args.target)
            except Exception as e:
                print(f"❌ MalwareBazaar下载失败: {e}")
                exit(1)
        else:
            print("❌ 错误：无效的引擎编号，支持: 1=Malshare, 2=HA, 3=URLHaus, 4=InQuest, 5=VX, 6=Bazaar")
            exit(1)
        
        exit(0)  # 下载完成后退出

    # 执行聚合查询：哈希仍走 aggregate；URL/域名走 urlgate 模板
    try:
        target = args.target or ""
        is_hash = False
        if target:
            tl = target.lower()
            is_hash = (len(tl) in (32, 40, 64)) and all(c in "0123456789abcdef" for c in tl)
        is_url = bool(re.match(r"^https?://", target, re.I))
        is_ip = re.fullmatch(r"(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))(?:\\.(?:(?:2(5[0-5]|[0-4]\\d))|(?:1?\\d?\\d))){3}", target) is not None

        if is_hash or is_ip:
            agg = aggregate_indicator(target, apis)
            print_chinese_report(agg)
        else:
            # URL 或域名
            from modules.urlgate import query_url_or_domain, print_url_report
            agg = query_url_or_domain(target, apis)
            print_url_report(agg)
        printr()
    except Exception as e:
        print(f"❌ 查询失败: {e}")
        exit(1)

if __name__ == "__main__":
    main()
