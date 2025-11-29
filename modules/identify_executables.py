#!/usr/bin/env python3
"""
自动识别恶意软件样本中的可执行文件
Auto-identify executable files in malware samples
"""

import os
import subprocess
import sys
from pathlib import Path

def identify_executables(sample_dir):
    """自动识别样本目录中的可执行文件"""
    executables = []
    non_executables = []
    
    if not os.path.exists(sample_dir):
        print(f"❌ 错误：目录 {sample_dir} 不存在")
        return [], []
    
    print(f"🔍 正在扫描目录: {sample_dir}")
    print("=" * 60)
    
    for filename in os.listdir(sample_dir):
        filepath = os.path.join(sample_dir, filename)
        if os.path.isfile(filepath) and filename != "README.md":
            try:
                # 使用file命令识别文件类型
                result = subprocess.run(['file', filepath], 
                                     capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    file_type = result.stdout.strip()
                    
                    # 检查是否为可执行文件
                    executable_keywords = [
                        'executable', 'pe32', 'elf', 'mach-o', 'dos',
                        'windows pe', 'linux elf', 'mac os x'
                    ]
                    
                    is_executable = any(keyword in file_type.lower() 
                                      for keyword in executable_keywords)
                    
                    if is_executable:
                        executables.append((filename, file_type))
                    else:
                        non_executables.append((filename, file_type))
                else:
                    non_executables.append((filename, "无法识别文件类型"))
                    
            except subprocess.TimeoutExpired:
                non_executables.append((filename, "文件识别超时"))
            except Exception as e:
                non_executables.append((filename, f"识别错误: {str(e)}"))
    
    return executables, non_executables

def print_results(executables, non_executables):
    """打印识别结果"""
    print(f"\n🎯 检测结果统计:")
    print(f"  📄 可执行文件: {len(executables)} 个")
    print(f"  📄 其他文件: {len(non_executables)} 个")
    print(f"  📄 总文件数: {len(executables) + len(non_executables)} 个")
    
    if executables:
        print(f"\n🔴 可执行文件列表:")
        print("-" * 60)
        for i, (filename, file_type) in enumerate(executables, 1):
            print(f"{i:2d}. 📄 {filename}")
            print(f"    🔍 类型: {file_type}")
            print()
    
    if non_executables:
        print(f"\n🟡 其他文件列表:")
        print("-" * 60)
        for i, (filename, file_type) in enumerate(non_executables, 1):
            print(f"{i:2d}. 📄 {filename}")
            print(f"    🔍 类型: {file_type}")
            print()

def get_file_info(filepath):
    """获取文件详细信息"""
    try:
        stat = os.stat(filepath)
        size = stat.st_size
        mtime = stat.st_mtime
        
        # 格式化文件大小
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            size_str = f"{size / (1024 * 1024):.1f} MB"
        else:
            size_str = f"{size / (1024 * 1024 * 1024):.1f} GB"
        
        # 格式化修改时间
        import datetime
        mtime_str = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
        
        return size_str, mtime_str
    except:
        return "未知", "未知"

def main():
    """主函数"""
    print("🎯 THuntPro 样本文件识别工具")
    print("=" * 60)
    
    # 确定样本目录
    if len(sys.argv) > 1:
        sample_dir = sys.argv[1]
    else:
        sample_dir = "malwoverview/sample"
    
    # 检查目录是否存在
    if not os.path.exists(sample_dir):
        print(f"❌ 错误：目录 {sample_dir} 不存在")
        print(f"💡 请确保已下载样本到 {sample_dir} 目录")
        return
    
    # 识别文件
    executables, non_executables = identify_executables(sample_dir)
    
    # 打印结果
    print_results(executables, non_executables)
    
    # 安全提醒
    if executables:
        print("⚠️  安全提醒:")
        print("  - 请勿在生产环境打开这些可执行文件")
        print("  - 建议在虚拟机或沙箱环境中分析")
        print("  - 分析前请备份重要数据")
        print()
    
    # 提供分析建议
    if executables:
        print("🛠️  分析建议:")
        print("  - 静态分析: 使用 IDA Pro, Ghidra, Radare2")
        print("  - 动态分析: 使用 Cuckoo Sandbox, Any.run")
        print("  - 行为分析: 使用 Process Monitor, Wireshark")
        print("  - 网络隔离: 确保样本无法访问网络")

if __name__ == "__main__":
    main()
