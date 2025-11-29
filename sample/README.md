# 恶意软件样本文件夹 (sample)

此文件夹用于存放通过 THuntPro 工具下载的恶意软件样本。

## ⚠️ 安全提醒

- **请勿在生产环境或未隔离的系统上打开这些文件。**
- 建议在虚拟机、沙箱或其他隔离环境中进行分析。
- 定期检查并清理不需要的样本。

## 📁 文件命名规则

下载的样本通常以其哈希值（MD5, SHA1, SHA256）命名。
某些引擎可能会添加 `.zip` 或 `.gz` 等扩展名。

## 🔍 自动识别执行文件

### 方法1：使用file命令
```bash
# 识别文件类型
file malwoverview/sample/*

# 只显示可执行文件
file malwoverview/sample/* | grep -E "(executable|PE32|ELF)"
```

### 方法2：使用Python脚本自动识别
```python
#!/usr/bin/env python3
import os
import subprocess
import magic

def identify_executables(sample_dir):
    """自动识别样本目录中的可执行文件"""
    executables = []
    
    for filename in os.listdir(sample_dir):
        filepath = os.path.join(sample_dir, filename)
        if os.path.isfile(filepath):
            try:
                # 使用python-magic库识别文件类型
                file_type = magic.from_file(filepath)
                if any(keyword in file_type.lower() for keyword in 
                      ['executable', 'pe32', 'elf', 'mach-o', 'dos']):
                    executables.append((filename, file_type))
            except:
                # 如果python-magic不可用，使用file命令
                try:
                    result = subprocess.run(['file', filepath], 
                                          capture_output=True, text=True)
                    if any(keyword in result.stdout.lower() for keyword in 
                          ['executable', 'pe32', 'elf', 'mach-o', 'dos']):
                        executables.append((filename, result.stdout.strip()))
                except:
                    pass
    
    return executables

# 使用示例
if __name__ == "__main__":
    sample_dir = "malwoverview/sample"
    executables = identify_executables(sample_dir)
    
    print("🔍 检测到的可执行文件:")
    for filename, file_type in executables:
        print(f"  📄 {filename}: {file_type}")
```

### 方法3：使用THuntPro内置功能
```bash
# 下载样本后自动识别
python malwoverview/THuntPro.py -d 6 [哈希值]
# 然后运行识别脚本
python identify_executables.py
```

## 📥 使用示例

```bash
# 下载 Malshare 样本 (编号 1)
python malwoverview/THuntPro.py -d 1 [哈希值]

# 下载 MalwareBazaar 样本 (编号 6)
python malwoverview/THuntPro.py -d 6 [哈希值]

# 识别所有可执行文件
file malwoverview/sample/* | grep -E "(executable|PE32|ELF)"
```

## 🛡️ 分析建议

1. **隔离环境**：在虚拟机中分析样本
2. **工具准备**：准备静态分析工具（IDA Pro、Ghidra等）
3. **动态分析**：使用沙箱环境进行行为分析
4. **网络隔离**：确保样本无法访问网络
5. **备份重要数据**：分析前备份重要文件

## 📊 文件统计

```bash
# 统计样本数量
ls -1 malwoverview/sample/ | wc -l

# 按文件大小排序
ls -lah malwoverview/sample/ | sort -k5 -h

# 按修改时间排序
ls -laht malwoverview/sample/
```
