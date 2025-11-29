bkg = 0
windows = 0
# 基于本文件位置，自动定位到 malwoverview/sample 目录（与 THuntPro.py 执行路径无关）
import os as _os
_base_dir = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
output_dir = _os.path.join(_base_dir, 'sample')