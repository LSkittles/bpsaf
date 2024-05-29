# 使用profiler模块分析事实生成模块的时间开销
import site
site.addsitedir('C:\\Users\\LENOVO\\Documents\\bhe_pycharm\\bpsaf')

import profile
from bpsaf import generateFacts, writeFacts, printVEXIR
import os
import sys

generateFacts(binary_path="output/binary/arm/CWE500.exe")
# profile.run('generateFacts(binary_path="output/binary/arm/CWE15.exe")')

