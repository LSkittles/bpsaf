# 测试pp
from test.exp01.pp import pp
import sys


pp_file = open("tmp11.log", "w")
sys.stdout = pp_file
pp("../test/exp01/facts/arm/CWE15.exe")
sys.stdout = sys.__stdout__