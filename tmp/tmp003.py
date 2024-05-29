# 测试IRSB2Facts模块
from IRSB2Facts import IRSB2Facts
from TargetFacts import TargetFacts

import angr

proj = angr.Project("../samples/403.gcc_O0_gcc", auto_load_libs = False)
irsb01 = proj.factory.block(proj.entry).vex
# irsb01.pp()
irsb02 = proj.factory.block(0x80490b0).vex
# irsb02.pp()
# ite运算
irsb03 = proj.factory.block(0x8336724).vex
# ite运算，参数含有常量
irsb04 = proj.factory.block(0x8052c5b).vex
# t31 = nan
irsb05 = proj.factory.block(0x80a353b).vex
# 可以存入表中的ite语句
irsb06 = proj.factory.block(0x8052c5b).vex
# t13 = 1.000000
irsb07 = proj.factory.block(0x826fecf).vex

proj = angr.Project("../samples/401.bzip2_O0_gcc", auto_load_libs=False)
irsb08 = proj.factory.block(0x80486c0).vex

results = TargetFacts()
results.arch = proj.arch
eid_iter = iter(range(1, 100_000_000_000))
IRSB2Facts(irsb05, results, eid_iter)

print("analysis end.")