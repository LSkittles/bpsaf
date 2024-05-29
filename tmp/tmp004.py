# 测试writeFacts函数

from IRSB2Facts import IRSB2Facts
from TargetFacts import TargetFacts

from bpsaf import writeFacts

import angr

proj_gcc = angr.Project("../samples/403.gcc_O0_gcc", auto_load_libs = False)
irsb01 = proj_gcc.factory.block(proj_gcc.entry).vex
irsb01.pp()
# irsb02 = proj.factory.block(0x80490b0).vex
# irsb02.pp()

results = TargetFacts()
eid_iter = iter(range(1, 100_000_000_000))
IRSB2Facts(irsb01, results, eid_iter)

facts = results

# set_loc_rtl = open("set_loc_rtl.facts", "w")

writeFacts(facts, "output")

print("analysis end")