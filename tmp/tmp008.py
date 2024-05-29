# 测试angr对arm架构文件的支持
import angr
from bpsaf import generateFacts
from TargetFacts import TargetFacts

# proj = angr.Project("../test\\exp01\\binary\\x64\\CPU2006_Linux_GCC5.1.1_x64_O1_gcc", load_options={'auto_load_libs': False})
# proj = angr.Project("../test/exp01/binary/x64/CPU2006_Linux_GCC5.1.1_x64_O1_bzip2", load_options={'auto_load_libs': False})
# proj = angr.Project("../samples/403.gcc_O0_gcc", auto_load_libs = False)
# proj = angr.Project("../samples/CPU2006_Linux_GCC5.1.1_x64_O1_bzip2", auto_load_libs = False)
# proj = angr.Project("../samples/busybox", auto_load_libs = False)
# proj = angr.Project("../samples/BAP_Linux_GCC4.7.2_x64_O0_cat", auto_load_libs = False)
proj = angr.Project("../samples/CWE114.exe", auto_load_libs = False)

irsb01 = proj.factory.block(proj.entry).vex

results = generateFacts("../samples/CWE114.exe", cfg_dir="../samples")

print("analysis end")