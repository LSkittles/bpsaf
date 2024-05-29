# 打印binary对应的vex ir到results/log中
import os
import sys
import angr

filelist = ["401.bzip2_O0_gcc",
        "403.gcc_O0_gcc",
        "458.sjeng_O0_gcc"]
# filelist = ["CWE114.exe"]

# proj = angr.Project("../samples/403.gcc_O0_gcc", load_options={'auto_load_libs': False})
for filename in filelist:
    sys.stdout = sys.__stdout__
    proj = angr.Project(os.path.join("../samples", filename), load_options={'auto_load_libs': False})
    cfg  = proj.analyses.CFGFast()

    # f = open("output/vex-gcc.log", "w")
    f = open("../results/log/" + filename + "-vex.log", "w")
    sys.stdout = f
    for node in cfg._nodes.values():
        block = node.block
        if not block is None:
            irsb = block.vex
            irsb.pp()
    
    f = open("../results/log/" + filename + "-capstone.log", "w")
    sys.stdout = f
    for node in cfg._nodes.values():
        block = node.block
        if not block is None:
            irsb = block.capstone
            irsb.pp()