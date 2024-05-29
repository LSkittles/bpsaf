# 可用性验证模块测试
import os

# os.system("souffle" + " --help")
# refine bpa facts
os.system("souffle -D test/exp03/all_facts/x86/401.bzip2_O0_gcc/ -F test/exp03/all_facts/x86/401.bzip2_O0_gcc/ test/exp03/rule/refineFacts.dl")
# classify fatcs
os.system("souffle -D test/exp03/all_facts/x86/401.bzip2_O0_gcc/output/ -F test/exp03/all_facts/x86/401.bzip2_O0_gcc/ test/exp03/rule/classifyFacts.dl ")