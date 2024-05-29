# 实验一：系统功能测试与验证
# 1.对二进制文件进行分析，生成对应的Datalog事实
# 2.生成二进制文件对应的VEX IR文件
# 3.根据生成的Datalog事实还原出一份VEX IR，将其与Angr直接生成的VEX IR进行对比，验证所生成的Datalog事实的准确性。

from bpsaf import generateFacts, writeFacts, printVEXIR
from pp import pp
import os
import sys
import time

import angr
import pickle

from flatten import flatten_log
from compare import compareVEX

binary_dir = "binary"
facts_dir = "facts"
logs_angr = "logs_angr"
logs_rebuild = "logs_rebuild"
cfg_pickle_dir = "cfg_pickle"
flattened_logs_angr = "flattened_logs_angr"
flattened_logs_rebuild = "flattened_logs_rebuild"


# 用于统计时间消耗
time_list = []

archlist = os.listdir(binary_dir)
for arch in archlist:
    binary_name_list = os.listdir(os.path.join(binary_dir, arch))
    for binary_name in binary_name_list:
        # 重置stdout
        sys.stdout = sys.__stdout__
        
        binary_file = os.path.join(binary_dir, arch, binary_name)
        
        # cfg_start_time = time.time()
        # # 生成cfg
        # # 创建cfg文件夹
        # if not os.path.exists(os.path.join(cfg_pickle_dir, arch)):
        #     os.makedirs(os.path.join(cfg_pickle_dir, arch))
        # proj = angr.Project(binary_file, load_options={'auto_load_libs': False})
        # cfg = proj.analyses.CFGFast()
        # # 序列化保存入硬盘中
        # cfg_file_path = os.path.join(cfg_pickle_dir, arch, binary_name) + ".cfg-pickle"
        # with open(cfg_file_path, "wb") as cfg_file:
        #     pickle.dump(cfg, cfg_file)
        # cfg_end_time = time.time()
        # cfg_time = cfg_end_time - cfg_start_time

        facts_start_time = time.time()
        # 生成Datalog事实
        # 创建facts文件夹
        if not os.path.exists(os.path.join(facts_dir, arch, binary_name)):
            os.makedirs(os.path.join(facts_dir, arch, binary_name))
        facts = generateFacts(binary_file, cfg_dir = os.path.join(cfg_pickle_dir, arch))
        writeFacts(facts, os.path.join(facts_dir, arch, binary_name))
        facts_end_time = time.time()
        facts_time = facts_end_time - facts_start_time
        
        # time_list.append((arch, binary_name, cfg_time, facts_time))
    
        # # 使用angr将程序的VEX IR打印出来
        # if not os.path.exists(os.path.join(logs_angr, arch)):
        #     os.makedirs(os.path.join(logs_angr, arch))
        # log_file_path = open(os.path.join(logs_angr, arch, binary_name) + "-vex.log", "w")
        # printVEXIR(binary_file, cfg_dir = os.path.join(cfg_pickle_dir, arch), out=log_file_path)
        
        # # 根据生成的Datalog事实还原出一份VEX IR
        # if not os.path.exists(os.path.join(logs_rebuild, arch)):
        #     os.makedirs(os.path.join(logs_rebuild, arch))
        # pp_file = open(os.path.join(logs_rebuild, arch, binary_name) + "-vex-rebuild.log", "w")
        # sys.stdout = pp_file
        # pp(os.path.join(facts_dir, arch, binary_name))
        # sys.stdout = sys.__stdout__
    
        # # 将生成的VEX IR展平
        # # angr
        # if not os.path.exists(os.path.join(flattened_logs_angr, arch)):
        #     os.makedirs(os.path.join(flattened_logs_angr, arch))
        # log_angr_file_path = os.path.join(logs_angr, arch, binary_name) + "-vex.log"
        # flattened_log_angr_file_path = os.path.join(flattened_logs_angr, arch, binary_name) + "-vex-flattened.log"
        # flatten_log(log_angr_file_path, flattened_log_angr_file_path)
        # # rebuild
        # if not os.path.exists(os.path.join(flattened_logs_rebuild, arch)):
        #     os.makedirs(os.path.join(flattened_logs_rebuild, arch))
        # log_rebuild_file_path = os.path.join(logs_rebuild, arch, binary_name) + "-vex-rebuild.log"
        # flattened_log_rebuild_file_path = os.path.join(flattened_logs_rebuild, arch, binary_name) + "-vex-rebuild-flattened.log"
        # flatten_log(log_rebuild_file_path, flattened_log_rebuild_file_path)
    
        # compare
        flattened_log_angr_file_path = os.path.join(flattened_logs_angr, arch, binary_name) + "-vex-flattened.log"
        flattened_log_rebuild_file_path = os.path.join(flattened_logs_rebuild, arch, binary_name) + "-vex-rebuild-flattened.log"
        compareVEX(flattened_log_angr_file_path, flattened_log_rebuild_file_path)

print(time_list)
print("experiment complete")