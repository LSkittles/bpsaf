# Datalog事实生成模块功能测试

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
        # 生成Datalog事实并写入硬盘
        facts = generateFacts(binary_file, cfg_dir=os.path.join(cfg_pickle_dir, arch))
        writeFacts(facts, os.path.join(facts_dir, arch, binary_name))
        facts_end_time = time.time()
        facts_time = facts_end_time - facts_start_time