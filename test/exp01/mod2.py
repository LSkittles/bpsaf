# 正确性验证模块测试

from bpsaf import generateFacts, writeFacts, printVEXIR
from pp import pp
import os
import sys
import time

import angr
import pickle

import pandas as pd

from flatten import flatten_log
from compare import compareVEX

binary_dir = "binary"
facts_dir = "facts"
logs_angr = "logs_angr"
logs_rebuild = "logs_rebuild"
cfg_pickle_dir = "cfg_pickle"
flattened_logs_angr = "flattened_logs_angr"
flattened_logs_rebuild = "flattened_logs_rebuild"

# 用于统计VEX IR长度
len_list = []

archlist = os.listdir(binary_dir)
for arch in archlist:
    binary_name_list = os.listdir(os.path.join(binary_dir, arch))
    for binary_name in binary_name_list:
        # 重置stdout
        sys.stdout = sys.__stdout__
        
        binary_file = os.path.join(binary_dir, arch, binary_name)
        
        # # 使用angr将程序的VEX IR打印出来
        # if not os.path.exists(os.path.join(logs_angr, arch)):
        #     os.makedirs(os.path.join(logs_angr, arch))
        # log_file_path = open(os.path.join(logs_angr, arch, binary_name) + "-vex.log", "w")
        # printVEXIR(binary_file, cfg_dir = os.path.join(cfg_pickle_dir, arch), out=log_file_path)
        #
        # # 根据生成的Datalog事实还原出一份VEX IR
        # if not os.path.exists(os.path.join(logs_rebuild, arch)):
        #     os.makedirs(os.path.join(logs_rebuild, arch))
        # pp_file = open(os.path.join(logs_rebuild, arch, binary_name) + "-vex-rebuild.log", "w")
        # sys.stdout = pp_file
        # pp(os.path.join(facts_dir, arch, binary_name))
        # sys.stdout = sys.__stdout__
        #
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
        #
        # # compare
        # flattened_log_angr_file_path = os.path.join(flattened_logs_angr, arch, binary_name) + "-vex-flattened.log"
        # flattened_log_rebuild_file_path = os.path.join(flattened_logs_rebuild, arch,
        #                                                binary_name) + "-vex-rebuild-flattened.log"
        # compareVEX(flattened_log_angr_file_path, flattened_log_rebuild_file_path)
        
        
        # 统计行数
        flattened_log_angr_file_path = os.path.join(flattened_logs_angr, arch, binary_name) + "-vex-flattened.log"
        flattened_log_rebuild_file_path = os.path.join(flattened_logs_rebuild, arch,
                                                       binary_name) + "-vex-rebuild-flattened.log"
        angr_len = 0
        rebuild_len = 0
        with open(flattened_log_angr_file_path, "r") as f:
            angr_len = len(f.readlines())
        with open(flattened_log_rebuild_file_path, "r") as f:
            rebuild_len = len(f.readlines())
        len_list.append((arch, binary_name, angr_len, rebuild_len))

pd.DataFrame(len_list).to_csv("len_list.csv")