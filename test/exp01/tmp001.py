# 统计生成的facts的长度
import os
import pandas as pd

dir = "facts"

facts_len_list = []

archlist = os.listdir(dir)
for arch in archlist:
    binary_name_list = os.listdir(os.path.join(dir, arch))
    for binary_name in binary_name_list:
        facts_dir = os.path.join(dir, arch, binary_name)
        len1 = 0
        len2 = 0
        len3 = 0
        len4 = 0
        len5 = 0
        len6 = 0
        len7 = 0
        len8 = 0
        len9 = 0
        len10 = 0
        with open(os.path.join(facts_dir, "binop_vex_exp.facts"), "r") as f:
            len1 = len(f.readlines())
        with open(os.path.join(facts_dir, "const_vex_exp.facts"), "r") as f:
            len2 = len(f.readlines())
        with open(os.path.join(facts_dir, "exit_vex.facts"), "r") as f:
            len3 = len(f.readlines())
        with open(os.path.join(facts_dir, "ite_vex_exp.facts"), "r") as f:
            len4 = len(f.readlines())
        with open(os.path.join(facts_dir, "mem_vex_exp.facts"), "r") as f:
            len5 = len(f.readlines())
        with open(os.path.join(facts_dir, "put_reg_vex.facts"), "r") as f:
            len6 = len(f.readlines())
        with open(os.path.join(facts_dir, "regname_vex_exp.facts"), "r") as f:
            len7 = len(f.readlines())
        with open(os.path.join(facts_dir, "store_mem_vex.facts"), "r") as f:
            len8 = len(f.readlines())
        with open(os.path.join(facts_dir, "tmp_vex_exp.facts"), "r") as f:
            len9 = len(f.readlines())
        with open(os.path.join(facts_dir, "unop_vex_exp.facts"), "r") as f:
            len10 = len(f.readlines())
        
        facts_len_list.append((arch, binary_name, len1, len2, len3, len4, len5, len6, len7, len8, len9, len10))

pd.DataFrame(facts_len_list).to_csv("facts_len.csv", index=False)