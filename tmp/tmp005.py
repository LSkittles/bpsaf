# 对生成的facts按addr从小到大进行排序
# 顺道把addr加上base，转成十六进制
# 输出在results/sorted
import pandas as pd
import os

dir_list = ["bpa"]
filelist = ["401.bzip2_O0_gcc",
        "403.gcc_O0_gcc",
        "458.sjeng_O0_gcc"]
bpa_facts_list = ["set_loc_rtl.facts", "set_mem_rtl.facts"]
bhe_facts_list = ["put_reg_vex.facts", "store_mem_vex.facts"]

for file in filelist:
    for fact in bpa_facts_list:
        fact_tmp = pd.read_csv(os.path.join("../results", "bpa", file, fact), sep="\t", header=None)
        fact_tmp.sort_values(by=[0, 1], ascending=True, inplace=True)
        l = fact_tmp[0]
        m = []
        for addr in l:
            m.append(hex(int(addr) + 0x8048000))
        fact_tmp[0] = m
        if not os.path.exists(os.path.join("../results/sorted", "bpa", file)):
            os.makedirs(os.path.join("../results/sorted", "bpa", file))
        fact_tmp.to_csv(os.path.join("../results/sorted", "bpa", file, fact), mode = 'w', index=False, sep="\t", header=None)
        
for file in filelist:
    for fact in bhe_facts_list:
        fact_tmp = pd.read_csv(os.path.join("../results", "bhe", file, fact), sep="\t", header=None)
        fact_tmp.sort_values(by=[0, 1], ascending=True, inplace=True)
        l = fact_tmp[0]
        m = []
        for addr in l:
            m.append(hex(int(addr, 16)))
        fact_tmp[0] = m
        if not os.path.exists(os.path.join("../results/sorted", "bhe", file)):
            os.makedirs(os.path.join("../results/sorted", "bhe", file))
        fact_tmp.to_csv(os.path.join("../results/sorted", "bhe", file, fact), mode = 'w', index=False, sep="\t", header=None)


# set_loc = pd.read_csv("../results/bpa/bzip2/set_mem_rtl.facts", dtype={'addr': int, 'order': int, 'bit_number': int, 'data': str, 'target': str}, header=None, sep='\t')
# set_loc_bhe = pd.read_csv("../results/bhe/bzip2/set_mem_rtl.facts", dtype={'addr': int, 'order': int, 'bit_number': int, 'data': str, 'target': str}, header=None, sep='\t')
# # set_loc.dtypes
#
# set_loc.sort_values(by=[0, 1], ascending=True, inplace=True)
# set_loc_bhe.sort_values(by=[0, 1], ascending=True, inplace=True)
#
# set_loc.to_csv("../results/compare/bzip2/set_mem_rtl.csv", mode = 'w', index=False, sep='\t', header=None)
# set_loc_bhe.to_csv("../results/compare/bzip2/set_mem_rtl_bhe.csv", mode = 'w', index=False, sep='\t', header=None)