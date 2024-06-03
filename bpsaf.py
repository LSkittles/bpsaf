import angr
import os
import sys
import pickle

import time

from TargetFacts import TargetFacts
from IRSB2Facts import IRSB2Facts
# from line_profiler import LineProfiler, profile

# @profile
def generateFacts(binary_path, cfg_dir=None) -> TargetFacts:
    '''
    生成binary所对应的facts
    param1 binary_path 需要分析的二进制文件路径
    param2 cfg_dir 之前保存的cfg文件夹路径，用于避免调试时重复使用angr构建控制流图。如果指定后文件夹里没有cfg，就重新生成并保存一份。如果为None，就不保存。
    return TargetFacts, 内含所需的表
    '''
    results = TargetFacts()
    
    proj = angr.Project(binary_path, auto_load_libs=False)
    eid_iter = iter(range(1, 100_000_000_000))
    # 修改arch
    results.arch = proj.arch
    
    (filepath, filename) = os.path.split(binary_path)
    
    if cfg_dir is not None:
        # 指定cfg_dir时
        cfg_file_path = str(os.path.join(cfg_dir, filename) + ".cfg-pickle")
        if not os.path.exists(cfg_file_path):
            # 不存在cfg就重新分析保存
            cfg = proj.analyses.CFGFast()
            with open(cfg_file_path, 'wb') as cfg_file:
                pickle.dump(cfg, cfg_file)
        else:
            # 存在cfg就直接load
            cfg = pickle.load(open(cfg_file_path, 'rb'))
    else:
        # cfg_dir为None时直接分析
        cfg = proj.analyses.CFGFast()
    

    # 直接从cfg里拿block
    for node in cfg._nodes.values():
        block = node.block
        # 这里有几个坑，一是cfg里的block可能为None，二是block不为None，但size是0
        if block is not None and block.size != 0:
            irsb = block.vex
            IRSB2Facts(irsb, results, eid_iter)
 
    return results


def writeFacts(facts:TargetFacts, target_dir):
    '''
    将facts写入文件中。
    看起来好像作为TargetFacts的方法更合理一些，不过还没改
    '''
    # put_reg_vex表
    sa = []
    with open(os.path.join(target_dir, "put_reg_vex.facts"), "w") as put_reg_vex:
        for item in facts.put_reg_vex:
            addr = item[0]
            tmp = str(addr) + '\t' + str(item[1]) + '\t' + str(item[2]) + '\t' + 'e' + str(item[3]) + '\t' + 'e' + str(item[4])
            sa.append(tmp)
        put_reg_vex.write('\n'.join(sa))
    
    # store_mem_vex表
    sa = []
    with open(os.path.join(target_dir, "store_mem_vex.facts"), "w") as store_mem_vex:
        for item in facts.store_mem_vex:
            addr = item[0]
            tmp = str(addr) + '\t' + str(item[1]) + '\t' + str(item[2]) + '\t' + 'e' + str(item[3]) + '\t' + 'e' + str(item[4]) + '\t' + item[5]
            sa.append(tmp)
        store_mem_vex.write('\n'.join(sa))

    # unop_vex_exp表
    sa = []
    with open(os.path.join(target_dir, "unop_vex_exp.facts"), "w") as unop_vex_exp:
        for key, value in facts.unop_vex_exp.items():
            tmp = 'e' + str(value) + '\t' + str(key[0]) + '\t' + key[1] + '\t' + 'e' + str(key[2])
            sa.append(tmp)
        unop_vex_exp.write('\n'.join(sa))
    
    # binop_vex_exp表
    sa = []
    with open(os.path.join(target_dir, "binop_vex_exp.facts"), "w") as binop_vex_exp:
        for key, value in facts.binop_vex_exp.items():
            tmp = 'e' + str(value) + '\t' + str(key[0]) + '\t' + key[1] + '\t' + 'e' + str(key[2]) + '\t' 'e' + str(key[3])
            sa.append(tmp)
        binop_vex_exp.write('\n'.join(sa))
    
    # ite_vex_exp表
    sa = []
    with open(os.path.join(target_dir, "ite_vex_exp.facts"), "w") as ite_vex_exp:
        for key, value in facts.ite_vex_exp.items():
            tmp = 'e' + str(value) + '\t' + str(key[0]) + '\t' + 'e' + str(key[1]) + '\t' + 'e' + str(key[2]) + '\t' 'e' + str(key[3])
            sa.append(tmp)
        ite_vex_exp.write('\n'.join(sa))
    
    # mem_vex_exp表
    sa = []
    with open(os.path.join(target_dir, "mem_vex_exp.facts"), "w") as mem_vex_exp:
        for key, value in facts.mem_vex_exp.items():
            tmp = 'e' + str(value) + '\t' + str(key[0]) + '\t' + 'e' + str(key[1]) + '\t' + key[2]
            sa.append(tmp)
        mem_vex_exp.write('\n'.join(sa))
    
    # regname_vex_exp表
    sa = []
    with open(os.path.join(target_dir, "regname_vex_exp.facts"), "w") as regname_vex_exp:
        for key, value in facts.regname_vex_exp.items():
            tmp = 'e' + str(value) + '\t' + str(key).upper()
            sa.append(tmp)
        regname_vex_exp.write('\n'.join(sa))
    
    # const_vex_exp表
    sa = []
    with open(os.path.join(target_dir, "const_vex_exp.facts"), "w") as const_vex_exp:
        for key, value in facts.const_vex_exp.items():
            tmp = 'e' + str(value) + '\t' + str(key[0]) + '\t' + str(key[1])
            sa.append(tmp)
        const_vex_exp.write('\n'.join(sa))
    
    # tmp_vex_exp(eid, tmp_size, irsb_addr, tmp)
    # key=(irsb_addr, tmp), value=(eid, tmp_size)
    sa = []
    with open(os.path.join(target_dir, "tmp_vex_exp.facts"), "w") as tmp_vex_exp:
        for key, value in facts.tmp_vex_exp.items():
            tmp = 'e' + str(value[0]) + '\t' + str(value[1]) + '\t' + str(key[0]) + '\t' + str(key[1])
            sa.append(tmp)
        tmp_vex_exp.write('\n'.join(sa))
    
    # exit_vex(addr, order, guard, dst, jumpkind, offsIP)
    sa = []
    with open(os.path.join(target_dir, "exit_vex.facts"), "w") as exit_vex:
        for item in facts.exit_vex:
            tmp = str(item[0]) + '\t' + str(item[1]) + '\t' + 'e' + str(item[2]) + '\t' + 'e' + str(item[3]) + '\t' + item[4] +  '\t' + 'e' + str(item[5])
            sa.append(tmp)
        exit_vex.write('\n'.join(sa))
    
    # arch也序列化保存一份，pretty print用
    pickle.dump(facts.arch, file=open(os.path.join(target_dir, "bin_arch.pickle"), "wb"))
    # bin_cfg
    pickle.dump(facts.bin_cfg, file=open(os.path.join(target_dir, "bin_cfg.pickle"), "wb"))


def printVEXIR(binary_path, cfg_dir=None, out=sys.__stdout__):
    '''
    在指定的out打印程序的VEX IR，默认为控制台，可以指定文件
    '''
    # 重置stdout，避免分析时产生的warn输出到out中
    sys.stdout = sys.__stdout__
    
    proj = angr.Project(binary_path, auto_load_libs=False)
    
    (filepath, filename) = os.path.split(binary_path)
    
    if cfg_dir is not None:
        # 指定cfg_dir时
        cfg_file_path = str(os.path.join(cfg_dir, filename) + ".cfg-pickle")
        if not os.path.exists(cfg_file_path):
            # 不存在cfg就重新分析保存
            cfg = proj.analyses.CFGFast()
            with open(cfg_file_path, 'wb') as cfg_file:
                pickle.dump(cfg, cfg_file)
        else:
            # 存在cfg就直接load
            cfg = pickle.load(open(cfg_file_path, 'rb'))
    else:
        # cfg_dir为None时直接分析
        cfg = proj.analyses.CFGFast()

    sys.stdout = out
    # 直接从cfg里拿block
    for node in cfg._nodes.values():
        block = node.block
        if block is not None and block.size != 0:
            irsb = block.vex
            irsb.pp()
    
    sys.stdout = sys.__stdout__