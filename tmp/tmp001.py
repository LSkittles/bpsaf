# 仅供测试使用
import pyvex
import archinfo
# 翻译ADD EBX, 0x4; ADD EBX, 0x4
# 同一个基本块内，EBX只会被赋值一次。
irsbtmp = pyvex.lift(data=b"\x81\xc3\x04\x00\x00\x00\x81\xc3\x04\x00\x00\x00", addr=0x400400, arch=archinfo.ArchX86())
irsbtmp.pp()

#  LEA ECX, [ESP+0x4]
# irsbtmp = pyvex.lift(b"\x8d\x4c\x24\x04", 0x400400, archinfo.ArchX86())
# irsbtmp.pp()


# ARM的寄存器对应偏移
# import archinfo
# ainfo = archinfo.ArchARM()
# AMD64的
# binfo = archinfo.ArchAMD64()

# 0327 统计arith表中运算符的种类
import os
import glob

arithop = {}

for arith in glob.glob(os.path.join('../bpa-facts', '*', 'facts/arith_rtl_exp.facts')):
    # print(arith)
    with open(arith, 'r') as file:
        lines = file.readlines()
        for line in lines:
            op = line.split()[2]
            if op not in arithop:
                arithop[op] = 1
        # l = binary_path.readline().split()
        # print("H")

# print(list(arithop.keys()))
# 目前总共发现了15个二元运算符，分别为
# +, -, *, &, ^, |, %u, %s, /u, /s, >>, <<, >>u, ROL, ROR

print("analysis end")