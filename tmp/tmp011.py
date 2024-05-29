import pickle
cfg = pickle.load(open("../test/exp01/cfg_pickle/arm/CWE15.exe.cfg-pickle", "rb"))

nodes = cfg._nodes
# Angr的bug：IRSB的地址与IRSB中第一条指令的地址不同
# 此处IRSB的地址为0x40fa71，第一条指令的地址为0x40fa70
node = nodes[0x40fa71]