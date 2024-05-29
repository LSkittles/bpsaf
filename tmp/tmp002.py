# 查询bpa的set_loc与set_mem表中的表达式是否均在其他四个表格中出现

set_loc = open("../results/bpa/bzip2/set_loc_rtl.facts","r")

src_eid_set = set()

lines = set_loc.readlines()
for line in lines:
    src_eid = line.split()[3]
    src_eid_set.add(src_eid)


arith = open("../results/bpa/bzip2/arith_rtl_exp.facts","r")
get_loc = open("../results/bpa/bzip2/get_loc_rtl_exp.facts","r")
get_mem = open("../results/bpa/bzip2/get_mem_rtl_exp.facts","r")
imm = open("../results/bpa/bzip2/imm_rtl_exp.facts","r")

database = set()

lines = arith.readlines()
for line in lines:
    eid = line.split()[0]
    database.add(eid)
lines = get_loc.readlines()
for line in lines:
    eid = line.split()[0]
    database.add(eid)
lines = get_mem.readlines()
for line in lines:
    eid = line.split()[0]
    database.add(eid)
lines = imm.readlines()
for line in lines:
    eid = line.split()[0]
    database.add(eid)

print(src_eid_set.__len__(), database.__len__())

num = 0
for eid in src_eid_set:
    if eid not in database:
        # print("set表中出现了database中未出现的表达式")
        num += 1

if num == 0:
    print("set表中未出现database中未出现的表达式")
else:
    print("set表中出现了database中未出现的表达式")
    print(num)