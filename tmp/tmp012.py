import re

# # 示例字符串
# text = "这里有一些十六进制数字：0x12, 0x1234, 0xFFAA, 0x000e2, 还有一些不是的：e3, e34"
# text = 'Sub32(e1,e145)'
# # 正则表达式
# pattern = r'0x[0-9A-Fa-f]+'
# pattern = r'(?:^|[^0-9A-Fa-fxX])([e][0-9]+|[t][0-9]+)'
#
# match = re.findall(pattern, text)

# # 创建一个函数来转换十六进制到十进制
# def hex_to_decimal(hex_str):
#     return str(int(hex_str, 16))
#
# # 使用re.sub()来替换所有的十六进制数字
# def replace_hex_with_decimal(match):
#     return hex_to_decimal(match.group())
#
# # 替换十六进制数字为对应的十进制字符串
# replaced_text = re.sub(pattern, replace_hex_with_decimal, text)
#
# # 输出替换后的字符串
# print(replaced_text)

import re
print()
m = re.fullmatch(pattern=r'(?:^|[^0-9A-Fa-fxX])([e][0-9]+|[t][0-9]+)', string=',e145')
m2 = re.fullmatch(pattern=r'[e][0-9]+|[t][0-9]+', string='e3')

matches = re.finditer(pattern=r'(?:^|[^0-9A-Fa-fxX])([e][0-9]+|[t][0-9]+)', string='e1,e145)')
for match in matches:
    print(match.start(), match.end(), match.group())
    
res = re.findall(pattern=r'(?:^|[^0-9A-Fa-fxX])([e][0-9]+|[t][0-9]+)', string='e1,e145)')
print(res)
pass