# 调试generateFacts模块

from bpsaf import generateFacts
from TargetFacts import TargetFacts

binary_path = "../samples/CWE114.exe"

# results = TargetFacts()
results = generateFacts(binary_path)

print()