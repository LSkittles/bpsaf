# 测试flatten模块
from test.exp01.flatten import flatten_log

# 使用memory_profiler模块
# flatten_log(log_file_path="output/tmp.log", flatten_log_file_path="output/flatten_tmp.log")
# flatten_log(log_file_path="output/tmp2.log", flatten_log_file_path="output/flatten_tmp2.log")
# flatten_log(log_file_path="output/tmp3.log", flatten_log_file_path="output/flatten_tmp3.log")
# flatten_log(log_file_path="output/tmp4.log", flatten_log_file_path="output/flatten_tmp4.log")
flatten_log(log_file_path="output/tmp5.log", flatten_log_file_path="output/flatten_tmp5.log")
# flatten_log(log_file_path="output/tmp6.log", flatten_log_file_path="output/flatten_tmp6.log")
# flatten_log(log_file_path="output/tmp7.log", flatten_log_file_path="output/flatten_tmp7.log")
# flatten_log(log_file_path="output/tmp8.log", flatten_log_file_path="output/flatten_tmp8.log")
# 案例9：正常展开后exp会过长
# flatten_log(log_file_path="output/tmp9.log", flatten_log_file_path="output/flatten_tmp9.log")

# 在shell使用
# flatten_log(log_file_path="tmp/output/tmp5.log", flatten_log_file_path="tmp/output/flatten_tmp5.log")