from bpsaf import generateFacts, writeFacts
import os
import time

if __name__ == '__main__':
    filelist = ["401.bzip2_O0_gcc",
                "403.gcc_O0_gcc",
                "458.sjeng_O0_gcc"]
    for filename in filelist:
        print("start to encode ", filename, "")
        start = time.time()
        facts = generateFacts(os.path.join("samples", filename))
        print("encode finished in ", time.time() - start)

        print("start to write ", filename, "'s facts")
        start = time.time()
        folder_name = os.path.join("tmp/output", filename)
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)
        writeFacts(facts, folder_name)
        print("write finished in ", time.time() - start)