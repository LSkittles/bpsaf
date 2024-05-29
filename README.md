```
bpsaf
├── IRSB2Facts.py       处理单个的IRSB
├── README.md
├── TargetFacts.py      用于存放生成的facts
├── bpsaf.py            提供generateFacts,writeFacts等接口
├── main.py             提供了几个demo
├── samples             放了几个二进制文件用于测试
├── test                写论文的时候引入的测试模块，跟编码没什么关系，代码也没tidy
└── tmp                 一些调试用的文件
```

还有一点，Angr的控制流图划分算法目前来看好像不是很完美，有些代码片段会重复出现在不同的块中，可能需要注意一下。