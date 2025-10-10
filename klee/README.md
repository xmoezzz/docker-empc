## *Empc*: Effective Path Prioritization for Symbolic Execution with Path Cover (S&P '25)
*Empc* is a path prioritization method using path cover to deal with path explosion problem in symbolic execution. It improves code coverage and meanwhile reduces the number of execution states and memory usage. *Empc* is instantiated on [KLEE](https://klee-se.org) version 3.1. Please refer to [*Empc* paper (S&P '25)](https://arxiv.org/pdf/2505.03555).

### Build

The build process is the same as KLEE on LLVM 13. Please refer to [KLEE document](https://klee-se.org/build/build-llvm13/).

### Usage

*Empc* is a searcher module in KLEE. You can easily use `--search=empc` in argument options. We also provide some other *Empc* searcher options and you can use `klee --help` to get usage information.

### Citing *Empc*

```
@INPROCEEDINGS {,
author = { Yao, Shuangjie and She, Dongdong },
booktitle = { 2025 IEEE Symposium on Security and Privacy (SP) },
title = {{ Empc: Effective Path Prioritization for Symbolic Execution with Path Cover }},
year = {2025},
volume = {},
ISSN = {2375-1207},
pages = {2772-2790},
keywords = {},
doi = {10.1109/SP61157.2025.00190},
url = {https://doi.ieeecomputersociety.org/10.1109/SP61157.2025.00190},
publisher = {IEEE Computer Society},
address = {Los Alamitos, CA, USA},
month =May}
```

### License

The code uses [KLEE release license](https://github.com/joshuay2022/empc/blob/main/LICENSE.TXT).

