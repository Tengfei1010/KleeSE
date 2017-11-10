## KleeSE

KleeSE is the core of klee symbolic engine and built on llvm 5.0.

## How to install and build KleeSE?

- 1 Install LLVM 5.0 follow install-llvm.md

- 2 Install STP Solver follow install-stp.md

- 3 Get the source code and build

```bash
$ git clone https://github.com/tutengfei/KleeSE.git

$ cd KleeSE 

$ mkdir build & cd build

$ cmake ..

$ make
```

## How to debug KleeSE?

There is a main.cpp, which is used to debug KleeSE.

## How to use KleeSE?

In build fold, you can use KleeSE as executable file. such as

```bash
$ ./KleeSE test.bc
```

## How to run KleeSE by using uclibc and runtime?

```bash
$ ./KleeSE --libc=uclibc --posix-runtime ./test.bc --sym-arg 3
```
usage: (klee_init_env) [options] [program arguments]

  -sym-arg <N>              - Replace by a symbolic argument with length N
  
  -sym-args <MIN> <MAX> <N> - Replace by at least MIN arguments and at most
                              MAX arguments, each with maximum length N
  
  -sym-files <NUM> <N>      - Make NUM symbolic files ('A', 'B', 'C', etc.),
                              each with size N
  
  -sym-stdin <N>            - Make stdin symbolic with size N.
  
  -sym-stdout               - Make stdout symbolic.
  
  -max-fail <N>             - Allow up to N injected failures
  
  -fd-fail                  - Shortcut for '-max-fail 1'

## How to contribute KleeSE?

#### TODO
