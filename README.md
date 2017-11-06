## KleeSE
---------

KleeSE is the core of klee symbolic engine and built on llvm 5.0.

## How to install and build KleeSE?
-------------

- 1 Install LLVM 5.5 follow install-llvm.md

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
------------------------

There is a main.cpp, which is used to debug KleeSE.

## How to use KleeSE?
-----------------------

In build fold, you can use KleeSE as executable file. such as 
```bash
$ KleeSE test.bc
```

## How to contribute KleeSE?
-----------------------
#### TODO