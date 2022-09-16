# ExMap
The goal of this documentation is to provide answers to the following questions:

- What is ExMap?
- How do I build/run/use it?
- What files are in this repository?
- What's the implementation structure, what gets called when and in which order?

## ExMap basics
- memory-mapped file I/O, but explicitly controlled
- kernel module that creates memory area that isn't managed by linux
- possible application: database buffer manager

## How to build
- simply run `make all`, see Makefile for more details

## How to run
- `./load.sh` or `insmod exmap.ko`
- run `./test-exmap` for a basic functionality test
