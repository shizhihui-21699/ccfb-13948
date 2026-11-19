#!/bin/sh
# build.sh — 交叉编译固件(ARMv7)并构建故障仿真器
set -e
cd "$(dirname "$0")"

CFLAGS="--target=arm-none-eabi -march=armv7-a -marm -mfloat-abi=soft \
        -Os -ffreestanding -nostdlib -fno-builtin -fno-stack-protector \
        -fno-unwind-tables -fno-asynchronous-unwind-tables -mno-unaligned-access"

echo "[1/3] 编译固件 (ARMv7, -Os)"
clang $CFLAGS -c ../firmware/auth_naive.c    -o naive.o
clang $CFLAGS -c ../firmware/auth_hardened.c -o hardened.o

echo "[2/3] 链接"
ld.lld -T link.ld naive.o    -o naive.elf
ld.lld -T link.ld hardened.o -o hardened.elf

echo "[3/3] 构建故障仿真器 (主机端)"
clang -O2 -Wall -I../firmware -o rvm rvm.c

echo "完成: naive.elf hardened.elf rvm"
