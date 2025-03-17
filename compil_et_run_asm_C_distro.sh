#!/bin/bash

cmake --build build
# Exécuter les commandes sur binaires d'assembleurs
build/desassam ../binaries/elf/jmp_imm asm > results/asm/jmp_imm.txt
build/desassam ../binaries/elf/jmp_reg asm > results/asm/jmp_reg.txt
build/desassam ../binaries/elf/data asm > results/asm/data.txt
build/desassam ../binaries/elf/jmp_in_same_bb asm > results/asm/jmp_in_same_bb.txt
build/desassam ../binaries/elf/jmp_in_other_bb asm > results/asm/jmp_in_other_bb.txt
build/desassam ../binaries/elf/bar asm > results/asm/bar.txt

# Exécuter les commandes sur binaires de C
build/desassam ../binaries/elf/return0 C > results/C/return0.txt
build/desassam ../binaries/elf/if_function C > results/C/if_function.txt 
build/desassam ../binaries/elf/hello_world C > results/C/hello_world.txt

# Exécuter les commandes sur distro 
build/desassam /bin/ls distro > results/distro/ls.txt