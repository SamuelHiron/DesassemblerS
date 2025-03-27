#!/bin/bash

cmake --build build

# Exécuter les commandes sur binaires d'assembleurs
build/desassam ../binaries/elf/jmp_imm ON asm > results/asm/jmp_imm.txt
build/desassam ../binaries/elf/jmp_reg ON asm > results/asm/jmp_reg.txt
build/desassam ../binaries/elf/data ON asm > results/asm/data.txt
build/desassam ../binaries/elf/jmp_in_same_bb ON asm > results/asm/jmp_in_same_bb.txt
build/desassam ../binaries/elf/jmp_in_other_bb ON asm > results/asm/jmp_in_other_bb.txt
build/desassam ../binaries/elf/bar ON asm > results/asm/bar.txt

# Exécuter les commandes sur binaires de C
build/desassam ../binaries/elf/return0 ON C > results/C/return0.txt
build/desassam ../binaries/elf/if_function ON C > results/C/if_function.txt 
build/desassam ../binaries/elf/hello_world ON C > results/C/hello_world.txt
build/desassam ../binaries/elf/function_pointer ON C > results/C/function_pointer.txt
build/desassam ../binaries/elf/switch ON C > results/C/switch.txt

# Exécuter les commandes sur binaires de C
build/desassam ../binaries/elf/exception ON Cpp > results/Cpp/exception.txt
build/desassam ../binaries/elf/methode_virtuelle ON Cpp > results/Cpp/methode_virtuelle.txt


# Exécuter les commandes sur distro 
build/desassam /bin/ls ON distro > results/distro/ls.txt