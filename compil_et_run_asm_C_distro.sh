#!/bin/bash

cmake --build build

# OPTION MOV ON
# Exécuter les commandes sur binaires d'assembleurs
mkdir -p "results/asm/ON"
build/desassam ../binaries/elf/jmp_imm ON asm > results/asm/ON/jmp_imm.txt
build/desassam ../binaries/elf/jmp_reg ON asm > results/asm/ON/jmp_reg.txt
build/desassam ../binaries/elf/data ON asm > results/asm/ON/data.txt
build/desassam ../binaries/elf/jmp_in_same_bb ON asm > results/asm/ON/jmp_in_same_bb.txt
build/desassam ../binaries/elf/jmp_in_other_bb ON asm > results/asm/ON/jmp_in_other_bb.txt
build/desassam ../binaries/elf/bar ON asm > results/asm/ON/bar.txt

# Exécuter les commandes sur binaires de C
mkdir -p "results/C/ON"
build/desassam ../binaries/elf/return0 ON C > results/C/ON/return0.txt
build/desassam ../binaries/elf/if_function ON C > results/C/ON/if_function.txt 
build/desassam ../binaries/elf/hello_world ON C > results/C/ON/hello_world.txt
build/desassam ../binaries/elf/function_pointer ON C > results/C/ON/function_pointer.txt
build/desassam ../binaries/elf/switch ON C > results/C/ON/switch.txt

# Exécuter les commandes sur binaires de C
mkdir -p "results/Cpp/ON"
build/desassam ../binaries/elf/exception ON Cpp > results/Cpp/ON/exception.txt
build/desassam ../binaries/elf/methode_virtuelle ON Cpp > results/Cpp/ON/methode_virtuelle.txt


# Exécuter les commandes sur distro 
mkdir -p "results/distro/ON"
build/desassam /bin/ls ON distro > results/distro/ON/ls.txt


# OPTION MOV OFF
# Exécuter les commandes sur binaires d'assembleurs
mkdir -p "results/asm/OFF"
build/desassam ../binaries/elf/jmp_imm OFF asm > results/asm/OFF/jmp_imm.txt
build/desassam ../binaries/elf/jmp_reg OFF asm > results/asm/OFF/jmp_reg.txt
build/desassam ../binaries/elf/data OFF asm > results/asm/OFF/data.txt
build/desassam ../binaries/elf/jmp_in_same_bb OFF asm > results/asm/OFF/jmp_in_same_bb.txt
build/desassam ../binaries/elf/jmp_in_other_bb OFF asm > results/asm/OFF/jmp_in_other_bb.txt
build/desassam ../binaries/elf/bar OFF asm > results/asm/OFF/bar.txt

# Exécuter les commandes sur binaires de C
mkdir -p "results/C/OFF"
build/desassam ../binaries/elf/return0 OFF C > results/C/OFF/return0.txt
build/desassam ../binaries/elf/if_function OFF C > results/C/OFF/if_function.txt
build/desassam ../binaries/elf/hello_world OFF C > results/C/OFF/hello_world.txt
build/desassam ../binaries/elf/function_pointer OFF C > results/C/OFF/function_pointer.txt
build/desassam ../binaries/elf/switch OFF C > results/C/OFF/switch.txt

# Exécuter les commandes sur binaires de C++
mkdir -p "results/Cpp/OFF"
build/desassam ../binaries/elf/exception OFF Cpp > results/Cpp/OFF/exception.txt
build/desassam ../binaries/elf/methode_virtuelle OFF Cpp > results/Cpp/OFF/methode_virtuelle.txt

# Exécuter les commandes sur distro
mkdir -p "results/distro/OFF"
build/desassam /bin/ls OFF distro > results/distro/OFF/ls.txt
