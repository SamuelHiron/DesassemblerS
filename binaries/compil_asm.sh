#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <assembly_file.asm>"
    exit 1
fi

# Get the input assembly file name
ASM_FILE=$1

# Extract the base name of the assembly file (without the extension)
BASE_NAME=$(basename "$ASM_FILE" .asm)

# Define the output directories
OBJ_DIR="o"
ELF_DIR="elf"
OBJDUMP_DIR="objdump/asm"


# Assemble the code using NASM
nasm -f elf64 "asm/$BASE_NAME.asm" -o "$OBJ_DIR/$BASE_NAME.o"

# Link the object file using LD
ld "$OBJ_DIR/$BASE_NAME.o" -o "$ELF_DIR/$BASE_NAME"

# Disassemble the executable using objdump
objdump -D "$ELF_DIR/$BASE_NAME" -M intel > "$OBJDUMP_DIR/$BASE_NAME.asm.txt"

echo "Build completed successfully. Output files are in the respective directories."
