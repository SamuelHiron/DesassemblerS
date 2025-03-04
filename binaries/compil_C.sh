#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <C_file.c>"
    exit 1
fi

# Get the input C file name
C_FILE=$1

# Extract the base name of the assembly file (without the extension)
BASE_NAME=$(basename "$C_FILE" .c)

# Define the output directories
ELF_DIR="elf"
OBJDUMP_DIR="objdump/C"

# Compile the code 
gcc "C/$BASE_NAME.c" -o "$ELF_DIR/$BASE_NAME"

# Disassemble the executable using objdump
objdump -D "$ELF_DIR/$BASE_NAME" -M intel > "$OBJDUMP_DIR/$BASE_NAME.C.txt"

echo "Build completed successfully. Output files are in the respective directories."
