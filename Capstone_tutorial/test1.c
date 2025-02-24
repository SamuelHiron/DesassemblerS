/*test1.c*/

#include <stdio.h>
#include <inttypes.h> // for PRIx64 macro , it formats the instruction address as a hexadecimal number. 

#include <capstone/capstone.h>

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00\x55" // sample is in hex mode

int main(void)
{
    csh handle; //handle will be used at every API of Capstone.
    cs_insn *insn; // pointer to a memory containing all disassembled instructions.
    size_t count;
    //cs_open() is used to initialize the Capstone engine. It returns a handle to the engine.
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK){
        return -1;
    } 
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON, time & memory consuming


    //Disassemble the code, 0x1000 is its address, 0 means continue until no more code or a broken instruction. insn is a pointer to the memory containing all disassembled instructions. The number returned count is the number of disassembled instructions.
    count = cs_disasm(handle, CODE, sizeof(CODE)-1, 0x1000, 0, &insn);
    if (count >0) {
        size_t j;
        for (j=0; j<count; j++){
            // printf("0x%"PRIx64":\t%s\t\t%s\t\tid = %s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
            printf("0x%"PRIx64":\t%s\t\t%s\t\tid = %u\tsize = %u\tgroups = %u\n",
                insn[j].address, insn[j].mnemonic, insn[j].op_str,
                insn[j].id, insn[j].size, insn[j].detail->groups);
         
        }

        cs_free(insn, count);
    } else {
        printf("ERROR: Failed to disassemble given code!\n");
    }
    cs_close(&handle);
    return 0;
}
