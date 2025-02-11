# DesassemblerS
The project is about creating a home-made Desassembler using Capstone and Lief.
First the ELF file will be parsed.
Then using Capsone, Recursive Descent will be first implemented with the binary not stripped to establish a ground truth.
There will also be a mode where the binary will be stripped.

A special care will be given on flow resolution (e.g. resolve eax in jmp eax).
