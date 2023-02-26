- Download ditelibc
- Build dietlibc without stack protection
    - you can do this by modifying the Makefile like this  
    EXTRACFLAGS=-ffunction-sections -fdata-sections -fno-stack-protector
- Change DIET_LIBC_PATH in main.py to reflect your dietlibc folder.
- Make sure you have some gcc version installed

You can now obfuscate most x86-64 binaries by running  
./main.py [binary]  
the output will be stored as [binary_MODED]
