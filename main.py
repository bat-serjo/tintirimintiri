#!/usr/bin/python
import os
import sys
import string

from lief import ELF


def random_string(length=8) -> str:
    return os.urandom(length).translate((f'{string.ascii_letters}{string.digits}-_' * 4).encode('ascii')).decode()


class TM:
    def __init__(self, fname):
        self._bin = ELF.parse(fname)

    def copySection(self, name: str = ".text"):
        orig = self._bin.get_section(name)
        print(orig.information, orig.type)

        new_section = ELF.Section()
        new_section.name = random_string()
        new_section.type = orig.type
        new_section.flags = orig.flags
        new_section.entry_size = orig.entry_size
        new_section.alignment = orig.alignment
        new_section.link = len(self._bin.sections) + 1
        new_section.content = orig.content

        self._bin.add(new_section, loaded=True)

        orig.content = [0x90 for i in range(orig.size)]

    def store(self):
        self._bin.write(self._bin.name+"_MODED")


if __name__ == "__main__":
    o = TM(sys.argv[1])
    o.copySection()
    o.store()

# binary = ELF.parse(sys.argv[1])
#
# symtab_section             = ELF.Section()
# symtab_section.name        = ""
# symtab_section.type        = ELF.SECTION_TYPES.SYMTAB
# symtab_section.entry_size  = 0x18
# symtab_section.alignment   = 8
# symtab_section.link        = len(binary.sections) + 1
# symtab_section.content     = [0] * 100
#
# symstr_section            = ELF.Section()
# symstr_section.name       = ""
# symstr_section.type       = ELF.SECTION_TYPES.STRTAB
# symstr_section.entry_size = 1
# symstr_section.alignment  = 1
# symstr_section.content    = [0] * 100
#
# symtab_section = binary.add(symtab_section, loaded=False)
# symstr_section = binary.add(symstr_section, loaded=False)
#
# symbol         = ELF.Symbol()
# symbol.name    = ""
# symbol.type    = ELF.SYMBOL_TYPES.NOTYPE
# symbol.value   = 0
# symbol.binding = ELF.SYMBOL_BINDINGS.LOCAL
# symbol.size    = 0
# symbol.shndx   = 0
# symbol         = binary.add_static_symbol(symbol)
#
# symbol         = ELF.Symbol()
# symbol.name    = "main"
# symbol.type    = ELF.SYMBOL_TYPES.FUNC
# symbol.value   = 0x402A00
# symbol.binding = ELF.SYMBOL_BINDINGS.LOCAL
# symbol.shndx   = 14
# symbol         = binary.add_static_symbol(symbol)
#
# print(symbol)
#
# binary.write(sys.argv[2])
