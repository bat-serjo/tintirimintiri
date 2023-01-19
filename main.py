#!/usr/bin/python
import os
import sys
import string

from lief import ELF


def random_string(length=8) -> str:
    return os.urandom(length).translate((f'{string.ascii_letters}{string.digits}-_' * 4).encode('ascii')).decode()


class TM:
    def __init__(self, fname, tm_file):
        self._bin = ELF.parse(fname)
        self._tm = ELF.parse(tm_file)

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

        # orig.content = [0xf4 for i in range(orig.size)]

        _tm_entry = self._tm.entrypoint
        _tm_segment = self._tm.get(ELF.SEGMENT_TYPES.LOAD)

        _tm_offset = _tm_entry - _tm_segment.virtual_address

        new_tm_segment = self._bin.add(_tm_segment)
        new_tm_entry = new_tm_segment.virtual_address + _tm_offset

        self._bin.header.entrypoint = new_tm_entry

    def store(self):
        self._bin.write(self._bin.name+"_MODED")


if __name__ == "__main__":
    o = TM(sys.argv[1], sys.argv[2])
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
