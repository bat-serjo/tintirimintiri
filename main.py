#!/usr/bin/python
import os
import sys
import string
import shutil
import subprocess

from lief import ELF


def random_string(length=8) -> str:
    return os.urandom(length).translate((f'{string.ascii_letters}{string.digits}-_' * 4).encode('ascii')).decode()


class TM:
    def __init__(self, fname):
        self._bin = ELF.parse(fname)
        self._moded = self._bin.name+"_MODED"
        self._tm = None

    def _build_loader(self, entry: int, dietpath: str = "/home/serj/_o/netstock/dietlibc"):
        oldd = os.getcwd()
        os.chdir("tintirimintiri")

        p = subprocess.Popen(["gcc", "-pie", "-fPIC", "-fcf-protection=none", "-fno-stack-protector", "tintiri.c", "-c",
                              f"-DENTRY={entry}"])
        p.wait()

        p = subprocess.Popen(["ld", "-pie",  "-nostdlib",  "tintiri.o",
                              f"-L{dietpath}bin-x86_64",
                              f"{dietpath}/bin-x86_64/dietlibc.a",
                              "-T", "my_link.ld",  "-o", "a.out"])
        p.wait()
        out = os.path.abspath("a.out")
        os.chdir(oldd)

        self._tm = ELF.parse(out)

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

    def patch(self):
        self._build_loader(0xb70)
        self.copySection()
        if os.path.exists(self._moded):
            os.unlink(self._moded)
        self.store()
        os.chmod(self._moded, 755)

    def store(self):
        self._bin.write(self._moded)


if __name__ == "__main__":
    o = TM(sys.argv[1])
    o.patch()

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
