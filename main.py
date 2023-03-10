#!/usr/bin/python
import os
import sys
import string
import subprocess

from lief import ELF


DIET_LIBC_PATH = "/home/serj/_o/netstock/dietlibc"


def random_string(length=8) -> str:
    return os.urandom(length).translate((f'{string.ascii_letters}{string.digits}-_' * 4).encode('ascii')).decode()


class Zone:
    def __init__(self, oid: int, cid: int, entry: int):
        self.orig_id = oid
        self.copy_id = cid
        self.entry = entry

    def to_c(self) -> str:
        return '{ %d, %d, %d, 0, 0, 0}' % (self.orig_id, self.copy_id, self.entry)

    def __str__(self) -> str:
        return f"ENTRY {hex(self.entry)} ORIG_ID {hex(self.orig_id)} COPY_ID {hex(self.copy_id)}"


class TM:
    def __init__(self, fname):
        self._bin = ELF.parse(fname)
        self._moded = self._bin.name+"_MODED"
        self._tm = None

    def _get_load_segment_id_for_addr(self, addr: int):
        cnt = 0
        for s in self._bin.segments:
            if s.virtual_address < addr < s.virtual_address + s.virtual_size:
                return s.file_offset, s
            if s.type == ELF.SEGMENT_TYPES.LOAD or s.type == ELF.SEGMENT_TYPES.DYNAMIC:
                cnt += 1
        raise Exception("address not found in segments")

    def check(self):
        elf = self._bin.concrete
        print(elf.header)
        print("%X" % self._bin.entrypoint)
        [print(s) for s in elf.segments]
        print(self._get_load_segment_id_for_addr(self._bin.entrypoint))

    def _build_loader(self, zone_text: Zone, zone_str: Zone, dietpath: str = DIET_LIBC_PATH):

        oldd = os.getcwd()
        os.chdir("tintirimintiri")

        d_text = '-DTEXT=%s, %s' % (zone_text.to_c(), zone_str.to_c())
        # d_text = '-DTEXT=%s' % zone_text.to_c()
        print(d_text)

        p = subprocess.Popen(["diet", "gcc", "-pie", "-fPIC", "-fcf-protection=none", "-fno-stack-protector",
                              "-c", d_text, "tintiri.c"])
        p.wait()

        p = subprocess.Popen(["diet", "ld", "-pie",  "-nostdlib",  "tintiri.o",
                              f"-L{dietpath}bin-x86_64",
                              f"{dietpath}/bin-x86_64/dietlibc.a",
                              "-T", "my_link.ld",  "-o", "a.out"])
        p.wait()

        out = os.path.abspath("a.out")
        os.chdir(oldd)

        self._tm = ELF.parse(out)

    def encrypt(self, blob: bytes):
        ret = bytearray(blob)
        for i, b in enumerate(blob):
            ret[i] = (b ^ 0xA3) & 0xff
        return ret

    def find_strings_zone(self):
        for s in self._bin.segments:
            for i in s.sections:
                if i.name == '.rodata':
                    return s, Zone(s.file_offset, 0, 0)

    def copy_section(self, name: str = ".text"):
        orig = self._bin.get_section(name)
        orig_id, orig_segment = self._get_load_segment_id_for_addr(orig.virtual_address)
        print("ORIG SEGMENT ", orig_id)

        copy_segment = ELF.Segment()
        copy_segment.type = ELF.SEGMENT_TYPES.LOAD
        copy_segment.alignment = orig_segment.alignment
        copy_segment.content = self.encrypt(orig_segment.content)
        copy_segment.flags = ELF.SEGMENT_FLAGS.R
        copy_segment.physical_size = orig_segment.physical_size

        n_seg = self._bin.add(copy_segment)
        n_seg_id, _ = self._get_load_segment_id_for_addr(n_seg.virtual_address+1)

        orig.content = [0xf4 for i in range(orig.size)]

        _, segment = self._get_load_segment_id_for_addr(self._bin.entrypoint)

        d_entry = self._bin.entrypoint - segment.virtual_address
        d_orig_id = _
        d_copy_id = n_seg_id

        z_text = Zone(d_orig_id, d_copy_id, d_entry)
        print(z_text)

        str_seg, z_str = self.find_strings_zone()
        str_seg.content = self.encrypt(str_seg.content)
        print(z_str)

        self._build_loader(z_text, z_str)

        _tm_entry = self._tm.entrypoint
        _tm_segment = self._tm.get(ELF.SEGMENT_TYPES.LOAD)

        _tm_offset = _tm_entry - _tm_segment.virtual_address

        new_tm_segment = self._bin.add(_tm_segment)
        new_tm_entry = new_tm_segment.virtual_address + _tm_offset
        print("TM SEG ", self._get_load_segment_id_for_addr(new_tm_entry))

        n_seg_id, _ = self._get_load_segment_id_for_addr(n_seg.virtual_address+1)
        print("#### NEW COPY ID ####", n_seg_id)

        self._bin.header.entrypoint = new_tm_entry

    def patch(self):
        self.copy_section()
        if os.path.exists(self._moded):
            os.unlink(self._moded)
        self.store()
        os.chmod(self._moded, 0o755)

    def store(self):
        self._bin.write(self._moded)


if __name__ == "__main__":
    o = TM(sys.argv[1])
    # o.check()
    o.patch()
