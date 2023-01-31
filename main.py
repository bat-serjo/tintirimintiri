#!/usr/bin/python
import os
import sys
import string
import subprocess

from lief import ELF


def random_string(length=8) -> str:
    return os.urandom(length).translate((f'{string.ascii_letters}{string.digits}-_' * 4).encode('ascii')).decode()


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

    def _build_loader(self, entry: int, entry_id: int, copy_id: int, dietpath: str ="/home/serj/_o/netstock/dietlibc"):

        oldd = os.getcwd()
        os.chdir("tintirimintiri")

        p = subprocess.Popen(["diet", "gcc", "-pie", "-fPIC", "-fcf-protection=none", "-fno-stack-protector", "tintiri.c", "-c",
                              f"-DENTRY={entry}", f"-DENTRY_ID={entry_id}", f"-DCOPY_ID={copy_id}"])
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

    def copySection(self, name: str = ".text"):
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
        d_entry_id = _
        d_copy_id = n_seg_id
        print("ENTRY_OFFSET ", d_entry)
        print("ORIG_ID ", hex(d_entry_id))
        print("COPY_ID ", hex(d_copy_id))

        self._build_loader(d_entry, d_entry_id, d_copy_id)

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
        self.copySection()
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
