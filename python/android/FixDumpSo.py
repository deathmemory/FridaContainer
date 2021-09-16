# encoding: utf-8
'''
@author: xingjun.xyf
@contact: deathmemory@163.com
@file: bb.py
@time: 2021/8/6 8:46 下午
@desc:
'''
import json
import sys

import lief
from lief import ELF
from lief.ELF import SEGMENT_TYPES


class FixDumpSo:

    def __init__(self):
        pass

    def fix_dump_so(self, sopath, savepath):
        pobj = lief.parse(sopath)
        if isinstance(pobj, ELF.Binary) is not True:
            return
        header = pobj.header
        header.section_header_offset = 0
        header.section_header_offset = 0
        header.numberof_sections = 0
        header.section_name_table_idx = 0

        segments = pobj.segments
        # fix segment
        for segment in segments:
            if isinstance(segment, ELF.Segment):
                segment.file_offset = segment.virtual_address
                print(f'segment: {segment}')
                if segment.type == SEGMENT_TYPES.DYNAMIC:
                    print(f'found {segment.type}')
        pobj.write(savepath)
        pass

    def remove_section_table(self, filename, output):
        binary = lief.parse(filename)  # Build an ELF binary

        header = binary.header
        header.section_header_offset = 0
        header.numberof_sections = 0

        binary.write(output)

    def print_elf(self, sopath):
        binary = lief.parse(sopath)
        json_data = json.loads(lief.to_json(binary))
        print(json.dumps(json_data, sort_keys=True, indent=4))


if __name__ == '__main__':
    if 2 != len(sys.argv):
        print('修复内存 Dump 出的so')
        print(f'Usage:\n\t{sys.argv[0]} /so/path/libxxx.so')
    else:
        fdso = FixDumpSo()
        sopath = sys.argv[1]
        savepath = sopath + "_saved"

        print(f'input so: {sopath}')
        print(f'saved so: {savepath}')
        print('working ...')
        # fdso.print_elf(savepath)
        fdso.fix_dump_so(sopath=sopath, savepath=savepath)
        # bjbus.remove_section_table(sopath, savepath)
        print('done .')
    pass
