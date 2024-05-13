from idautils import *
from idc import *

import ida_idp
ida_idp.get_idp_name()
# 定义要搜索的字节序列
# arm
# search_bytes = b"\x00\x00\x00\xd4"
# arm64
search_bytes = b"\x01\x00\x00\xd4"
result = []
# 遍历整个二进制文件的可执行段
seg = ida_segment.get_segm_by_name(".text")

# 在每个段中搜索字节序列
for address in range(seg.start_ea, seg.end_ea):
    if get_bytes(address, len(search_bytes)) == search_bytes:
        print("Match found at address: 0x%x" % address)
        result.append(address)

print([hex(n) for n in result])
