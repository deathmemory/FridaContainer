#!/usr/bin/env python
# -*- coding: utf-8 -*-
# name: decompress_multi_dex.py

import os

path = r'/path/dex/dir/'    # dex 文件夹目录
out_path =r'/path/out/dir/'  #输出文件夹

files = os.listdir(path)

for file in files:  # 遍历文件夹
    if file.find("dex") > 0:  ## 查找dex 文件
        sh = f'jadx -j 1 -r -d {out_path} {path}/{file}'
        print(sh)
        os.system(sh)
