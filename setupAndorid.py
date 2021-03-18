# encoding: utf-8
'''
@author: xingjun.xyf
@contact: deathmemory@163.com
@file: setupAndorid.py
@time: 2021/3/18 4:50 下午
@desc:
'''
import os

if __name__ == '__main__':
    os.system('adb push utils/android/libs/gson-2.8.6.jar /data/local/tmp/fclibs/gson.jar')
    pass
