#coding=utf-8
#!/usr/bin/python

import os
import fnmatch

def gen_find(path, filepat):
    """在path目录，找filepat文件或目录，放回一个列表生成器"""
    for root, dirs, files in os.walk(path):
        for name in fnmatch.filter(files, filepat):
            yield os.path.join(root, name)
            
if __name__ == '__main__':
    for f in gen_find("/tmp", "20150916*log"):
        print(f)
