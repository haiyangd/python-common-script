#coding=utf-8
#!/usr/bin/python

import os

def delete_all_meta(src):
    if (os.path.isfile(src) and src.endswith('.meta')):
        try:
            print 'delete:' + src
            os.remove(src)
        except:
            pass
    elif os.path.isdir(src):
        for item in os.listdir(src):
            itemsrc = os.path.join(src,item)
            delete_all_meta(itemsrc) 
            try:
                os.rmdir(src)
            except:
                pass
                    
                    
if __name__ == "__main__" : 
    path = os.getcwd()
    delete_all_meta(path)
