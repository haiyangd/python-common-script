#coding=utf-8
#!/usr/bin/python

is_chinese = lambda uchar: uchar >= u'\u4e00' and uchar <= u'\u9fa5'

if __name__ == "__main__":
    print is_chinese(1)
    print is_chinese('A')
    print is_chinese('我'.decode('utf-8'))
