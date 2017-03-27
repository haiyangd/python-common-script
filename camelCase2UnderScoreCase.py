import re
#coding=utf-8
#!/usr/bin/python

def camelCase2UnderScoreCase(code, pattern):
    '''驼峰命名转为下划线命名'''
    callback = lambda match : '_' + match.group().lower() 
    return re.sub(pattern, 
            lambda match: re.sub(r'[A-Z]', callback, match.group()), 
            code)

def underScoreCase2CamelCase(code, pattern):
    '''下划线命名转为驼峰命名'''
    callback = lambda match : match.group()[-1].upper() 
    return re.sub(pattern, 
            lambda match: re.sub(r'_[a-z]', callback, match.group()), 
            code)

if __name__ == '__main__':
	php_code = ''' 
<?php
    $camelCase = "camelCase";
    $under_score_case= "under_score_case";
'''
	pattern = r'\$[\w]+' # PHP变量
	print camelCase2UnderScoreCase(php_code, pattern)
	print underScoreCase2CamelCase(php_code, pattern)
