# -*- coding: utf-8 -*-
'''杂项工具
'''
#2016/03/09 eeelin 新建

import socket
import time

import paramiko

from qclib import _pprint
from qt4s._proxy import ProxyController
from qt4s._proxy.neehi import GeneralProxyError, Socks5Error
from testbase.conf import settings


class DataCapacity(object):
    '''数据量
    
    用户辅助各种数据量的转换和对比，例如::
    
    DataCapacity(12) == DataCapacity("12B")
    DataCapacity("12 kB") == DataCapacity(12*1024)
 
    '''
    
    unit_map = {
        'k': 1024,
        'M': 1024*1024,
        'G': 1024**3,
        'T': 1024**4,        
    }
    
    def __init__(self, val, unit='B' ):
        '''构造函数
        
        :param val: 数据量，如果为数字则表示字节数，如果是字符串则需要在字符串后面带上单位值，比如"2099kB"
        :type val: str/int
        :param unit: 单位，可以是B\kB\MB\GB\TB，只有但val为int类型才有作用
        :type unit: str
        '''
        if isinstance(val, int) or isinstance(val, long):
            self._bytes = val
            if unit != 'B':
                multi = self.unit_map.get(unit[0])
                if not multi:
                    raise ValueError("错误的单位：\"%s\"" % unit)
                self._bytes *= multi
                
        else:
            self._bytes = self._str_to_bytes(val)

            
    def _str_to_bytes(self, val ):
        val = val.strip()
        digi = ''
        for idx, it in enumerate(val):
            if it.isdigit() or it == '.':
                digi += it
            else:
                break
        else:
            idx += 1
        
        unit = val[idx:].strip()
        if not digi:
            raise ValueError("错误的数据量字符串\"%s\"，必须以数字量开头" % val )
        
        if '.' in digi:
            digi = float(digi)
        else:
            digi = long(digi)
        
        if not unit:
            unit = 'B'
        
        if len(unit) > 2:
            raise ValueError("错误的数据量字符串\"%s\"，单位\"%s\"错误" % (val, unit))
        
        if unit[-1] == 'B': #字节
            divider = 1
        elif unit[-1] == 'b': #比特
            divider = 8
        elif len(unit) == 1:
            divider = 1
            unit += 'B'
        else:
            raise ValueError("错误的数据量字符串\"%s\"，单位\"%s\"错误" % (val, unit))
        
        if len(unit) == 2:
            multi = self.unit_map.get(unit[0])
            if not multi:
                raise ValueError("错误的数据量字符串\"%s\"，单位\"%s\"错误" % (val, unit))
        else:
            multi = 1
            
        byte_val = digi * multi
        if isinstance(byte_val, long):
            if byte_val % divider != 0:
                raise ValueError("错误的数据量字符串\"%s\"，不支持量不是8的倍数的比特" % (val))
        byte_val /= divider
        return byte_val
            
    def __eq__(self, val):
        if isinstance(val, DataCapacity):
            return self._bytes == val.bytes
        elif isinstance(val, int):
            return self._bytes == val
        elif isinstance(val, basestring):
            return self._bytes == self._str_to_bytes(val)
        else:
            return False

    def likely_equal(self, val, error ):
        '''近似等于
        '''
        if isinstance(val, DataCapacity):
            val_bytes = val.bytes
        elif isinstance(val, int):
            val_bytes = val
        elif isinstance(val, basestring):
            val_bytes = self._str_to_bytes(val)
        else:
            raise TypeError()
        
        if isinstance(error, DataCapacity):
            error_bytes = error.bytes
        elif isinstance(error, int):
            error_bytes = error
        elif isinstance(error, basestring):
            error_bytes = self._str_to_bytes(error)
        else:
            raise TypeError()
        
        return abs(val_bytes-self._bytes) < error_bytes
        
        
    def __gt__(self, val):
        if isinstance(val, DataCapacity):
            return self._bytes > val.bytes
        elif isinstance(val, int):
            return self._bytes > val
        elif isinstance(val, basestring):
            return self._bytes > self._str_to_bytes(val)
        else:
            raise TypeError()
        
    def __str__(self):
        return '%s B' % self._bytes
    
    def __add__(self, val ):
        if isinstance(val, DataCapacity):
            return DataCapacity(self._bytes + val.bytes)
        elif isinstance(val, int):
            return DataCapacity(self._bytes + val)
        elif isinstance(val, basestring):
            return DataCapacity(self._bytes + self._str_to_bytes(val))
        else:
            raise TypeError("unsupported operand type(s) for +: '%s' and '%s'" % (type(self).__name__, type(val).__name__))
    
    @property
    def bytes(self):
        '''字节数
        '''
        return self._bytes
           
    @property     
    def kilobytes(self):
        '''k字节数
        '''
        return self._bytes/self.unit_map['k']
        
    @property
    def megabytes(self):
        '''M字节数
        '''
        return self._bytes/self.unit_map['M']
    
    @property
    def gigabytes(self):
        '''G字节数
        '''
        return self._bytes/self.unit_map['G']
    

DCT = DataCapacity   

if __name__ == '__main__':
    
    
    pprint({"a":u"中午", "b":"信息"})
    
    raise
    
    assert DCT(12) != DCT(121)
    assert DCT(12) == DCT(12)
    assert DCT('10 kB') == DCT(10*1024)
    assert DCT('10kB') == DCT(10*1024)
    assert DCT('10B') == DCT(10)
    assert DCT('1024b') == DCT(128)
    
    assert DCT('1024b') == 128
    assert DCT('1024b') != 129
    
    
    print DCT('0')
