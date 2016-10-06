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

def wait_tcp_accessible(address, timeout, interval=5, location=None ):
    '''等待TCP网络端口可以访问
    '''
    if location is None:
        location = settings.QT4S_DEFAULT_LOCATION
    proxy = ProxyController().get_tcp_proxy(location)
    t0 = time.time()
    retry_cnt = 0
    while time.time() - t0 < timeout:
        try:
            if proxy:
                with proxy:
                    s = socket.socket()
                    s.settimeout(interval)
                    s.connect(address)
            else:
                s = socket.socket()
                s.settimeout(interval)
                s.connect(address)
        except (socket.error, Socks5Error):
            pass
        else:
            s.close()
            return            
        retry_cnt += 1
    raise RuntimeError("%s秒内重试了%s次，主机%s:%d不可访问" % (timeout, retry_cnt, address[0], address[1]))


def wait_sshd_ready( address, ssh_passwd, timeout, interval=10, location=None, ssh_username='root'):
    '''等待SSH服务准备就绪
    '''
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
    if location is None:
        location = settings.QT4S_DEFAULT_LOCATION
    t0 = time.time()
    retry_cnt = 0
    proxy = ProxyController().get_tcp_proxy(location)
    while time.time() - t0 < timeout:
        try:
            if proxy:
                with proxy:
                    ssh.connect(address[0], address[1], ssh_username, ssh_passwd)
            else:
                ssh.connect(address[0], address[1], ssh_username, ssh_passwd)
        except paramiko.SSHException, e:
            if not e.args[0].startswith('Error reading SSH protocol banner'):
                raise
            else:
                retry_cnt += 1
                continue
        except Socks5Error, e:
            if not e.args[0].endswith('Connection refused'):
                raise
            else:
                retry_cnt += 1
        else:
            return            
    raise RuntimeError("%s秒内重试了%s次，SSHD %s:%d不可访问" % (timeout, retry_cnt, address[0], address[1]))
