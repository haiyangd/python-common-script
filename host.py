# -*- coding: utf-8 -*-
'''主机操作接口
'''
#2016/03/09 新建


import os
import datetime
import re
import socket
import time

import paramiko

from testbase.conf import settings
from qt4s._proxy import ProxyController
        
from qclib.util import DCT

class IHost(object):
    '''主机操作接口
    '''
    def close(self):
        '''关闭连接
        '''
        pass
              
    def get_cpu_count(self):
        '''获取对应的CPU核数
        '''    
        raise NotImplementedError()
    
    def get_memory_size(self):
        '''获取内存大小
        '''
        raise NotImplementedError()
    
#     def process_create(self, name ):
#         '''创建一个对应名称的进程
#         '''
#         raise NotImplementedError()
#         
#     def process_exist(self, command ):
#         '''对应的进程是否存在
#         
#         :param command: 进程命令行参数，支持正则表达式
#         '''
#         raise NotImplementedError()
# 
#     def process_exist_like(self, command ):
#         '''对应的进程是否存在（模糊匹配）
#         
#         :param command: 进程命令行参数正则表达式
#         '''
#         raise NotImplementedError()
    
    def network_can_reach(self, address ):
        '''检查网络是否可达
        '''
        raise NotImplementedError()
    
    def push_file(self, local, remote ):
        '''传输文件
        '''
        raise NotImplementedError()
        
class LinuxSSHSession(IHost):
    '''Linux主机
    '''
    def __init__(self, host, location=None, ssh_password=None, key_filename=None, ssh_username='root', ssh_port=22 ):
        '''构造函数
        
        :param host: 主机地址
        :param location: 主机所在区域
        :param ssh_password: 密码，如果不提供则使用QT4S默认的密钥登录
        :param key_filename: 密钥文件，如果不提供则使用QT4S默认的密钥登录
        :param ssh_username: 用户名
        :param ssh_port: 端口号
        '''
        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if location is None:
            location = settings.QT4S_DEFAULT_LOCATION
        self._proxy = ProxyController().get_tcp_proxy(location)
        self._sftp = None
        if self._proxy:
            with self._proxy:
                self._connect(host, ssh_port, ssh_username, ssh_password, key_filename)
        else:
            self._connect(host, ssh_port, ssh_username, ssh_password, key_filename)
            
    def _connect(self, host, ssh_port, ssh_username, ssh_password, key_filename):
        #self._wait_accessible(host, ssh_port)
        if ssh_password:
            self._ssh.connect(host, ssh_port, ssh_username, ssh_password, banner_timeout=60)
        else:
            if key_filename is None:
                key_filename = os.path.join(os.path.dirname(os.path.dirname(__file__)), *settings.QC_SSH_PRIVATE_KEY.split('.'))
            self._ssh.connect(host, ssh_port, ssh_username, key_filename=key_filename, banner_timeout=60)
            
    def _get_sftp(self):
        if self._sftp is None:
            self._sftp = paramiko.SFTPClient.from_transport(self._ssh.get_transport())
        return self._sftp
        
#     def _wait_accessible(self, host, port, timeout=15, inteval=1 ):
#         '''等待主机可以连接
#         '''
#         t0 = time.time()
#         retry_cnt = 0
#         while time.time() - t0 < timeout:
#             try:
#                 s = socket.socket()
#                 s.settimeout(inteval)
#                 s.connect((host, port))
#             except socket.error:
#                 pass
#             else:
#                 s.close()
#                 return
#             
#             retry_cnt += 1
#             #time.sleep(inteval)
#             
#         raise RuntimeError("%s秒内重试了%s次，主机%s:%d不可访问" % (timeout, retry_cnt, host, port))
            
        
    def close(self):
        '''关闭连接
        '''
        self._ssh.close()
        
    def exec_command(self, command ):
        '''执行Shell命令
        '''
        if self._proxy:
            with self._proxy:
                return self._ssh.exec_command(command)
        else:
            return self._ssh.exec_command(command)
        
    def cpuinfo(self):
        '''查询CPU信息，返回列表，列表元素为每个CPU核详细信息
        '''
        _, out, _ =  self.exec_command('cat /proc/cpuinfo')
        result = out.read()
        if not result:
            raise RuntimeError("cat /proc/cpuinfo执行失败")
        
        cpuinfos = []
        curr_cpuinfo = {}
        for it in result.split('\n'):
            if not it:
                if curr_cpuinfo:
                    cpuinfos.append(curr_cpuinfo)
                    curr_cpuinfo = {}
                continue
            k, v = it.split(':', 1)
            curr_cpuinfo[k.strip()] = v.strip()
        return cpuinfos
    
    def meminfo(self):
        '''查询内存信息
        '''
        _, out, _ =  self.exec_command('cat /proc/meminfo')
        result = out.read()
        meminfo = {}
        for it in result.split('\n'):
            if not it:
                continue
            k, v = it.split(':', 1)
            meminfo[k.strip()] = v.strip()
        return meminfo
    
    def uname(self):
        '''内核信息
        '''
        _, out, _ =  self.exec_command('uname -a')
        result = out.read()
        return result
        
    def _parse_table_like_stream(self, content, colnum=None ):
        '''格式化列表式的输出内容
        '''
        lines = content.split('\n')
        if colnum:
            titles = lines[0].split(colnum-1)
        else:
            titles = lines[0].split()
        items_cnt = len(titles)
        results = []
        for line in lines[1:]:
            if not line:
                continue
            items = line.split(None, items_cnt-1)
            result = {}
            for idx, item in enumerate(items):
                result[titles[idx].strip()] = item.strip()
            results.append(result)
        return results
    
    def df(self):
        '''磁盘信息
        '''
        _, out, _ =  self.exec_command('df -h')
        return self._parse_table_like_stream(out.read(), colnum=7)
#         result = out.read()
#         lines = result.split('\n')
#         titles = lines[0].split(None,6)
#         df_infos = []
#         for it in lines[1:]:
#             if not it:
#                 continue
#             df_info = {}
#             for idx, it in enumerate(it.split(None,6)):
#                 df_info[titles[idx]] = it
#             df_infos.append(df_info)
#         return df_infos
    
    def uptime(self):
        '''系统运行时长
        '''
        _, out, _ =  self.exec_command('cat /proc/uptime')
        result = out.read()
        uptime_seconds = float(result.split()[0])
        return datetime.timedelta(seconds=uptime_seconds)
        
    def ps(self, *args):
        '''查询进程列表
        '''
        _, out, _ =  self.exec_command('ps %s' % (' '.join(args)))
        return self._parse_table_like_stream(out.read())
#         result = out.read()
#         lines = result.split('\n')
#         titles = lines[0].split()
#         items_cnt = len(titles)
#         procs = []
#         for line in lines[1:]:
#             if not line:
#                 continue
#             items = line.split(None, items_cnt-1)
#             proc = {}
#             for idx, item in enumerate(items):
#                 proc[titles[idx].strip()] = item.strip()
#             procs.append(proc)
#         return procs
                
    def get_cpu_count(self):
        '''获取对应的CPU核数
        '''    
        return len(self.cpuinfo())
    
    def get_memory_size(self):
        '''获取内存大小
        '''    
        return DCT(self.meminfo()['MemTotal'])
    
#     def process_create(self, name ):
#         '''创建一个对应名称的进程
#         '''
#         self.exec_command("echo '#!/bin/bash' >> %s" % name)
#         self.exec_command('echo sleep 10d >> %s' % name)
#         self.exec_command('chmod a+x %s' % name)
#         self.exec_command('./%s &' % name)
#      
#     def process_exist(self, command ):
#         '''对应的进程是否存在
#         
#         :param command: 进程命令行参数，支持正则表达式
#         '''
#         for it in self.ps('aux'):
#             if command == it['COMMAND']:
#                 return True
#         return False
#     
#     def process_exist_like(self, command ):
#         '''对应的进程是否存在（模糊匹配）
#         
#         :param command: 进程命令行参数正则表达式
#         '''
#         for it in self.ps('aux'):
#             if re.match(command, it['COMMAND']):
#                 #print it['COMMAND']
#                 return True
#         return False
    
    def network_can_reach(self, address ):
        '''检查网络是否可达
        '''
        _, out, _ = self.exec_command('ping -c 1 -q %s' % address)
        result = out.read()
        if '1 packets transmitted, 1 received' in result:
            return True
        else:
            return False
        
    def push_file(self, local, remote ):
        '''传输文件
        '''
        sftp = self._get_sftp()
        sftp.put(local, remote)
        
    def list_disk(self):
        '''磁盘列表
        '''
        _, out, _ = self.exec_command('fdisk -l')
        disks = []
        pattern = re.compile(r'Disk (?P<disk>/dev/[a-zA-Z_0-9]+): [a-zA-Z_0-9. ]+, (?P<bytes>\d+) bytes')
        for line in out.read().split('\n'):
            result = pattern.match(line)
            if result:
                disks.append({'disk': result.group('disk'),
                              'bytes': result.group('bytes')})
        return disks
    
    def has_disk(self, disk ):
        '''是否有磁盘
        '''
        for it in self.list_disk():
            if it['disk'] == disk:
                return True
        else:
            return False
        
    def get_disk_size(self, disk ):
        '''获取磁盘大小
        '''
        for it in self.list_disk():
            if it['disk'] == disk:
                return DCT(it['bytes'])
        else:
            return False
        
    def list_partition(self):
        '''分区列表
        '''
        _, out, _ = self.exec_command('cat /proc/partitions')
        return self._parse_table_like_stream(out.read())
        
    def has_partition(self, name ):
        '''是否有分区
        '''
        for it in self.list_partition():
            if it['name'] == name:
                return True
        else:
            return False
        
    def format_disk_and_create_partition(self, dev_path, partition_size ):
        '''格式化磁盘并创建一个分区
        '''
        self.exec_command("parted -s %s mklabel gpt" % dev_path)
        self.exec_command("parted -s %s mkpart primary 0 %s" % (dev_path, partition_size))
        self.exec_command("mkfs.ext4 -T largefile %s1" % dev_path)
        
    def mount_partition(self, dev_path, mount_point ):
        '''挂载分区
        '''
        self.exec_command("mkdir -p %s" % mount_point)
        self.exec_command("mount %s %s" % (dev_path, mount_point))
        
class WindowsRMSession(IHost):
    '''Windows主机
    
    
    注意，目前需要在云主机上打开winrm才能正常调用，执行以下命令可以开启：
    
    $ winrm quickconfig -quiet
    $ winrm set winrm/config/client/auth @{Basic="true"}
    $ winrm set winrm/config/service/auth @{Basic="true"}
    $ winrm set winrm/config/service @{AllowUnencrypted="true"}

    '''
    def __init__(self, host, password, username='Administrator'):
        '''构造函数
        
        :param host: 主机地址
        :param password: 密码
        :param username: 用户名
        '''
        import winrm
        self._session = winrm.Session(host, auth=(username, password))
              
    def wmic(self, role ):
        '''通过WMIC获取信息
        '''
        result = self._session.run_cmd('wmic %s' % role)
        lines = []
        for line in result.std_out.split('\n'):
            line = line.strip()
            if not line:
                continue
            lines.append(line)

        field_info = {}
        sidx = 0
        inspace = False
        attrname = ''
        
        for idx, c in enumerate(lines[0]):
            if c == ' ':
                inspace = True
            else:
                if inspace == True:
                    inspace = False
                    field_info[attrname] = sidx, idx
                    attrname = c
                    sidx = idx
                else:
                    attrname += c   
            
        infos = []        
        for line in lines[1:]:
            info = {}
            for attrname in field_info:
                sidx, eidx = field_info[attrname]
                info[attrname] = line[sidx:eidx].strip()
            infos.append(info)
        return infos
                
    def get_cpu_count(self):
        '''获取对应的CPU核数
        '''    
        return len(self.wmic('cpu'))
    
    def get_memory_size(self):
        '''获取内存大小
        '''
        kbytes = 0
        for it in self.wmic('memphysical'):
            kbytes += long(it['MaxCapacity'])
        return DCT(kbytes, 'kB')
    
    def network_can_reach(self, address ):
        '''检查网络是否可达
        '''
        result = self._session.run_cmd('ping -n 1 %s' % address)
        if '100% loss' in result.std_out:
            return False
        if '100% 丢失' in result.std_out:
            return False
        return True
        
        
class KVMHost(LinuxSSHSession):
    '''KVM母鸡
    '''
    def get_hypervisor(self):
        '''返回改主机的hypervisor
        '''
        _, o, _ = self.exec_command('lsmod | grep kvm')
        result = o.read()
        if 'kvm' in result:
            return 'kvm'
        
        _, o, _ = self.exec_command('uname -r')
        result = o.read()
        if 'xen' in result:
            return 'xen'
        
        return 'unknown'
            
    def get_cpu(self):
        '''返回CPU类型
        '''
        _, o, _ = self.exec_command('cat /proc/cpuinfo')
        for it in o.read().split('\n'):
            if it.startswith('model name'):
                return it.split(":",1)[1].strip()
        return 'unknown'
        
    def has_cbs(self):
        '''是否支持CBS
        '''
        for it in self.ps('aux'):
            if it['COMMAND'].startswith('./tbsd_watchdog'):
                return True
        else:
            return False

    def list_vm(self):
        '''查看该主机的全部VM
        '''
        _, o, _ = self.exec_command('virsh list --all')
        result = o.read()
        lines = result.split('\n')
        titles = lines[0].split()
        vms = []
        for it in lines[2:]: #skip seperator line
            if not it:
                continue
            vals = it.split(None, len(titles))
            vm = {}
            for idx, name in enumerate(titles):
                vm[name] = vals[idx]
            vms.append(vm)
        return vms

    def vm_console(self, uuid ):
        '''子机Console
        '''
        channel = self._ssh.invoke_shell()
        channel.send('virsh console %s\n' % uuid )
        while not channel.recv_ready():
            time.sleep(1)
        while channel.recv_ready():
            print channel.recv(1024)
        
        channel.send('\n')
        while not channel.recv_ready():
            time.sleep(1)
        while channel.recv_ready():
            print channel.recv(1024)
        
        channel.send('root\n')
        while not channel.recv_ready():
            time.sleep(1)
        while channel.recv_ready():
            print channel.recv(1024)
            
        channel.send('isd@cloud\n')
        while not channel.recv_ready():
            time.sleep(1)
        while channel.recv_ready():
            print channel.recv(1024)
            
            
            
        
        channel.send('ls')
        while not channel.recv_ready():
            time.sleep(1)
        while channel.recv_ready():
            print channel.recv(1024)
        
        
        
        channel.send('exit\n')
        while not channel.recv_ready():
            time.sleep(1)
        while channel.recv_ready():
            print channel.recv(1024)
            
        
        print channel.recv_exit_status()
            

        
    
    
if __name__ == '__main__':
    
    vm = LinuxSSHSession('119.29.160.208')
    #print vm.process_exist_like('.*RebootInstanceTestScript_1457591554.51')
    #vm = LinuxMachine('119.29.160.201')
    print vm.uptime()
    
    #print vm.network_can_reach('www.baidu.com')
    #print vm.network_can_reach('10.0.0.2')
    

#     vm = WindowsMachine('182.254.226.60', 'Tencent#45678')
#     print vm.get_cpu_count()
#     #print vm.network_can_reach('www.baidu.com')
#     print vm.get_memory_size().gigabytes
#     
#     
#     print vm.process_exist('explorer.exe')

#     kvm = KVMHost('10.249.97.20', ssh_port=36000, ssh_password=settings.QC_CHECK_HOST_PASSWD)
#     kvm.vm_console('4ce00080-1f38-401d-b625-df9a17fa83ae')
 
