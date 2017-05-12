python生成随机mac地址
#!/usr/bin/python
import random
def randomMAC():
        mac = [ 0x52, 0x54, 0x00,
                random.randint(0x00, 0x7f),
                random.randint(0x00, 0xff),
                random.randint(0x00, 0xff) ]
        return ':'.join(map(lambda x: "%02x" % x, mac))
print randomMAC()

python生成随机密码或随机字符串

import string,random 
def makePassword(minlength=5,maxlength=25): 
  length=random.randint(minlength,maxlength) 
  letters=string.ascii_letters+string.digits # alphanumeric, upper and lowercase 
  return ''.join([random.choice(letters) for _ in range(length)]) 



Shell 获取指定网卡IP，兼容公司各种Linux

现在现网Tlinux2.2已经越来越多了，之前shell使用 ifconfig 来获取指定网卡IP已不再通用，因此抽空写了个脚本，基于 ip 命令获取指定网卡的IP地址，理论上支持ip命令的Linux都是兼容的。

Ps：另附上网上找的Python版本，经供参考。

#!/bin/bash
###############################################
# 获取指定网卡的IP地址, 兼容现网所有Linux版本     #
# 已测试的系统：Tlinux 、SUSE、Slackware、Centos#
# Usage：                                     # 
# eth1ip=$(get_ip_of_interface)               #
# eth0ip=$(get_ip_of_interface eth0)          #
###############################################

get_ip_of_interface()
{
   local iface=${1:-eth1}
   /sbin/ip addr | grep "$iface" 2>/dev/null | \
   awk -F '[/ ]+' '/inet / {print $3}'
   # 返回grep的状态，可用于判断$iface是否存在
   return ${PIPESTATUS[1]}
}


################### 华丽的分割线 ###################
#!/usr/bin/python
# Python 版本获取网卡IP
# 可 shell 调用： eth1ip=$(python get_ip.py) 
import socket
import fcntl
import struct
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])
print get_ip_address('eth1') #这样就获取了eth1的IP地址了

shell脚本重试函数 
支持设置重试次数，命令成功时的退出码，重试间隔时间
# Usage: retry retry_max_times success_exit_code sleep_seconds_between_failure command_and_argument
function retry {
  if [ $# -le 3 ]; then
	  echo "Usage: retry retry_max_times success_exit_code sleep_seconds_between_failure command_and_argument"
	  return 2
  fi
  local retry_max=$1
  local succ_exit_code=$2
  local sleep_seconds=$3
  shift 3
 
  local count=$retry_max
  while [ $count -gt 0 ]; do
    "$@"
	if [ $? -eq ${succ_exit_code} ]; then
		break;
	fi
    count=$(($count - 1))
    sleep $sleep_seconds
  done
 
  [ $count -eq 0 ] && {
    echo "Retry failed [$retry_max]: $@" >&2
    return 1
  }
  return 0
}

# 重试三次，命令成功时的退出码为0，失败时sleep 10s
retry 3 0 10 ping foo.bar
      
Shell 实现多任务并发 
场景：
需要控制并发进程数

优点：
用xargs命令实现，简单方便。

说明：
xargs -P参数，同时运行的最大进程数
for ((i = 0; i < 20; i++))
do
        echo "./a.out $i"
done | xargs -0 -I'{}' -n1 -P4 sh -c '{}'

通过shell脚本添加删除crontab任务 
很多时候，比如在实现后台程序的自动化安装卸载的时候，我们需要通过脚本自动化添加删除crontab任务。假设我们需要针对程序安装目录下的start.sh
添加删除crontab任务，我们在当前目录下创建addcrontab.sh和delcrontab.sh脚本：
############## version 0.2 -- 考虑重复问题(感谢riverzheng的指点) ###########

### addcrontab.sh ###
#! /bin/sh

unset IFS
unset OFS
unset LD_PRELOAD
unset LD_LIBRARY_PATH
export PATH='/usr/sbin:/sbin:/usr/bin:/bin'

# 指定为哪个用户添加任务项
user="root"

check_user()
{
	curr="`whoami`"
    if [[ "root" != $curr || $user != $curr ]]; then
        echo "permission denied"
        exit 1
    fi    
}

check_exist()
{
   str="$(crontab -u $user -l | grep "$1")"
   if [ -n "$str" ]; then
       echo "crontab item existed"
       exit 1
   fi  
}

check_user
# 获取当前脚本的目录
dir="$( cd "$( dirname $0 )" && pwd )"
bin="$dir/start.sh"
check_exist $bin
# 创建添加到crontab的任务项，可以根据实际情况构造，比如接受传入参数进行构造
line="*/1 * * * * $bin > /dev/null 2>&1 &"
# 将任务项添加到crontab列表
(crontab -u $user -l; echo "$line") | crontab -u $user -


### delcrontab.sh ###
#! /bin/sh

check_user
dir="$( cd "$( dirname $0 )" && pwd )"
line="$dir/start.sh"
# 从crontab列表删除指定任务项
(crontab -u $user -l | grep -v "$line") | crontab -u $user -


### delcrontab.sh ###
#! /bin/sh

check_user
dir="$( cd "$( dirname $0 )" && pwd )"
line="$dir/start.sh"
# 从crontab列表删除指定任务项
(crontab -u $user -l | grep -v "$line") | crontab -u $user -

########################## version 0.1 ##########################

### addcrontab.sh ###
#! /bin/sh

# 指定为哪个用户添加任务项
user="root"

check_user()
{
	curr="`whoami`"
    if [[ "root" != $curr || $user != $curr ]]; then
        echo "permission denied"
        exit 1
    fi    
}

check_user
# 获取当前脚本的目录
dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# 创建添加到crontab的任务项，可以根据实际情况构造，比如接受传入参数进行构造
line="*/1 * * * * $dir/start.sh > /dev/null 2>&1 &"
# 将任务项添加到crontab列表
(crontab -u $user -l; echo "$line") | crontab -u $user -




### delcrontab.sh ###
#! /bin/sh

check_user
dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
line="$dir/start.sh"
# 从crontab列表删除指定任务项
(crontab -u $user -l | grep -v "$line") | crontab -u $user -      
 
简单的多SH命令并发控制 
适用于有多个SH命令可以并行执行，同时又希望并发数控制的情况。

优点：使用简单，可以达到并行执行的效果，且并行度可控。
缺点：使用FIFO实现，代码中绑定了文件描述符6，存在文件描述符冲突的可能。
      
function DoParallelSHWork()
{

    function DoParallelSHWorkUsage()
    {
        #打印DoParallelSHWork使用帮助
        echo $1
        echo 'Usage:   DoParallelSHWork ParallelNum Task1 Task2 Task3 ... TaskN'
        echo 'Example: DoParallelSHWork 2 "sleep 10" "sleep 11" "echo haha" "sleep 3"'
    }


    #参数个数
    ParameterCount=$#    
    if [[ $ParameterCount -lt 2 ]]
    then
        DoParallelSHWorkUsage "ParameterCount less than 2"
        return 1
    fi
    

    #声明并行任务进程个数
    ParallelNum=$1    
    if [ "$1" -gt 0 ] 2>/dev/null
    then 
      :
    else 
      DoParallelSHWorkUsage "ParallelNum $ParallelNum is not a number"
      return 1
    fi
    
    
    
    #使用FIFO来做并行控制
    #使用进场号，在tmp目录下创建FIFO   
    tmp_fifofile="/tmp/$$.fifo"
    #echo "mkfifo: $tmp_fifofile"
    mkfifo $tmp_fifofile
    #将对应的FIFO文件绑定为文件描述符6
    exec 6<>$tmp_fifofile
    #至此，已经可以删除FIFO文件，但其实对于该进程，这个文件依然可读写
    rm -f $tmp_fifofile
    
    #初始化FIFO的管道内容，写入ParallelNum个换行符   
    for (( i = 0; i < $ParallelNum; i++ ))
    do
        echo
    done >&6
    
    
    shift #去掉并发数，剩下的就是具体的任务了
    while [[ -n "$1" ]]
    do
        read -u6
        {
            echo `date +"%Y-%m-%d %H:%M:%S"` running $1
            (eval "$1") #子shell中执行
            echo >&6
            echo `date +"%Y-%m-%d %H:%M:%S"` done $1
        } &
        
        shift #下一个任务
    done
    
    wait #等待任务完成，完成不代表没有执行错误，后续需要进一步检查任务运行的实际结果
    return 0
}

#test
#DoParallelSHWork 2 "sleep 11" "echo haha" "sleep 13" 'cd /tmp && echo $PWD'

一条命令找出端口冲突的进程 
通过lsof找出端口冲突的进程
lsof  -P -n -i |  perl -alne '$p{ "$F[-1]:$F[-2]"}->{$F[0]} += 1; END{ for $k (keys %p){ %v = %{$p{$k}}; printf("%s => %s\n", $k, join("\,\t", keys(%v))) if keys(%v) > 1}}'

服务器时间同步脚本 
因为偶尔遇到由于各种原因，我们在使用ntpdate的时候无法成功的跟服务器同步时间的现象，而一般情况下我们对时间的精度要求都不是太高，所以想到可以使用根据HTTP头里面的信息来校时的做法。原作者使用php编写脚本，但是考虑到很多机器是没有php环境的，
因此选用shell来进行代码的编写，尽量保证通用。
#!/bin/bash
#Set localtime based on server's http response time
#By Citruswang
 
host="www.google.com"
#server host name
timeout="5"
#acceptable time out for curl
proxyHost=""
proxyPort=""
proxyUser=""
proxyPass=""
#define proxy settings
 
export TIMEFORMAT=$'Time cost: %lR'
header=$((time curl --proxy "$proxyHost:$proxyPort" --proxy-user "$proxyUser:$proxyPass" --connect-timeout $timeout --silent --head $host) | tr -d '\r' 2>&1)
#command to get server's http response header
error_code=$?
if [[ $error_code -ne 0 ]]; then
    echo "cUrl error on code $error_code"
    exit $error_code
fi
 
#Sun, 06 Nov 1994 08:49:37 GMT ; RFC 822, updated by RFC 1123
regex1="Date: ((Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-9]{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT)"
#Sunday, 06-Nov-94 08:49:37 GMT ; RFC 850, obsoleted by RFC 1036
regex2="Date: ((Mon|Tues|Wednes|Thurs|Fri|Satur|Sun)day, [0-9]{2}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT)"
#Sun Nov 6 08:49:37 1994 ; ANSI C's asctime() format
regex3="Date: ((Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) *[0-9]{1,2} [0-9]{1,2}:[0-9]{2}:[0-9]{2} [0-9]{4})"
#use regex to Match time in server's http response header
 
if [[ $header =~ $regex1 ]]; then
    server_time=${BASH_REMATCH[1]}
    #get date time
elif [[ $header =~ $regex2 ]]; then
    server_time=${BASH_REMATCH[1]}
    #get date time
elif [[ $header =~ $regex3 ]]; then
    server_time=${BASH_REMATCH[1]}
    #get date time
else
    error_code=$?
    echo "Get time from server failed! Error code $error_code"
    exit $error_code
fi
 
#date_str=$(date --date="$server_time")
#convert date format
set_result=$(date -s "$server_time")
#set local time
error_code=$?
if [[ $error_code -ne 0 ]]; then
    echo "Set time with date -s error on code $error_code"
    exit $error_code
else
    echo $set_result
    regex="(Time cost: [0-9]*m[0-9]*\.[0-9]*s)"
    if [[ $header =~ $regex ]]; then
        echo ${BASH_REMATCH[1]}
    fi
fi

使用sort 和 uniq 做集合运算 
# a 并 b
cat a b | sort | uniq 

# a 交 b
cat a b | sort | uniq -d
    
Getting MAC Address
#!/usr/bin/python
import fcntl, socket, struct
def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

print getHwAddr('eth0')


move_files_over_x_days.py - This will move all the files from the source directory that are over 240 days old to the destination directory.


import shutil
import sys
import time
import os

src = 'u:\\test'  # Set the source directory
dst = 'c:\\test'  # Set the destination directory

now = time.time()  # Get the current time
for f in os.listdir(src):  # Loop through all the files in the source directory
    if os.stat(f).st_mtime < now - 240 * 86400:  # Work out how old they are, if they are older than 240 days old
        if os.path.isfile(f):  # Check it's a file
            shutil.move(f, dst)  # Move the files

Check and rebuild the rpm database
rpmdb.py
#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2016, Jay <smile665@gmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import syslog
import subprocess
import time

DOCUMENTATION = '''
---
module: rpmdb
short_description: Manages the rpm database.
description:
  - Check and rebuild the rpm database.
version_added: "2.0"
options:
  action:
    choices: [ "check", "rebuild" ]
    description:
      - The action name.
      - check: only check if rpm db is OK or not.
      - rebuild: rebuild rpm db if it is NOT OK.
    required: false
    default: check
  timeout:
    description:
      - The TIMEOUT seconds when checking rpm db.
    required: false
    default: 10
notes: []
requirements: [ rpm, rm ]
author: Jay <smile665@gmail.com>
'''

EXAMPLES = '''
- rpmdb: action=check
- rpmdb: action=rebuild
'''

# ==============================================================


RPMBIN = '/bin/rpm'


def log(msg):
    syslog.openlog('ansible-%s' % os.path.basename(__file__))
    syslog.syslog(syslog.LOG_NOTICE, msg)


def execute_command(module, cmd):
    log('Command %s' % '|'.join(cmd))
    return module.run_command(cmd)


def check_db(module, timeout=10):
    rc = 0
    logfile = '/tmp/rpm-qa.log'
    elapsed_time = 0
    cmd = '%s -qa &> %s' % (RPMBIN, logfile)
    child = subprocess.Popen(cmd, shell=True)
    while elapsed_time <= timeout:
        child_ret = child.poll()
        if child_ret is None:  # child still running
            time.sleep(1)
            elapsed_time += 1
        elif child_ret == 0:
            if 'error:' in open(logfile, 'r').read():
                rc = 1
                break
            else:  # cmd is excuted with no error.
                break
        else:
            rc = 2
            break
    if elapsed_time > timeout:
        child.kill()
        time.sleep(1)
        rc = 3
    return rc


def rebuild_db(module):
    rmdb_cmd = ['rm', '-f', '/var/lib/rpm/__db.*']
    rc1, out1, err1 = execute_command(module, rmdb_cmd)
    cmd = [RPMBIN, '--rebuilddb']
    rc, out, err = execute_command(module, cmd)
    return (rc == 0) and (rc1 == 0)


# main
def main():

    # defining module
    module = AnsibleModule(
        argument_spec=dict(
            action=dict(required=False, default='check', choices=['check', 'rebuild']),
            timeout=dict(required=False, default=10, type='int')
        )
    )

    changed = False
    msg = ''
    action = module.params['action']
    timeout = module.params['timeout']
    check_cmd = 'rpm -qa'

    if action == 'check':
        rc = check_db(module, timeout)
        if rc == 1:
            module.fail_json(msg='Error when running cmd: %s' % check_cmd)
        elif rc == 2:
            module.fail_json(msg='return code error. cmd: %s' % (check_cmd))
        elif rc == 3:
            module.fail_json(msg='Timeout %d s. cmd: %s' % (timeout, check_cmd))
        elif rc == 0:
            msg = 'OK. cmd: %s' % check_cmd
    elif action == 'rebuild':
        rc = check_db(module, timeout)
        if rc != 0:
            if rebuild_db(module):
                changed = True
                msg = 'OK. rm -f /var/lib/rpm/__db.00*; rpm --rebuilddb'
            else:
                msg = 'Error. rm -f /var/lib/rpm/__db.00*; rpm --rebuilddb'
                module.fail_json(msg=msg)

    module.exit_json(
        changed=changed,
        action=action,
        msg=msg
    )

# this is magic, see lib/ansible/executor/module_common.py
#<<INCLUDE_ANSIBLE_MODULE_COMMON>>
main()      
ping_subnet.py - After supplying the first 3 octets it will scan the final range for available addresses.
ping_subnet.py
# Script Name		: ping_subnet.py
# Author				: Craig Richards
# Created				: 12th January 2012
# Last Modified		:
# Version				: 1.0

# Modifications		:

# Description			: After supplying the first 3 octets it will scan the final range for available addresses

import os						# Load the Library Module
import subprocess			# Load the Library Module
import sys						# Load the Library Module

filename = sys.argv[0]																				# Sets a variable for the script name

if '-h' in sys.argv or '--h' in sys.argv or '-help' in sys.argv or '--help' in sys.argv:	# Help Menu if called
    print '''
You need to supply the first octets of the address Usage : ''' + filename + ''' 111.111.111 '''
    sys.exit(0)
else:

    if (len(sys.argv) < 2): 																				# If no arguments are passed then display the help and instructions on how to run the script
        sys.exit (' You need to supply the first octets of the address Usage : ' + filename + ' 111.111.111')

    subnet = sys.argv[1]																				# Set the variable subnet as the three octets you pass it

    if os.name == "posix":																			# Check the os, if it's linux then
        myping = "ping -c 2 "																			# This is the ping command
    elif os.name in ("nt", "dos", "ce"):															# Check the os, if it's windows then
        myping = "ping -n 2 "																			# This is the ping command

    f = open('ping_' + subnet + '.log', 'w')															# Open a logfile
    for ip in range(2,255):																				# Set the ip variable for the range of numbers
        ret = subprocess.call(myping + str(subnet) + "." + str(ip) ,
            shell=True, stdout=f, stderr=subprocess.STDOUT) # Run the command pinging the servers
        if ret == 0:																							# Depending on the response
            f.write (subnet + "." + str(ip) + " is alive" + "\n")									# Write out that you can receive a reponse
        else:
f.write (subnet + "." + str(ip) + " did not respond" + "\n") # Write out you can't reach the box
      
check_ping.py 多进程检测ping，并取值

	默认开启4个进程，需要将hosts.txt IP列表文件放入同一目录下，IP列表每行一个，支持域名、IP

#!/usr/bin/python 
#coding:utf-8
import multiprocessing
import re 
import sys,os
import commands
import datetime
def  pinger(ip):
	cmd='ping -c 2 %s' % (ip.strip())
	ret = commands.getoutput(cmd)
	loss_re=re.compile(r"received, (.*) packet loss")
	packet_loss=loss_re.findall(ret)[0]
	rtt_re=re.compile(r"rtt min/avg/max/mdev = (.*) ")
	rtts=rtt_re.findall(ret)
	#rtt.split(["/"])
	rtt=rtts[0].split('/')
	rtt_min=rtt[0]
	rtt_avg=rtt[1]
	rtt_max=rtt[2]
	print "%s\t\t%s\t\t%s\t\t%s\t\t%s"%(ip,packet_loss,rtt_min,rtt_max,rtt_avg)



if __name__ == "__main__":
    if not os.path.exists("hosts.txt") :
	print "\033[31mhosts.txt文件不存在，请重试\033[0m"
	sys.exit(1)
    now=datetime.datetime.now()
    file=open('hosts.txt','r')
    pool=multiprocessing.Pool(processes=4)
    result=[]
    print "########%s###########"%now
    print "IPADDRSS\t\t\tLOSS\t\tMIN\t\tMAX\t\tAVG"
    for i in file.readlines():
        if len(i)==1 or i.startswith("#"):
           continue
        result.append(pool.apply_async(pinger,(i.strip(),))) 
    pool.close()           
pool.join()

cleanup_pid.py
#!/usr/bin/env python

import os
import subprocess

base_dir = '/tmp/pid_dir'
pid_files = ['ut.pid', 'ft.pid']
max_seconds = 48 * 3600


def check_pid(pid):
    """ Check For the existence of a unix pid. """
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


def get_elapsed_time(pid):
    '''get the elapsed time of the process with this pid'''
    cmd = 'ps -p %s -o pid,etime' % str(pid)
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    # get data from stdout
    proc.wait()
    results = proc.stdout.readlines()
    # parse data (should only be one)
    for result in results:
        try:
            result.strip()
            if result.split()[0] == str(pid):
                pidInfo = result.split()[1]
                # stop after the first one we find
                break
        except IndexError:
            pass    # ignore it
    else:
        # didn't find one
        print "Process PID %s doesn't seem to exist!" % pid
        return 0
    pidInfo = [result.split()[1] for result in results
               if result.split()[0] == str(pid)][0]
    pidInfo = pidInfo.partition("-")
    if pidInfo[1] == '-':
        # there is a day
        days = int(pidInfo[0])
        rest = pidInfo[2].split(":")
        hours = int(rest[0])
        minutes = int(rest[1])
        seconds = int(rest[2])
    else:
        days = 0
        rest = pidInfo[0].split(":")
        if len(rest) == 3:
            hours = int(rest[0])
            minutes = int(rest[1])
            seconds = int(rest[2])
        elif len(rest) == 2:
            hours = 0
            minutes = int(rest[0])
            seconds = int(rest[1])
        else:
            hours = 0
            minutes = 0
            seconds = int(rest[0])

    elapsed_time = days*24*3600 + hours*3600 + minutes*60 + seconds
    return elapsed_time


def remove_pid(pidfiles):
    '''remove pid files if the process is not running.'''
    for i in pidfiles:
        filepath = '%s/%s' % (base_dir, i)
        if os.path.exists(filepath):
            del_flag = 0
            with open(filepath) as f:
                pid = f.read()
                if not check_pid(int(pid)):
                    print 'pid file: %s' % i
                    print 'process does not exist with pid %s' % pid
                    del_flag = 1
                elif get_elapsed_time(pid) > max_seconds:
                    print 'elapsed_time is greater than max_seconds'
                    print 'tring to kill pid %s' % pid
                    os.kill(int(pid), 9)
                    del_flag = 1
            if del_flag:
                os.unlink(filepath)


if __name__ == '__main__':
remove_pid(pid_files)
      
#######################################################
args_kargs.py
# *-* encoding=utf-8 *-*
'''
just try to use *args and **kargs.
*args表示任何多个无名参数，它是一个tuple；**kwargs表示关键字参数，它是一个dict。并且同时使用*args和**kwargs时，必须*args参数列要在**kwargs前
'''

def foo(*args, **kwargs):
    print 'args = ', args
    print 'kwargs = ', kwargs
    print '---------------------------------------'

if __name__ == '__main__':
    foo(1,2,3,4)
    foo(a=1,b=2,c=3)
    foo(1,2,3,4, a=1,b=2,c=3)
foo('a', 1, None, a=1, b='2', c=3)

###########################################
 dnsmap.py
 #!/bin/python

"""
Based on WebMap: https://github.com/4rsh/python/blob/master/webmap.py
DNSMap - Developed by Arsh Leak.
$ wget https://github.com/4rsh/
"""

# Colours
D  = "\033[0m";  
W  = "\033[01;37m";  
O  = "\033[01;33m"; 
SUCESS = "\033[01;32m";
FAIL = "\033[01;31m";

import socket
import sys
import os
os.system("clear")
print O+ "+----------------------------------------------------------------------------+"
print "|                                      DNSMap                                |"
print "+----------------------------------------------------------------------------+"
print "|                            Development by Arsh Leak.                       |"
print "|                         $ Wget > http://github.com/4rsh                    |"
print "+----------------------------------------------------------------------------+"
print W+""
domain = raw_input("Set domain: ") # www.domain.com
 
try:
    ip = socket.gethostbyname( domain )
 
except socket.gaierror:
    print FAIL+'Invalid Domain.\n\n\n\n\n\n\n'
    sys.exit()
print SUCESS+"+-------------------------+"
print SUCESS+"| DNS   : " +ip+ "     |"
print SUCESS+"+-------------------------+"

###############################################################
md5sum.py
#!/usr/bin/python
#encoding=utf-8
import io
import sys
import hashlib
import string

def printUsage():
	print ('''Usage: [python] pymd5sum.py <filename>''')
	
def main():
	if(sys.argv.__len__()==2):
		#print(sys.argv[1])

		m = hashlib.md5()
		file = io.FileIO(sys.argv[1],'r')
		bytes = file.read(1024)
		while(bytes != b''):
			m.update(bytes)
			bytes = file.read(1024) 
		file.close()
		
		#md5value = ""
		md5value = m.hexdigest()
		print(md5value+"\t"+sys.argv[1])
		
		#dest = io.FileIO(sys.argv[1]+".CHECKSUM.md5",'w')
		#dest.write(md5value)
		#dest.close()
	
	else:
		printUsage() 
main()
################################################
muti-site.ini
[site]
url = http://www.361way.com/ 
username = 361way
password = nothing

[site2]
url = http://www.91it.org/ 
username = 91it
password = org

musite.py
from ConfigParser import SafeConfigParser

parser = SafeConfigParser()
parser.read('multisection.ini')

for section_name in parser.sections():
    print 'Section:', section_name
    print '  Options:', parser.options(section_name)
    for name, value in parser.items(section_name):
        print '  %s = %s' % (name, value)
print

#########################################################
log_timedRotate.py
#!/usr/bin/env python
# coding=utf-8
# site: www.361way.com   
# mail: itybku@139.com
# desc: Rotating logfile by times or size


import re
import subprocess
import logging
import socket,time
from logging.handlers import TimedRotatingFileHandler

LOG_FILE = "/var/log/ping/ping.log"

#logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',datefmt='%Y-%m-%d %I:%M:%S',filemode='w')   #for term print
logger = logging.getLogger()
logger.setLevel(logging.INFO)
fh = TimedRotatingFileHandler(LOG_FILE,when='M',interval=1,backupCount=30)
datefmt = '%Y-%m-%d %H:%M:%S'
format_str = '%(asctime)s %(levelname)s %(message)s '
#formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
formatter = logging.Formatter(format_str, datefmt)
fh.setFormatter(formatter)
logger.addHandler(fh)
#logging.info(msg)
#hdlr.flush()

#----------------------------------------------------------------------
def pinghost(host):
    ping = subprocess.Popen(["ping", "-c", "1",host],stdout = subprocess.PIPE,stderr = subprocess.PIPE)
    out, error = ping.communicate()
    if "icmp_seq" in  out:
        icmp_line = re.findall(r'\d+\sbytes(.*?)ms',out)
        logging.info('ping ' + host + str(icmp_line))
    else:
        logging.info('ping ' + host + ' fail')
        
        
def tcping(server, port):
    ''' Check if a server accepts connections on a specific TCP port '''
    try:
        start = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, port))
        s.close()
        #print server + ':' + str(port) + '/tcp - ' +  str(port) + ' port is open' + ' - time=' + str(round((time.time()-start)*10000)/10) + 'ms'
        msg = server + ':' + str(port) + '/tcp - ' +  str(port) + ' port is open' + ' - time=' + str((time.time()-start)*1000) + 'ms'
        logging.info(msg)
    except socket.error:
        msg = server + ':' + str(port) + ' port not open'
        logging.info(msg)

while 1:
    pinghost('passport.migu.cn')
    pinghost('112.17.9.72')
    tcping('passport.migu.cn',8443)
    tcping('112.17.9.72',8443)
#time.sleep(0.5)

##################################################################
知道这20个正则表达式，能让你少写1,000行代码
正则表达式，一个十分古老而又强大的文本处理工具，仅仅用一段非常简短的表达式语句，便能够快速实现一个非常复杂的业务逻辑。熟练地掌握正则表达式的话，能够使你的开发效率得到极大的提升。

正则表达式经常被用于字段或任意字符串的校验，如下面这段校验基本日期格式的JavaScript代码：

var reg = /^(\\d{1,4})(-|\\/)(\\d{1,2})\\2(\\d{1,2})$/; 
var r = fieldValue.match(reg);             
if(r==null)alert('Date format error!');

下面是技匠整理的，在前端开发中经常使用到的20个正则表达式。
1 . 校验密码强度

密码的强度必须是包含大小写字母和数字的组合，不能使用特殊字符，长度在8-10之间。

^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z]).{8,10}$

2. 校验中文

字符串仅能是中文。

^[\\u4e00-\\u9fa5]{0,}$

3. 由数字、26个英文字母或下划线组成的字符串

^\\w+$

4. 校验E-Mail 地址

同密码一样，下面是E-mail地址合规性的正则检查语句。

[\\w!#$%&'*+/=?^_`{|}~-]+(?:\\.[\\w!#$%&'*+/=?^_`{|}~-]+)*@(?:[\\w](?:[\\w-]*[\\w])?\\.)+[\\w](?:[\\w-]*[\\w])?

5. 校验身份证号码

下面是身份证号码的正则校验。15 或 18位。

15位：

^[1-9]\\d{7}((0\\d)|(1[0-2]))(([0|1|2]\\d)|3[0-1])\\d{3}$

18位：

^[1-9]\\d{5}[1-9]\\d{3}((0\\d)|(1[0-2]))(([0|1|2]\\d)|3[0-1])\\d{3}([0-9]|X)$

6. 校验日期

“yyyy-mm-dd“ 格式的日期校验，已考虑平闰年。

^(?:(?!0000)[0-9]{4}-(?:(?:0[1-9]|1[0-2])-(?:0[1-9]|1[0-9]|2[0-8])|(?:0[13-9]|1[0-2])-(?:29|30)|(?:0[13578]|1[02])-31)|(?:[0-9]{2}(?:0[48]|[2468][048]|[13579][26])|(?:0[48]|[2468][048]|[13579][26])00)-02-29)$

7. 校验金额

金额校验，精确到2位小数。

^[0-9]+(.[0-9]{2})?$

8. 校验手机号

下面是国内 13、15、18开头的手机号正则表达式。（可根据目前国内收集号扩展前两位开头号码）

^(13[0-9]|14[5|7]|15[0|1|2|3|5|6|7|8|9]|18[0|1|2|3|5|6|7|8|9])\\d{8}$

9. 判断IE的版本

IE目前还没被完全取代，很多页面还是需要做版本兼容，下面是IE版本检查的表达式。

^.*MSIE [5-8](?:\\.[0-9]+)?(?!.*Trident\\/[5-9]\\.0).*$

10. 校验IP-v4地址

IP4 正则语句。

\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b

11. 校验IP-v6地址

IP6 正则语句。

(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))

12. 检查URL的前缀

应用开发中很多时候需要区分请求是HTTPS还是HTTP，通过下面的表达式可以取出一个url的前缀然后再逻辑判断。

if (!s.match(/^[a-zA-Z]+:\\/\\//))
{
    s = 'http://' + s;
}

13. 提取URL链接

下面的这个表达式可以筛选出一段文本中的URL。

^(f|ht){1}(tp|tps):\\/\\/([\\w-]+\\.)+[\\w-]+(\\/[\\w- ./?%&=]*)?

14. 文件路径及扩展名校验

验证windows下文件路径和扩展名（下面的例子中为.txt文件）

^([a-zA-Z]\\:|\\\\)\\\\([^\\\\]+\\\\)*[^\\/:*?"<>|]+\\.txt(l)?$

15. 提取Color Hex Codes

有时需要抽取网页中的颜色代码，可以使用下面的表达式。

^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$

16. 提取网页图片

假若你想提取网页中所有图片信息，可以利用下面的表达式。

\\< *[img][^\\\\>]*[src] *= *[\\"\\']{0,1}([^\\"\\'\\ >]*)

17. 提取页面超链接

提取html中的超链接。

(<a\\s*(?!.*\\brel=)[^>]*)(href="https?:\\/\\/)((?!(?:(?:www\\.)?'.implode('|(?:www\\.)?', $follow_list).'))[^"]+)"((?!.*\\brel=)[^>]*)(?:[^>]*)>

18. 查找CSS属性

通过下面的表达式，可以搜索到相匹配的CSS属性。

^\\s*[a-zA-Z\\-]+\\s*[:]{1}\\s[a-zA-Z0-9\\s.#]+[;]{1}

19. 抽取注释

如果你需要移除HMTL中的注释，可以使用如下的表达式。

<!--(.*?)-->

20. 匹配HTML标签

通过下面的表达式可以匹配出HTML中的标签属性。

<\\/?\\w+((\\s+\\w+(\\s*=\\s*(?:".*?"|'.*?'|[\\^'">\\s]+))?)+\\s*|\\s*)\\/?>
					   
#############################################
check_url_list.py
#!/usr/bin/env python
"""
Script to check a list of URLs (passed on stdin) for response code, and for response code of the final path in a series of redirects.
Outputs (to stdout) a list of count of a given URL, response code, and if redirected, the final URL and its response code
Optionally, with verbose flag, report on all URL checks on STDERR
Copyright 2013 Jason Antman <jason@jasonantman.com> all rights reserved
This script is distributed under the terms of the GPLv3, as per the
LICENSE file in this repository.
The canonical version of this script can be found at:
<http://github.com/jantman/misc-scripts/blob/master/check_url_list.py>
"""

import sys
import urllib2

def get_url_nofollow(url):
    try:
        response = urllib2.urlopen(url)
        code = response.getcode()
        return code
    except urllib2.HTTPError as e:
        return e.code
    except:
        return 0

def main():
    urls = {}

    for line in sys.stdin.readlines():
        line = line.strip()
        if line not in urls:
            sys.stderr.write("+ checking URL: %s\n" % line)
            urls[line] = {'code': get_url_nofollow(line), 'count': 1}
            sys.stderr.write("++ %s\n" % str(urls[line]))
        else:
            urls[line]['count'] = urls[line]['count'] + 1

    for url in urls:
        if urls[url]['code'] != 200:
            print "%d\t%d\t%s" % (urls[url]['count'], urls[url]['code'], url)

if __name__ == "__main__":
main()
	
##################################
tail.py
!/usr/bin/env python

import collections
import os
import sys

BUF_SIZE = 4096

def Tail(file, num_lines = 10):
  with open(file) as f:
    lines_already_found = 0
    buffer_size = BUF_SIZE
    file_length = os.stat(file).st_size
    remain_length = file_length

    while remain_length:
      if buffer_size < remain_length:
        remain_length -= buffer_size
      else:
        buffer_size = remain_length
        remain_length = 0

      f.seek(remain_length)
      data = f.read(buffer_size)
      i = buffer_size
      while lines_already_found <= num_lines:
        i -= 1
        if i < 0:
          break
        if data[i] == '\n':
          lines_already_found += 1
      if lines_already_found == num_lines + 1:
        break

    f.seek(remain_length + i + 1)
    while True:
      data = f.read(BUF_SIZE)
      if data:
        sys.stdout.write(data)
      else:
        break

"""Comments in master"""
"""This is comments in experimental."""

def Tail2(file, num_lines= 10):
  with open(file) as f:
    d = collections.deque(f, 10)
  for item in d:
    sys.stdout.write(item)

if __name__ == '__main__':
Tail2(sys.argv[1])					  

#######################################
format_ip_with_mask					     
[root@VM_132_108_centos python]# python tmp.py 
111.111.0.0/16					     
[root@VM_132_108_centos python]# cat tmp.py 
import os, pickle, random, re, resource, select, shutil, signal, StringIO
import socket, struct, subprocess, sys, time, textwrap, traceback, urlparse
def ip_to_long(ip):
    # !L is a long in network byte order
    return struct.unpack('!L', socket.inet_aton(ip))[0]


def long_to_ip(number):
    # See above comment.
    return socket.inet_ntoa(struct.pack('!L', number))


def create_subnet_mask(bits):
    return (1 << 32) - (1 << 32-bits)


def format_ip_with_mask(ip, mask_bits):
    masked_ip = ip_to_long(ip) & create_subnet_mask(mask_bits)
    return "%s/%s" % (long_to_ip(masked_ip), mask_bits)

result = format_ip_with_mask('111.111.111.111', 16)
print result
					     
################################################
[root@VM_132_108_centos python]# python tmp.py 
32768
61000
[root@VM_132_108_centos python]# cat tmp.py 
import os, pickle, random, re, resource, select, shutil, signal, StringIO
import socket, struct, subprocess, sys, time, textwrap, traceback, urlparse
def get_ip_local_port_range():
    match = re.match(r'\s*(\d+)\s*(\d+)\s*$',
                     read_one_line('/proc/sys/net/ipv4/ip_local_port_range'))
    return (int(match.group(1)), int(match.group(2)))


def set_ip_local_port_range(lower, upper):
    write_one_line('/proc/sys/net/ipv4/ip_local_port_range','%d %d\n' % (lower, upper))

def read_one_line(filename):
    return open(filename, 'r').readline().rstrip('\n')

def write_one_line(filename, line):
    open_write_close(filename, line.rstrip('\n') + '\n')


def open_write_close(filename, data):
    f = open(filename, 'w')
    try:
        f.write(data)
    finally:
        f.close()
lower, upper = get_ip_local_port_range()
print lower
print upper
set_ip_local_port_range(lower, upper)

#########################################
[root@VM_132_108_centos python]# python tmp.py 
X-Lite3.0: [#############################100%#################################] 
[root@VM_132_108_centos python]# cat tmp.py 
import os, pickle, random, re, resource, select, shutil, signal, StringIO
import socket, struct, subprocess, sys, time, textwrap, traceback, urlparse
import warnings, smtplib, logging, urllib2
from threading import Thread, Event, Lock
try:
    import hashlib
except ImportError:
    import md5, sha

"""
Basic text progress bar without fancy curses features
"""


__all__ = ['ProgressBar']


class ProgressBar:
    '''
    Displays interactively the progress of a given task
    Inspired/adapted from code.activestate.com recipe #168639
    '''

    DEFAULT_WIDTH = 77

    def __init__(self, minimum=0, maximum=100, width=DEFAULT_WIDTH, title=''):
        '''
        Initializes a new progress bar
        @type mininum: integer
        @param mininum: mininum (initial) value on the progress bar
        @type maximum: integer
        @param maximum: maximum (final) value on the progress bar
        @type width: integer
        @param with: number of columns, that is screen width
        '''
        assert maximum > minimum

        self.minimum = minimum
        self.maximum = maximum
        self.range = maximum - minimum
        self.width = width
        self.title = title

        self.current_amount = minimum
        self.update(minimum)


    def increment(self, increment, update_screen=True):
        '''
        Increments the current amount value
        '''
        self.update(self.current_amount + increment, update_screen)


    def update(self, amount, update_screen=True):
        '''
        Performs sanity checks and update the current amount
        '''
        if amount < self.minimum: amount = self.minimum
        if amount > self.maximum: amount = self.maximum
        self.current_amount = amount

        if update_screen:
            self.update_screen()


    def get_screen_text(self):
        '''
        Builds the actual progress bar text
        '''
        diff = float(self.current_amount - self.minimum)
        done = (diff / float(self.range)) * 100.0
        done = int(round(done))

        all = self.width - 2
        hashes = (done / 100.0) * all
        hashes = int(round(hashes))

        hashes_text = '#' * hashes
        spaces_text = ' ' * (all - hashes)
        screen_text = "[%s%s]" % (hashes_text, spaces_text)

        percent_text = "%s%%" % done
        percent_text_len = len(percent_text)
        percent_position = (len(screen_text) / 2) - percent_text_len

        screen_text = (screen_text[:percent_position] + percent_text +
                       screen_text[percent_position + percent_text_len:])

        if self.title:
            screen_text = '%s: %s' % (self.title,
                                      screen_text)
        return screen_text


    def update_screen(self):
        '''
        Prints the updated text to the screen
        '''
        print self.get_screen_text(), '\r',

def display_data_size(size):
    '''
    Display data size in human readable units.
    @type size: int
    @param size: Data size, in Bytes.
    @return: Human readable string with data size.
    '''
    prefixes = ['B', 'kB', 'MB', 'GB', 'TB']
    i = 0
    while size > 1000.0:
        size /= 1000.0
        i += 1
    return '%.2f %s' % (size, prefixes[i])

def interactive_download(url, output_file, title='', chunk_size=100*1024):
    '''
    Interactively downloads a given file url to a given output file
    @type url: string
    @param url: URL for the file to be download
    @type output_file: string
    @param output_file: file name or absolute path on which to save the file to
    @type title: string
    @param title: optional title to go along the progress bar
    @type chunk_size: integer
    @param chunk_size: amount of data to read at a time
    '''
    output_dir = os.path.dirname(output_file)
    output_file = open(output_file, 'w+b')
    input_file = urllib2.urlopen(url)

    try:
        file_size = int(input_file.headers['Content-Length'])
    except KeyError:
        raise ValueError('Could not find file size in HTTP headers')

    logging.info('Downloading %s, %s to %s', os.path.basename(url),
                 display_data_size(file_size), output_dir)

    # Calculate progrss bar size based on title size
    if title:
        width = ProgressBar.DEFAULT_WIDTH - len(title)
        progress_bar = ProgressBar(maximum=file_size,
                                               width=width, title=title)
    else:
        progress_bar = ProgressBar(maximum=file_size)

    # Download the file, while interactively updating the progress
    progress_bar.update_screen()
    while True:
        data = input_file.read(chunk_size)
        if data:
            progress_bar.increment(len(data))
            output_file.write(data)
        else:
            progress_bar.update(file_size)
            print
            break

    output_file.close()
interactive_download('http://123.207.166.197/tgw/tools/X-Lite3.0.rar', 'X-Lite3.0.rar', title='X-Lite3.0')
				     
###############################
[root@VM_132_108_centos python]# python tmp.py 
22:14:09 INFO | are you ok? (y/n) y
y
[root@VM_132_108_centos python]# python tmp.py 
22:14:12 INFO | are you ok? (y/n) n
n
[root@VM_132_108_centos python]# cat tmp.py 
import os, pickle, random, re, resource, select, shutil, signal, StringIO
import socket, struct, subprocess, sys, time, textwrap, traceback, urlparse
import warnings, smtplib, logging, urllib2
from threading import Thread, Event, Lock
try:
    import hashlib
except ImportError:
    import md5, sha
def ask(question, auto=False):
    """
    Raw input with a prompt that emulates logging.
    @param question: Question to be asked
    @param auto: Whether to return "y" instead of asking the question
    """
    if auto:
        logging.info("%s (y/n) y" % question)
        return "y"
    return raw_input("%s INFO | %s (y/n) " %
(time.strftime("%H:%M:%S", time.localtime()), question))
print ask('are you ok?')

######################################################
[root@VM_132_108_centos python]# python tmp.py 
60213
[root@VM_132_108_centos python]# cat tmp.py 
import os, pickle, random, re, resource, select, shutil, signal, StringIO
import socket, struct, subprocess, sys, time, textwrap, traceback, urlparse
import warnings, smtplib, logging, urllib2
from threading import Thread, Event, Lock
try:
    import hashlib
except ImportError:
    import md5, sha

def get_unused_port():
    """
    Finds a semi-random available port. A race condition is still
    possible after the port number is returned, if another process
    happens to bind it.
    Returns:
        A port number that is unused on both TCP and UDP.
    """

    def try_bind(port, socket_type, socket_proto):
        s = socket.socket(socket.AF_INET, socket_type, socket_proto)
        try:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('', port))
                return s.getsockname()[1]
            except socket.error:
                return None
        finally:
            s.close()

    # On the 2.6 kernel, calling try_bind() on UDP socket returns the
    # same port over and over. So always try TCP first.
    while True:
        # Ask the OS for an unused port.
        port = try_bind(0, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        # Check if this port is unused on the other protocol.
        if port and try_bind(port, socket.SOCK_DGRAM, socket.IPPROTO_UDP):
            return port

print get_unused_port()

#######################################
[root@VM_132_108_centos python]# python tmp.py 
{'a': '1', 'b': '2'}
[root@VM_132_108_centos python]# vim tmp.py 

import os, pickle, random, re, resource, select, shutil, signal, StringIO
import socket, struct, subprocess, sys, time, textwrap, traceback, urlparse
import warnings, smtplib, logging, urllib2
from threading import Thread, Event, Lock
try:
    import hashlib
except ImportError:
    import md5, sha

def args_to_dict(args):
    """Convert autoserv extra arguments in the form of key=val or key:val to a
    dictionary.  Each argument key is converted to lowercase dictionary key.
    Args:
        args - list of autoserv extra arguments.
    Returns:
        dictionary
    """
    arg_re = re.compile(r'(\w+)[:=](.*)$')
    dict = {}
    for arg in args:
        match = arg_re.match(arg)
        if match:
            dict[match.group(1).lower()] = match.group(2)
        else:
            logging.warning("args_to_dict: argument '%s' doesn't match "
                            "'%s' pattern. Ignored." % (arg, arg_re.pattern))
    return dict
args = ['a:1','b=2']
print args_to_dict(args)

#############################################
[root@VM_132_108_centos python]# python tmp.py 
0
-1
1

[root@VM_132_108_centos python]# cat tmp.py 
import os, pickle, random, re, resource, select, shutil, signal, StringIO
import socket, struct, subprocess, sys, time, textwrap, traceback, urlparse
import warnings, smtplib, logging, urllib2
from threading import Thread, Event, Lock
try:
    import hashlib
except ImportError:
    import md5, sha

def compare_versions(ver1, ver2):
    """Version number comparison between ver1 and ver2 strings.
    >>> compare_tuple("1", "2")
    -1
    >>> compare_tuple("foo-1.1", "foo-1.2")
    -1
    >>> compare_tuple("1.2", "1.2a")
    -1
    >>> compare_tuple("1.2b", "1.2a")
    1
    >>> compare_tuple("1.3.5.3a", "1.3.5.3b")
    -1
    Args:
        ver1: version string
        ver2: version string
    Returns:
        int:  1 if ver1 >  ver2
              0 if ver1 == ver2
             -1 if ver1 <  ver2
    """
    ax = re.split('[.-]', ver1)
    ay = re.split('[.-]', ver2)
    while len(ax) > 0 and len(ay) > 0:
        cx = ax.pop(0)
        cy = ay.pop(0)
        maxlen = max(len(cx), len(cy))
        c = cmp(cx.zfill(maxlen), cy.zfill(maxlen))
        if c != 0:
            return c
    return cmp(len(ax), len(ay))
print compare_versions('tgw-2.4.0.tlinux.1.0.8.m.l3-170328.x86_64', 'tgw-2.4.0.tlinux.1.0.8.m.l3-170328.x86_64')
print compare_versions('tgw-2.4.0.tlinux.1.0.8.m.l3-170328.x86_64', 'tgw-2.4.0.tlinux.1.0.8.m.l3-170329.x86_64')
print compare_versions('tgw-2.4.0.tlinux.1.0.8.m.l3-170328.x86_64', 'tgw-2.4.0.tlinux.1.0.8.m.l3-170327.x86_64')
###########################
[root@VM_132_108_centos python]# python tmp1.py 
[root@VM_132_108_centos python]# cat tmp1.py 
import os, pickle, random, re, resource, select, shutil, signal, StringIO
import socket, struct, subprocess, sys, time, textwrap, traceback, urlparse
import warnings, smtplib, logging, urllib2
from threading import Thread, Event, Lock

try:
    import hashlib
except ImportError:
    import md5, sha



def is_url(path):
    """Return true if path looks like a URL"""
    # for now, just handle http and ftp
    url_parts = urlparse.urlparse(path)
    return (url_parts[0] in ('http', 'ftp'))


def urlopen(url, data=None, timeout=5):
    """Wrapper to urllib2.urlopen with timeout addition."""

    # Save old timeout
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return urllib2.urlopen(url, data=data)
    finally:
        socket.setdefaulttimeout(old_timeout)


def urlretrieve(url, filename, data=None, timeout=300):
    """Retrieve a file from given url."""
    logging.debug('Fetching %s -> %s', url, filename)

    src_file = urlopen(url, data=data, timeout=timeout)
    try:
        dest_file = open(filename, 'wb')
        try:
            shutil.copyfileobj(src_file, dest_file)
        finally:
            dest_file.close()
    finally:
        src_file.close()

def get_file(src, dest, permissions=None):
    """Get a file from src, which can be local or a remote URL"""
    if src == dest:
        return

    if is_url(src):
        urlretrieve(src, dest)
    else:
        shutil.copyfile(src, dest)

    if permissions:
        os.chmod(dest, permissions)
    return dest
get_file('http://123.207.166.197/tgw/tools/X-Lite3.0.rar', '/data/haiyang/python/X-Lite3.0.rar', 777)
####################################
[root@VM_132_108_centos python]# python tmp1.py 
[root@VM_132_108_centos python]# cat tmp1.py 
import os, pickle, random, re, resource, select, shutil, signal, StringIO
import socket, struct, subprocess, sys, time, textwrap, traceback, urlparse
import warnings, smtplib, logging, urllib2
from threading import Thread, Event, Lock

try:
    import hashlib
except ImportError:
    import md5, sha



def is_url(path):
    """Return true if path looks like a URL"""
    # for now, just handle http and ftp
    url_parts = urlparse.urlparse(path)
    return (url_parts[0] in ('http', 'ftp'))


def urlopen(url, data=None, timeout=5):
    """Wrapper to urllib2.urlopen with timeout addition."""

    # Save old timeout
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return urllib2.urlopen(url, data=data)
    finally:
        socket.setdefaulttimeout(old_timeout)


def urlretrieve(url, filename, data=None, timeout=300):
    """Retrieve a file from given url."""
    logging.debug('Fetching %s -> %s', url, filename)

    src_file = urlopen(url, data=data, timeout=timeout)
    try:
        dest_file = open(filename, 'wb')
        try:
            shutil.copyfileobj(src_file, dest_file)
        finally:
            dest_file.close()
    finally:
        src_file.close()

def get_file(src, dest, permissions=None):
    """Get a file from src, which can be local or a remote URL"""
    if src == dest:
        return

    if is_url(src):
        urlretrieve(src, dest)
    else:
        shutil.copyfile(src, dest)

    if permissions:
        os.chmod(dest, permissions)
    return dest
#get_file('http://123.207.166.197/tgw/tools/X-Lite3.0.rar', '/data/haiyang/python/X-Lite3.0.rar', 777)

def unmap_url(srcdir, src, destdir='.'):
    """
    Receives either a path to a local file or a URL.
    returns either the path to the local file, or the fetched URL
    unmap_url('/usr/src', 'foo.tar', '/tmp')
                            = '/usr/src/foo.tar'
    unmap_url('/usr/src', 'http://site/file', '/tmp')
                            = '/tmp/file'
                            (after retrieving it)
    """
    if is_url(src):
        url_parts = urlparse.urlparse(src)
        filename = os.path.basename(url_parts[2])
        dest = os.path.join(destdir, filename)
        return get_file(src, dest)
    else:
        return os.path.join(srcdir, src)

unmap_url('/usr/src', 'http://123.207.166.197/tgw/tools/X-Lite3.0.rar', '/tmp')
##############################
十六进制和八进制转化为十进制
[root@VM_132_108_centos common_lib]# cat tmp.py 
import logging, optparse, os, re, sys, string, struct


def _str_to_num(n):
    """
    Convert a hex or octal string to a decimal number.
    @param n: Hex or octal string to be converted.
    @return: Resulting decimal number.
    """
    val = 0
    col = long(1)
    if n[:1] == 'x': n = '0' + n
    if n[:2] == '0x':
        # hex
        n = string.lower(n[2:])
        while len(n) > 0:
            l = n[len(n) - 1]
            val = val + string.hexdigits.index(l) * col
            col = col * 16
            n = n[:len(n)-1]
    elif n[0] == '\\':
        # octal
        n = n[1:]
        while len(n) > 0:
            l = n[len(n) - 1]
            if ord(l) < 48 or ord(l) > 57:
                break
            val = val + int(l) * col
            col = col * 8
            n = n[:len(n)-1]
    else:
        val = string.atol(n)
    return val
print _str_to_num(n='0x0a')
print _str_to_num(n='\\21')
###############################
[root@VM_132_108_centos python]# cat tmp1.py 
import os
import glob

"""
One day, when this module grows up, it might actually try to fix things.
'apt-cache search | apt-get install' ... or a less terrifying version of
the same. With added distro-independant pixie dust.
"""

def command(cmd):
    # this could use '/usr/bin/which', I suppose. But this seems simpler
    for dir in os.environ['PATH'].split(':'):
        file = os.path.join(dir, cmd)
        if os.path.exists(file):
            return file
    raise ValueError('Missing command: %s' % cmd)

print command('ls')
def commands(cmds):
    results = []
    for cmd in cmds:
        print cmd
        results.append(command(cmd))
    return results
print commands(['ls','pwd'])
#############################################################
根据网络位数获取ip的网段
import socket
import struct
def ip_to_long(ip):
    # !L is a long in network byte order
    return struct.unpack('!L', socket.inet_aton(ip))[0]


def long_to_ip(number):
    # See above comment.
    return socket.inet_ntoa(struct.pack('!L', number))


def create_subnet_mask(bits):
    return (1 << 32) - (1 << 32 - bits)


def format_ip_with_mask(ip, mask_bits):
    masked_ip = ip_to_long(ip) & create_subnet_mask(mask_bits)
    return "%s/%s" % (long_to_ip(masked_ip), mask_bits)

print format_ip_with_mask('192.168.1.1', 24)
#############################################################
读取文件的key vlaue值和把字典的key value值写到文件中去
[root@VM_255_119_centos hadong_python]# cat keyval
a=1
b="hadong"
c=1.23
[root@VM_255_119_centos hadong_python]# cat tmp.py 
import re
import os
def read_keyval(path):
    """
    Read a key-value pair format file into a dictionary, and return it.
    Takes either a filename or directory name as input. If it's a
    directory name, we assume you want the file to be called keyval.
    """
    if os.path.isdir(path):
        path = os.path.join(path, 'keyval')
    keyval = {}
    if os.path.exists(path):
        for line in open(path):
            line = re.sub('#.*', '', line).rstrip()
            if not re.search(r'^[-\.\w]+=', line):
                raise ValueError('Invalid format line: %s' % line)
            key, value = line.split('=', 1)
            if re.search('^\d+$', value):
                value = int(value)
            elif re.search('^(\d+\.)?\d+$', value):
                value = float(value)
            keyval[key] = value
    return keyval
print read_keyval('/data/haiyang/hadong_python')

def write_keyval(path, dictionary):
    """
    Write a key-value pair format file out to a file. This uses append
    mode to open the file, so existing text will not be overwritten or
    reparsed.

    If type_tag is None, then the key must be composed of alphanumeric
    characters (or dashes+underscores). However, if type-tag is not
    null then the keys must also have "{type_tag}" as a suffix. At
    the moment the only valid values of type_tag are "attr" and "perf".

    :param path: full path of the file to be written
    :param dictionary: the items to write
    :param type_tag: see text above
    """
    if os.path.isdir(path):
        path = os.path.join(path, 'keyval')
    keyval = open(path, 'a')

    try:
        for key in sorted(dictionary.keys()):
            keyval.write('%s=%s\n' % (key, dictionary[key]))
    finally:
        keyval.close()

dic_a = {'a': 1, 'c': 1.23, 'b': "hadong", 'd': 8}
write_keyval('/data/haiyang/hadong_python', dic_a)
##################################
[root@VM_255_119_centos hadong_python]# vim tmp.py 

try:
    import hashlib
except ImportError:
    import md5
    import sha
def read_file(filename):
    f = open(filename)
    try:
        return f.read()
    finally:
        f.close()
def hash(type, input=None):
    """
    Returns an hash object of type md5 or sha1. This function is implemented in
    order to encapsulate hash objects in a way that is compatible with python
    2.4 and python 2.6 without warnings.

    Note that even though python 2.6 hashlib supports hash types other than
    md5 and sha1, we are artificially limiting the input values in order to
    make the function to behave exactly the same among both python
    implementations.

    :param input: Optional input string that will be used to update the hash.
    """
    if type not in ['md5', 'sha1']:
        raise ValueError("Unsupported hash type: %s" % type)

    try:
        hash = hashlib.new(type)
    except NameError:
        if type == 'md5':
            hash = md5.new()
        elif type == 'sha1':
            hash = sha.new()

    if input:
        hash.update(input)

    return hash
a=read_file('/data/haiyang/hadong_python/keyval')
print hash('md5', a).hexdigest()
~
"tmp.py" 41L, 1166C written
[root@VM_255_119_centos hadong_python]# python tmp.py 
76b7f1335d68de1b821a110d3142ae6a
[root@VM_255_119_centos hadong_python]# md
md5sum  mdadm   mdmon   
[root@VM_255_119_centos hadong_python]# md
md5sum  mdadm   mdmon   
[root@VM_255_119_centos hadong_python]# md5sum  keyval 
76b7f1335d68de1b821a110d3142ae6a  keyval
