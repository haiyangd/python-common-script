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
