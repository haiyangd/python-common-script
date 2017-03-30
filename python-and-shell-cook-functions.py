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
      
