#monitor.py
#!-*- encoding: utf-8 -*- 
import urllib2
import logging 
import os 
import time 
from ConfigParser import ConfigParser
from logging.handlers import TimedRotatingFileHandler

#开启log 模块
LOG_FILE = "./logs/output.log"

logger = logging.getLogger()
logger.setLevel(logging.INFO)
fh = TimedRotatingFileHandler(LOG_FILE,when='midnight',interval=1,backupCount=30)
datefmt = '%Y-%m-%d %H:%M:%S'
format_str = '%(asctime)s %(levelname)s %(message)s '
formatter = logging.Formatter(format_str, datefmt)
fh.setFormatter(formatter)
fh.suffix = "%Y%m%d%H%M"
logger.addHandler(fh)

#获取url的code状态
def getUrlcode(url):
    try:
        start = time.time()
        response = urllib2.urlopen(url,timeout=10)
        msg = 'httpcode is ' + str(response.getcode()) + ' - open url use time ' + str((time.time()-start)*1000) + 'ms'
        logging.info(msg)
        return response.getcode()
    except urllib2.URLError as e:
        msg = 'open url error ,reason is:' + str(e.reason) 
        logging.info(msg)

#读取config.ini的用法    
def get(field, key):
    result = ""
    try:
        result = cf.get(field, key)
    except:
        result = ""
    return result
    
def read_config(config_file_path, field, key): 
    cf = ConfigParser()
    try:
        cf.read(config_file_path)
        result = cf.get(field, key)
    except:
        sys.exit(1)
    return result

CONFIGFILE='./cfg/config.ini' 

os.environ["JAVA_HOME"] = read_config(CONFIGFILE,'MonitorProgram','JAVA_HOME')
os.environ["CATALINA_HOME"] = read_config(CONFIGFILE,'MonitorProgram','CATALINA_HOME')

ProgramPath = read_config(CONFIGFILE,'MonitorProgram','StartPath') 
ProcessName = read_config(CONFIGFILE,'MonitorProcessName','ProcessName')
url = read_config(CONFIGFILE,'MonitorUrl','Url')
#url = "http://dh.361way.com/"


while True:
    HttpCode = getUrlcode(url)

    if HttpCode is not 200:
         command = 'taskkill /F /FI "WINDOWSTITLE eq ' + ProcessName + '"'
         os.system(command)
         os.system(ProgramPath)

    time.sleep(30)

'''
import os
import socket
def IsOpen(ip,port):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        s.connect((ip,int(port)))
        s.shutdown(2)
        print '%d is open' % port
        return True
    except:
        print '%d is down' % port
        return False
if __name__ == '__main__':
    IsOpen('127.0.0.1',800) '''

#config.ini
[MonitorProgram] 
StartPath: C:/tomcat/bin/startup.bat
CATALINA_HOME: C:\\tomcat\\
JAVA_HOME: C:\\Program Files\\Java\\jdk1.8.0_31
 
[MonitorProcessName] 
ProcessName: tomcat_8080

[MonitorUrl] 
Url: http://127.0.0.1:8080

#log_timedRotate.py
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

#开启log 模块 
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

#ping ip
#----------------------------------------------------------------------
def pinghost(host):
    ping = subprocess.Popen(["ping", "-c", "1",host],stdout = subprocess.PIPE,stderr = subprocess.PIPE)
    out, error = ping.communicate()
    if "icmp_seq" in  out:
        icmp_line = re.findall(r'\d+\sbytes(.*?)ms',out)
        logging.info('ping ' + host + str(icmp_line))
    else:
        logging.info('ping ' + host + ' fail')
        
# tcp协议 ip 和port        
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
    
###################################
python logging配置时间或大小轮转
python中的很多模块是非常牛X的，之前提到过logging模块(其功能类似于java下的Log4j )，由于最近一个涉及网络排障的脚本需要日志输出，这里就使用了python的logging模块去实现。日志全部写到一个文件中时，随着时间的推移文件会越来越来，这里可以利用TimedRotatingFileHandler方法或RotatingFileHandler方法来进行处理。

 在日志输出不涉及轮转的时候，可以通过logging.basicConfig 方法自定义输出的日志格式，这部分可以参考我之前的博文记录－－－python日志模块logging 。在涉及到按日期轮转时，再使用之前的logging.basicConfig格式处理，无法正常输出，这里在咨询之前的python大牛同事后，最终写出的代码内容如下：

1.#!/usr/bin/env python2.# coding=utf-83.# site: www.361way.com4.# mail: itybku@139.com5.# desc: Rotating logfile by times or size6.import re7.import subprocess8.import logging9.import socket,time10.from logging.handlers import TimedRotatingFileHandler11.LOG_FILE = "/var/log/ping/ping.log"12.#logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',datefmt='%Y-%m-%d %I:%M:%S',filemode='w')   #for term print13.logger = logging.getLogger()14.logger.setLevel(logging.INFO)15.fh = TimedRotatingFileHandler(LOG_FILE,when='M',interval=1,backupCount=30)16.datefmt = '%Y-%m-%d %H:%M:%S'17.format_str = '%(asctime)s %(levelname)s %(message)s '18.#formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')19.formatter = logging.Formatter(format_str, datefmt)20.fh.setFormatter(formatter)21.logger.addHandler(fh)22.#logging.info(msg)23.#hdlr.flush()24.#----------------------------------------------------------------------25.def pinghost(host):26.    ping = subprocess.Popen(["ping", "-c", "1",host],stdout = subprocess.PIPE,stderr = subprocess.PIPE)27.    out, error = ping.communicate()28.    if "icmp_seq" in  out:29.        icmp_line = re.findall(r'\d+\sbytes(.*?)ms',out)30.        logging.info('ping ' + host + str(icmp_line))31.    else:32.        logging.info('ping ' + host + ' fail')33.def tcping(server, port):34.    ''' Check if a server accepts connections on a specific TCP port '''35.    try:36.        start = time.time()37.        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)38.        s.connect((server, port))39.        s.close()40.        #print server + ':' + str(port) + '/tcp - ' +  str(port) + ' port is open' + ' - time=' + str(round((time.time()-start)*10000)/10) + 'ms'41.        msg = server + ':' + str(port) + '/tcp - ' +  str(port) + ' port is open' + ' - time=' + str((time.time()-start)*1000) + 'ms'42.        logging.info(msg)43.    except socket.error:44.        msg = server + ':' + str(port) + ' port not open'45.        logging.info(msg)46.while 1:47.    pinghost('passport.migu.cn')48.    pinghost('112.17.9.72')49.    tcping('passport.migu.cn',8443)50.    tcping('112.17.9.72',8443)51.    #time.sleep(0.5)
 代码已上传到我的github上。


 1、轮询函数语法


 TimedRotatingFileHandler的构造函数定义如下:

1.TimedRotatingFileHandler(filename [,when [,interval [,backupCount]]])

 filename 是输出日志文件名的前缀

 when 是一个字符串的定义如下：

1.“S”: Seconds2.“M”: Minutes3.“H”: Hours4.“D”: Days5.“W”: Week day (0=Monday)6.“midnight”: Roll over at midnight
 interval 是指等待多少个单位when的时间后，Logger会自动重建文件，当然，这个文件的创建取决于filename+suffix，若这个文件跟之前的文件有重名，则会自动覆盖掉以前的文件，所以有些情况suffix要定义的不能因为when而重复。

 backupCount 是保留日志个数。默认的0是不会自动删除掉日志。若设10，则在文件的创建过程中库会判断是否有超过这个10，若超过，则会从最先创建的开始删除。


 2、轮询使用示例


 RotatingFileHandler（按照文件大小分割）、TimedRotatingFileHandler（按照时间间隔分割）使用的示例如下

1.hdlr = logging.handlers.RotatingFileHandler(LOG_FILE,maxBytes=1024*1024,backupCount=40)或2.hdlr = logging.handlers.TimedRotatingFileHandler(LOG_FILE,when='M',interval=1,backupCount=40)
 其中maxBytes指定每个日志文件的大小，如果文件超过1024比特就分割该日志文件，最大的备份文件个数是40个。到LOG_FILE所在目录下查看，发现除了debug.log文件外，还多了debug.log.1，debug.log.2等文件。


 3、logging模块运行流程


 logging和handler模块运行的流程如下：

1.import logging2.# 创建一个logger3.logger = logging.getLogger('mylogger')4.logger.setLevel(logging.DEBUG)5.# 创建一个handler，用于写入日志文件6.fh = logging.FileHandler('test.log')7.fh.setLevel(logging.DEBUG)8.# 再创建一个handler，用于输出到控制台9.ch = logging.StreamHandler()10.ch.setLevel(logging.DEBUG)11.# 定义handler的输出格式12.formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')13.fh.setFormatter(formatter)14.ch.setFormatter(formatter)15.# 给logger添加handler16.logger.addHandler(fh)17.logger.addHandler(ch)18.# 记录一条日志19.logger.info('foorbar')
 4、logging Level


 logger.setLevel方法可以设置日志显示的级别，级别由高至低的顺序是：NOTSET < DEBUG < INFO < WARNING < ERROR < CRITICAL ，如果把looger的级别设置为INFO， 那么小于INFO级别的日志都不输出， 大于等于INFO级别的日志都输出 。

5、logging的父子关系


 如下图所示，logger日志之间是存在父子关系的。 root logger就是处于最顶层的logger 。
如果不创建logger实例， 直接调用logging.debug()、logging.info()logging.warning()、logging.error()、logging.critical()这些函数，那么使用的logger就是 root logger， 它可以自动创建，也是单实例的。通过logging.getLogger()或者logging.getLogger("")得到root logger实例。root logger默认的level是logging.WARNING 。

 logger的name的命名方式可以表示logger之间的父子关系. 比如：

1.parent_logger = logging.getLogger('foo')
2.child_logger = logging.getLogger('foo.bar')
 effective level：logger有一个概念，叫effective level。 如果一个logger没有显示地设置level，那么它就用父亲的level。如果父亲也没有显示地设置level， 就用父亲的父亲的level，以此推最后到达root logger，一定设置过level。默认为logging.WARNING child loggers得到消息后，既把消息分发给它的handler处理，也会传递给所有祖先logger处理，

 父子测试代码如下：

1.import logging
2.# 设置root logger
3.r = logging.getLogger()
4.ch = logging.StreamHandler()
5.ch.setLevel(logging.DEBUG)
6.formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
7.ch.setFormatter(formatter)
8.r.addHandler(ch)
9.# 创建一个logger作为父亲
10.p = logging.getLogger('foo')
11.p.setLevel(logging.DEBUG)
12.ch = logging.StreamHandler()
13.ch.setLevel(logging.DEBUG)
14.formatter = logging.Formatter('%(asctime)s - %(message)s')
15.ch.setFormatter(formatter)
16.p.addHandler(ch)
17.# 创建一个子logger
18.c = logging.getLogger('foo.bar')
19.c.debug('foo')
 输出如下：

1.2016-03-10 21:04:29,893 - foo
2.2016-03-10 21:04:29,893 - DEBUG - foo 
 子logger没有任何handler，所以对消息不做处理。但是它把消息转发给了它的父logger以及root logger。最后输出两条日志。

 6、其他


 根据在网上看到信息，该模块在多进程环境下使用可能会出现Windows Error 32 报错的情况，这需要重写下 doRollover 函数。

 另外涉及到logging模块的配置部分，我们还可以通过指定一个配置文件－－－使用logging.config.fileConfig('logging.conf')方法，读取该自定义配置的方法生效，具体可以参看官方相关文档。
 
################################################################################
# md5sum 功能
root@VM-255-210-ubuntu:/data/haiyang/python# cat md5sum.py 
#!/usr/bin/python
#encoding=utf-8
import io
import sys
import hashlib
import string

def printUsage():
	print ('''Usage: [python] pymd5sum.py <filename>''')
	
def md5sum_check():
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
md5sum_check()


