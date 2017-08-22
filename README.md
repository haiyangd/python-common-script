==========
	
##本项目为日常工作中的使用的python 和 shell 脚本


###1.  ssh_thread.py  是一个批量执行命令的脚本，支持直接执行ssh命令及文件传输，支持多线程

		使用说明如下：
	
		-h,-H,--help         帮助页面 
        -C, --cmd            执行命令模式 
        -M, --command        执行命令模式 
        -S, --sendfile       传输文件模式 
        -L, --localpath      本地文件路径 
        -R, --remotepath     远程服务器路径 

	    IP列表格式:

   	    IP地址		用户名     密码     端口
	    192.168.1.1        root	  123456    22

      	e.g.
              批量执行命令格式： -C "IP列表" -M '执行的命令'
              批量传送文件：     -S "IP列表" -L "本地文件路径" -R "远程文件路径"
	    错误日志文件：$PWD/ssh_errors.log

###2. check_ping.py  多进程检测ping，并取值
	
		默认开启4个进程，需要将hosts.txt IP列表文件放入同一目录下，IP列表每行一个，支持域名、IP

###3. nopswd_con.sh  run nopaswd_con.sh to add remote ssh keys to server to nopasswd for next ssh
	
		sh nopswd_con.sh slcn06vmf0021.us.oracle.com root

###4. configure_systat.sh  
	
		make rsys_dmn could be managed by service.(service rsys_dmn start)
		
###5. rsys_dmn.sh
	
		make r_systa script as daemon

###6. get_rpms.py
	
		get and parse html from a url, then, to download all the RPMs listed in the html context
		
###7. socket_server.py  socket_client.py
	
		

###8. network.py
	
		 a lib to valid the ip:port connection

###9. mult_thread_download.py && paxel.py
	
		 mult thread download a file to imporve download speed

###10. args_kargs.py
	
		 just try to use *args and **kargs.

###11. filter_map_reduce.py
	
		 讲述filter，map和reduce的用法

###12. parse-json.py
	
		 Testing out reading and writing json to a file

###13. cmdmain.py
	
		Example to show how module cmd is use

###14. mynameis.py && mynameis2.py
	
		Example to show how command-line options can be handled by a script.

###15. book_spider.py && spider.py
	
		 The heart of this program, finds all links within a web site.

###16. imp.py
	
		 使用imp 模块动态加载别的模块

###17. format_strings.py
	
		 format strings

###18. random_string.py 
	
		 使用 Python 如何生成 200 个激活码（或者优惠券)

###19. count_word.py 
	
		 count word num

###20. important_word.py  
	
		 Get all files in designated pat
		 Get the most popular word in designated files

###21.    mail_config.py  mail_send_list.py mail_send_queue.py 
	
		 邮件模块

###22.   testmymodule.py logging_test_output_to_a_file.py  profiling_and_timing_your_program.py
	
		unittest module

###23.   logconfig.ini simple_logging_for_scripts_example1.py simple_logging_for_scripts_example2.py
	
		logging module
		
###24.    backup_1.py
	
		读取配置文件和对subprocess.Popen的重构

###24.    timethis.py
	
		确定程序的运行时间
		
###25.    host.py
	
		ssh linux host执行相关的操作
		
###26.    DataCapacity.py
	
		数据量
    
    用户辅助各种数据量的转换和对比，例如::
    
    DataCapacity(12) == DataCapacity("12B")
    DataCapacity("12 kB") == DataCapacity(12*1024)
    
###27.    util.py
	1.wait_tcp_accessible  等待TCP网络端口可以访问
	2. wait_sshd_ready  等待SSH服务准备就绪
	   
###28.    database.py 

    数据库使用支持

    使用示例：
    db = Database( 'localhost', 3306, 'root', '6611750', 'eeelin')
    results = db.table('tttt').select().where(Field('sss')!='90')
    print results[1]
    print len(results)
    for it in results:
       print it.id, it

    results = db.table('tttt').select('sss').where(Field('sss')=='XXX')
    for it in results:
        print it

    results = db.table('tttt').select('sss')
    for it in results:
        print it

###29.    checkSites.py watchdogConfig.cfg.sample
     
     A website watchdog. Executing periodically via a cron.

    The config_file_path is the path for a file where each row has the following structure:

    domain,check1,check2...

    each check is a string that must exist in the root document of the domain


    Still a lot TODO:
    * Run as a daemon instead of cron
    * do not resend emails for repeated failures
    * more complex tests (e.g. regex)
    * machine-learning for automatic random website checks


###30.    log_parser.py 
     
     实时监控log 日志，类似tail -f log,搜索到指定的关键字并打印
     
###31.    folder_size.py

     This will scan the current directory and all subdirectories and display the size.
     [root@VM_28_85_centos python]# python folder_size.py 
     Folder Size: 0.15 Gigabytes
     Folder Size: 159085.67 Kilobytes
     Folder Size: 162903729.0 Bytes
     Folder Size: 155.36 Megabytes

###31.    file_rename.py

     This will batch rename a group of files in a given directory
###32.    move_files_over_x_days.py

     This will move all the files from the src directory that are over 240 days old to the destination directory.
###33.    cleanup_pid.py

     cleanup pid file and kill process
###34.    randomMAC.py

     generate random MAC address
###35.    rpmdb.py

     rpm db check and rpm db rebuild
###36.    download_repos.py

     download rpm Packages from repos url
###37.   string2dict.py

     通过调用json库把string类型转换为dict类型
###38.   mod_attrs_and_types.py

     Get names and types of all attributes of a Python module
###39.   Python one-liner to compare two files 

     python -c "print open('f0.txt', 'rb').read() == open('f1.txt', 'rb').read()"
###40.   sshcmd.py

     ssh login linux host with python module paramiko
###40.   sshConnect.py

     ssh login linux host with python module pexpect
     
###41.   difflib.py

     python  difflib.py nginx.conf.v1 nginx.conf.v2 > diff.html,对比nginx配置文件的差异，生成html格式的差异文档
     
###42.   filecmp_simple2.py

     python filecmp_simple2.py dir1 dir2,校验源于备份目录差异，并把原目录不同的同步到目的目录
 
###43.   pycurl_simple.py

     python pycurl_simple.py,实现探测web服务质量

###44.   nmap_simple.py

     python nmap_simple.py,实现高效的端口扫描，其中主机输入支持，如www.qq.com,192.168.1.*,192.168.1.1-20,192.168.1.0/24等，端口输入格式也是
     非常灵活，如80，443,22-443
     [root@VM_255_119_centos python-nmap-0.6.1]# python simple1.py 
     Please input hosts and port: 115.159.240.14 80
     ----------------------------------------------------
     Host : 115.159.240.14 ()
     State : up
     ----------
     Protocol : tcp
     port : 80	  state : open

###45.   pexpect_simple.py

     python pexpect_simple.py，远程文件自动打包并下载

###46.   pexpect_simple1.py

     python pexpect_simple1.py，实现一个自动化ftp操作
###47.   paramiko_simple1.py

     python paramiko_simple1.py，实现远程ssh运行命令
###48.   paramiko_simple2.py

     python paramiko_simple2.py，实现密钥方式登录远程主机
###49.   paramiko_simple3.py

     python paramiko_simple3.py，堡垒机模式下的远程命令执行
###50.   paramiko_simple4.py

     python paramiko_simple4.py，实现堡垒机模式下的远程文件上传
###51.   retry.sh

     支持设置重试次数，命令成功时的退出码，重试间隔时间
###52.   crontab.sh

     通过shell脚本添加删除crontab任务
###53.   multithreading.sh

     可控多线程 shell 脚本
     说到可控多线程的 shell 脚本，很多人第一时间应该都会想到前人分享的管道方案吧（详见代码一），用过的都说不错。
     今天主要分享一个入门级、更容易理解的shell可控多线程方案：任务切割
     场景一、多线程ping测试
     某日，接到了这个任务，需要对800多个IP进行一次Ping检测，只要取得ping可达的IP就好。

###54.   lockthread.sh

     shell 单例模式
     
###55.   camelCase2UnderScoreCase.py 下划线命名与驼峰命名风格转换

     背景： 业务逻辑中糅合了两种风格的变量命名，希望风格统一化，但由于涉及代码量较大，手工改易错漏， 因此利用正则写脚本来转。在尝试不同版本的实现中，      发现借助python实现十分简洁。
     
###56.   delmetafile.py 删除文件夹下面所有的.meta文件

     删除unity工程里的所有meta文件

###57.   is_chinese.py 用python判读字符是否是中文 

     用于检测字符串中的字符是否是中文，在调用函数前，必须先把字符串转成unicode编码

###58.   monitoring_process.py 进程监控/告警/拉取工具 

1. 核心功能：
- 监控编译/解释型进程的进程数、CPU使用率、内存， 以及是否有僵尸进程等信息；
- 自动触发告警和执行进程拉取命令；
- 定期收集进程的CPU、内存和进程状态信息， 方便跟踪进程运行情况；

2. 监控实现：
- 编译型进程通过匹配进程的exec file来实现， 配合PS命令来提取CPU、内存和进程状态信息；
- 解释型进程通过匹配进程执行参数来实现， CPU等信息同样适用PS命令提取；

3.告警实现：
- 支持自定义告警， 参见ibg_alarm函数；
- 支持网管告警， 参见tnm_alarm函数；

4. 进程自动拉取：
- 支持执行目录下的标识文件检测（手工停止会生成表示文件、Core down则不会）， 判断是否执行进程拉取；
- 如果不存在标识文件则直接执行拉取命令；存在标识文件则只触发告警；（避免变更前还需要手工停止监控脚本）

5. 日志记录：
- 监控进程的运行数量， CPU、内存和进程状态信息， 方便追溯和问题查询；

6. 配置文件说明：
[default]
log_level = debug
；定义日志级别
ibgalarm_api = http:///xxxxx
；定义告警服务的API
alarm_key = 1798
；定义告警发送的key id

[nginx]
type = compile
；定义进程类型为“编译型”
binpath = /usr/sbin/nginx
；定义进程的exec file
number = 2
；定义监控进程的数量
command = /usr/bin/nginx
；定义拉取进程的指令
alarm_key=2048
；为nginx定义独立的告警ID

[net prober]
type = interpret
；定义进程类型为“解释型”
keyword = python prober.py
；定义检测进程是否存在的关键字(ps 过滤关键字)
command = cd /opt/tools/; python prober.py
；定义拉取进程的指令
number = 10
；定义存活进程的数量

###59.   find_file.py 查找特定目录下的文件
###60.   countFile.py 对目录下所有文件计数
###61.   local_machine_info.py 用socket模块获取机器名和机器的ip
###62.   remote_machine_info.py 用socket模块根据别的机器名获取别的机器的ip
###63.   wait_for_remote_service.py 在超时时间之前看机器是否可达
###64.   port_forwarding.py 代理用于端口转发
###65.   ping_remote_host.py 自写的ping代码工具，用于ping远端服务器是否可达
###66.  simple_http_server.py 简易的http server
###67.  checking_webpage_with_HEAD_request.py 核实网页的状态
###68.  xmlrpc_server_with_http_auth.py 简易的xmlrpc server xmlrpc_client.py 简易的xmlrpc 客户端
###69.  healthcheck.py 探测list.txt列表机器的状态
###70.  unidecode：Unicode 文本的 ASCII 转换形式 。官网https://pypi.python.org/pypi/Unidecode
###71.  IO编程.py os常用模块
###72. url_check.py
1. It takes arguments for: timeout, url, expected_response_code, retry_count
2. The script performs an HTTP GET for the url
3. If the HTTP response code matches the expected_response_code the script will exit with status code 0
4. If the the HTTP GET either times out or the HTTP response code doesn't match, retry until retry count is exhausted
5. If the retry count is exhausted without receiving the expected_response_code, print an error message to STDERR and exit with a non zero status code.
