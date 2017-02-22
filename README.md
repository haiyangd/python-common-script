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
###38.   mod_attrs_and_types.pyy
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
