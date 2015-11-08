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

###9. args_kargs.py
	
		 just try to use *args and **kargs.
