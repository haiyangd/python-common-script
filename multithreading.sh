#代码一、管道方案的可控多线程模板
function a_sub {  # 此处定义一个函数，作为一个线程(子进程)
    sleep3 
} 
tmp_fifofile = "/tmp/$$.fifo"
mkfifo  $tmp_fifofile     # 新建一个fifo类型的文件
exec6 <> $tmp_fifofile    # 将fd6指向fifo类型
rm  $tmp_fifofile 
thread = 15               # 此处定义线程数
for  ((i = 0 ;i < $thread ;i ++ )); do
echo
done  >& 6                # 事实上就是在fd6中放置了$thread个回车符
for  ((i = 0 ;i < 50 ;i ++ )); do   # 50次循环，可以理解为50个主机
read   - u6   # 一个read -u6命令执行一次，就从fd6中减去一个回车符，然后向下执行，fd6中没有回车符的时候，就停在这了，从而实现了线程数量控制
 {                         # 此处子进程开始执行，被放到后台
 a_sub  &&  {              # 此处可以用来判断子进程的逻辑
        echo  "a_sub is finished"
       }  ||  { 
        echo  "sub error"
       } 
       echo  >& 6          # 当进程结束以后，再向fd6中加上一个回车符，即补上了read -u6减去的那个
}  &  
done 
wait                       # 等待所有的后台子进程结束
exec6 >&-   # 关闭df6
exit 0


#=====================================我·是·分·割·线========================================
#代码二、采用任务切割方案的可控多线程ping脚本
#!/bin/sh
#文本分割函数：将文本$1按份数$2进行分割
SplitFile()
{
        linenum=`wc -l $1 |awk '{print $1}'`
        if [[ $linenum -le $2 ]]
        then
               	echo "The lines of this file is less then $2, Are you kidding me..."
                exit
        fi
        Split=`expr $linenum / $2`
        Num1=1
        FileNum=1

        test -d SplitFile || mkdir -p SplitFile
        rm -rf SplitFile/*

        while [ $Num1 -lt $linenum ]
        do
        Num2=`expr   $Num1   +   $Split`
        sed   -n   "${Num1},   ${Num2}p "   $1 > SplitFile/$1-$FileNum  
        Num1=`expr   $Num2   +   1`
        FileNum=`expr   $FileNum   +   1`
        done
}

#Define some variables 
SPLIT_NUM=${1:-10} #参数1表示分割成多少份即,开启多少个线程，默认10个
FILE=${2:-iplist}  #参数2表示分割的对象，默认iplist文件

#分割文件
SplitFile $FILE $SPLIT_NUM

#循环遍历临时IP文件
for iplist in $(ls ./SplitFile/*)
do
		#循环ping测试临时IP文件中的ip（丢后台）
        cat $iplist | while read ip
        do
                ping -c 4 -w 4 $ip >/dev/null && echo $ip | tee -ai okip.log
        done &
done
