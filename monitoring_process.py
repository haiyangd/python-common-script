#!/usr/bin/env python
#coding=utf-8

#####################################################
#Author: hongzhinian                                #
#Create: June 27 2015                               #
#Abstract: For monitoring process                   #
#compatibility: python2                             #
#####################################################

import re
import os
import sys
import time
import json
import urllib
import urllib2
import logging
import subprocess
import ConfigParser

def exec_shell(command):
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
    except Exception as e:
        app_log.error("execute shell failed: %s"%e)
        raise

    return out, err


def get_os_ip(ifname="eth1"):
    command = ["/sbin/ip", "addr", "show", ifname]
    out, error = exec_shell(command)

    match_result = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", out)
    return match_result.group() if match_result.group() else None


def set_global_options():
    root = os.path.dirname(
            os.path.abspath(__file__)
        )

    log_name = "_".join([
        os.path.basename(__file__).split(".")[0],
        time.strftime("%Y%m%d", time.localtime())
    ])

    options["root_path"] = root
    options["log_file"] = os.path.join(root, "logs", log_name) 
    options["local_ip"] = get_os_ip()

def create_log_handler():
    #initial the global options 
    set_global_options()

    app_log = logging.getLogger("root")
    app_log.setLevel(getattr(logging, options.get("log_level", "debug").upper()))
    
    #create log file
    log_path = os.path.dirname(options["log_file"])
    if not os.path.exists(log_path):
        os.mkdir(log_path)

    #set log format
    fmt = logging.Formatter(
        '%(asctime)s %(levelname)s - %(funcName)s: %(message)s',
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    #create log handler
    ch = logging.StreamHandler()
    fh = logging.FileHandler(options["log_file"])
    ch.setFormatter(fmt)
    fh.setFormatter(fmt)
    app_log.addHandler(ch)
    app_log.addHandler(fh)

    return app_log

def send_ibg_alarm(alarm_key, msg):
    content = urllib.quote(msg)
    url = "{api}/check?content={content}&alarm_key=shell_{id}".format(
        api=options.get("ibgalarm_api"),
        content=content, 
        id=alarm_key)

    req = urllib2.Request(url)
    try:
        res = urllib2.urlopen(req)
        return res.read()
    except Exception as e:
        app_log.error("send alarm failed: %s"%e)
        #logging error massage and continue

def send_tnm_alarm(alarm_key, msg):
    pass

def send_alarm(alarm_key, proc_name, c_number, p_number, ip, stime):
    msg = "Kola assitant alerts you\n"\
          "Process Name: {proc_name} \n"\
          "Expect Process: {c_number} \n"\
          "Current Process: {p_number} \n"\
          "Server Ip: {ip} \n"\
          "Time: {stime}".format(**locals())
    send_ibg_alarm(alarm_key, msg)
    send_tnm_alarm(alarm_key, msg)


def pull_up_proc(c_command):
    c_command = c_command.split(" ")
    if c_command[0] == "sh":
        base_dir = "/".join(c_command[1].split("/")[:-1])
        lock_file = "/".join([base_dir, ".lock"])
        if os.path.exists(lock_file):
            app_log.warn('Exists lock file, skip to pull up process')
        else:
            res = exec_shell(c_command)
            app_log.info(res)

class CheckProcs():
    def __init__(self):
        self.proc_info = self.get_sys_proc()
        self.proc_execs = self.get_proc_exec()

    @staticmethod
    def get_sys_proc():
        raw_data = []        
        command = ["ps", "-Ao", "pid,%cpu,%mem,stat,args"]
        out, err = exec_shell(command)
        if not err:
           raw_data = [i.strip() for i in out.split("\n") if i][1:]
           #
        else:
            app_log.error("Get pids error {err}".format(**locals()))
        
        return [ i.split() for i in raw_data]


    @staticmethod
    def chk_proc_alive(stat):
        err_stat = ["T", "X", "Z"]
        flag = True
        if filter(lambda s: str(stat).startswith(s), err_stat): 
            flag = False
        
        return flag

    def get_proc_exec(self):
        procs_exe = {}
        pids = [ i[0] for i in self.proc_info ] 
        for pid in pids:
            try:
                exe = os.readlink(os.path.join("/proc", pid, "exe"))
            except OSError as e:
                #Can't find the execute file , ignore and continue
                if e.errno != 2:
                    app_log.error('Unkown issue occurred: %s'%e)    
                continue
            except Exception as e:
                #Logging errorr massages and continue
                app_log.error('Unkown issue occurred: %s'%e)
                continue
     
            if exe in procs_exe:
                procs_exe[exe]["number"] += 1
                procs_exe[exe]["pid"].append(pid)
            else:
                procs_exe[exe] = {}
                procs_exe[exe]["number"] = 1
                procs_exe[exe]["pid"] = [pid]

        return procs_exe    

    def get_proc_util(self, pids):
        cpu = mem = 0
        is_alive = True
        stats = [0.0, 0.0, is_alive]
        def get_pid_util(stats, proc):
            stats[0] += float(proc[1])
            stats[1] += float(proc[2])
            stats[2] = stats[2] and self.chk_proc_alive(proc[3])
            return stats

        _proc_info = [ i for i in self.proc_info if i[0] in pids]
        for proc in _proc_info:
            get_pid_util(stats, proc)

        return stats

    def get_compile_proc_stat(self, exec_file):
        proc_info = self.proc_execs.get(exec_file)
        alive_number = cpu = mem = 0
        stat = False
        if proc_info:
            alive_number = proc_info.get('number', 0)
            cpu, mem, stat = self.get_proc_util(proc_info.get('pid'))

        return alive_number, cpu, mem, stat

    def get_interpret_proc_stat(self, keyword):
        pids = []
        alive_number = cpu = mem = 0
        stat = False
        args = [ [arg[0], " ".join(arg[4:])] for arg in self.proc_info ]
        for arg in args:
            if re.search(keyword, arg[1]):
                alive_number += 1
                pids.append(arg[0])
        
        if alive_number:
            cpu, mem, stat = self.get_proc_util(pids)
 
        return alive_number, cpu, mem, stat

def check_compile_proc(proc_name, section, hdproc):
    ip = options.get("local_ip")
    stime = time.strftime("%Y-%m-%d %H:%M", time.localtime())
    section = dict(section)

    c_bin_path = section.get("binpath")
    c_number = section.get("number")
    c_alarmkey = section["alarm_key"] if section.get("alarm_key", None) else options["alarm_key"]
    c_command = section.get("command", None)

    alive_number, cpu, mem, stat = hdproc.get_compile_proc_stat(c_bin_path)
    app_log.debug("|".join([ip, proc_name, str(alive_number), str(cpu), str(mem), str(stat)]))
    if int(alive_number) < int(c_number):
        app_log.error("Check {proc_name} failed, running processes({alive_number}) "\
                  "less than define processes({c_number})".format(**locals()))
        send_alarm(c_alarmkey, proc_name, c_number, alive_number, ip, stime)
        if c_command: pull_up_proc(c_command)
    else:
        app_log.info("Check {proc_name} successfully, running processes({alive_number})"
                      .format(**locals()))      
    
def check_interpretion_proc(proc_name, section, hdproc):
    ip = options.get("local_ip")
    stime = time.strftime("%Y-%m-%d %H:%M", time.localtime())
    section = dict(section)

    c_keyword = section.get('keyword')
    c_number = section.get("number")
    c_alarmkey = section["alarm_key"] if section.get("alarm_key", None) else options["alarm_key"]
    c_command = section.get("command", None)

    alive_number, cpu, mem, stat = hdproc.get_interpret_proc_stat(c_keyword)

    app_log.debug("|".join([ip, proc_name, str(alive_number), str(cpu), str(mem), str(stat)]))
    if int(alive_number) < int(c_number):
        app_log.error("Check {proc_name} failed, running processes({alive_number}) "\
                      "less than define processes({c_number})".format(**locals()))
        send_alarm(c_alarmkey, proc_name, c_number, alive_number, ip, stime)
        if c_command: pull_up_proc(c_command)
    else:
        app_log.info("Check {proc_name} successfully, running processes({alive_number})"
                      .format(**locals()))

def main(cfg_file):
    cfg = ConfigParser.RawConfigParser()
    cfg.read(cfg_file)

    #Get the api address of ibg alarm
    options["ibgalarm_api"] = cfg.get("default", "ibgalarm_api")
    #Get the alarm key
    options["alarm_key"] = cfg.get("default", "alarm_key")
    chkproc = CheckProcs()

    for sec in cfg.sections():
        if sec == "default": continue
        c_type = cfg.get(sec, "type")
        if c_type == "compile":
            check_compile_proc(sec, cfg.items(sec), chkproc)
        elif c_type == "interpret":
            check_interpretion_proc(sec, cfg.items(sec), chkproc)
        else:
            app_log.error('Unkown proc type: %s'%c_type)

options = {"log_level": "debug"}
app_log = create_log_handler()
if __name__ == "__main__":
    cfg_file = "config.ini"
    main(cfg_file)
