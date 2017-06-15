#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import time
import unittest

from ConfigParser import ConfigParser
from pyinotify import ProcessEvent
from pyinotify import WatchManager
from pyinotify import Notifier
from pyinotify import IN_MOVED_TO,IN_MODIFY, IN_CLOSE_WRITE,ALL_EVENTS#, IN_UNMOUNT,IN_ACCESS,IN_OPEN,IN_DELETE_SELF,IN_CLOSE_NOWRITE,IN_DELETE,IN_ATTRIB,ALL_EVENTS
import getopt
import traceback
import gzip
import logging
#import pyhdfs
from multiprocessing import Process,Queue,Pool
import signal
import re

from gevent import monkey
#monkey.patch_socket()
#monkey.patch_os()
#monkey.patch_time()
import gevent

import redis
import gc

gc.enable()

FILENME_QUEUE=Queue()

IP_KEY_QUEUE = Queue()

logger = logging.getLogger("nac");
logger.setLevel(logging.DEBUG)
ch = logging.FileHandler("/var/log/nginx_parse.log")
formatter = logging.Formatter('%(asctime)s - %(name)s - %(process)d - %(levelname)s - %(message)s')  
ch.setFormatter(formatter)
logger.addHandler(ch)

__all__ = ["Log_Conf_handler"]

monitorerd_log_dir_list=set([])
daemon_list=set([]);
wm = WatchManager();

def on_signal_term(sino,stack):
    logger.info("recvie TERM signal,excute stop~")
    for i in daemon_list:
        logger.info("stop process: {0}".format(i))
        os.kill(i, signal.SIGTERM);
        logger.info("stop process: {0} over~~".format(i));
    logger.info("stop all process over");
    sys.exit(0)
#signal.signal(signal.SIGTERM, on_signal_term);


class Log_File_Create_Handler(ProcessEvent):
    def my_init(self):
        pass;

class Settings(object):
    cp = ConfigParser()
    cp.read("/etc/nginx_log_dir.conf")
    log_dir = cp.get("master","log_dir")
    redis_ip_host = cp.get("redis-ip","host")
    redis_ip_port = cp.getint("redis-ip","port")
    redis_ip_db = cp.get("redis-ip","db")
    redis_ip_password = cp.get("redis-ip","auth")
    
    redis_uri_host = cp.get("redis-uri","host")
    redis_uri_port = cp.getint("redis-uri","port")
    redis_uri_db = cp.get("redis-uri","db")
    redis_uri_password = cp.get("redis-uri","auth")    
        

class Parser(object):
    def __init__(self):
        global logger
        self.logger = logger
        self.redis_ip_pool = redis.ConnectionPool(host = Settings.redis_ip_host, port = Settings.redis_ip_port, max_connections=500)
        self.redis_uri_pool = redis.ConnectionPool(host = Settings.redis_uri_host, port = Settings.redis_uri_port, max_connections=500)
        self.redis_ip = redis.Redis(connection_pool=self.redis_ip_pool)
        self.redis_uri = redis.Redis(connection_pool=self.redis_uri_pool)        

    def parse(self,filename):
        global IP_KEY_QUEUE
        self.logger.info("run parse for : %s"%filename)
        def run(data):
            global IP_KEY_QUEUE
            try:
                ip_key_set = set([])
                for line in data:
                    line_list = line.split()
                    remote_addr = line_list[0]
                    if line_list[-1] != "\"-\"":
                        remote_addr = line.split("\"")[-2].split(",")[0]
                    remote_addr = remote_addr.strip(",")
                    ip_key_set.add(remote_addr)
                    ret = self.redis_ip.incr(remote_addr,amount=1)
                    if ret == 1:
                        self.redis_ip.expire(remote_addr,60)
                    
                    uri = line_list[7].split("?")[0]
                    ret = self.redis_uri.incr(uri,amount=1)
                    if ret == 1:
                        self.redis_uri.expire(uri,60)
                gc.collect()
                self.logger.debug("process: %d parse done"%(os.getpid()))
                IP_KEY_QUEUE.put(ip_key_set)
            except Exception,e:
                self.logger.error(e)
                self.logger.exception(e)
        def remove_key(keys):
            for key in keys:
                try:
                    value = self.redis_ip.get(key)
                    if not value:
                        continue
                    if int(value) < 500:
                        self.redis_ip.delete(key)
                    else:
                        self.redis_ip.rename(key,"counter:%s"%key)
                except redis.ResponseError,e:
                    pass
                except Exception,e:
                    self.logger.exception(e)
            self.logger.debug("process: %s prunne done"%(os.getpid()))
        #jobs = []
        with open(filename) as fp:
            count  = 0
            batch = 0
            lines = []
            for line in fp:
                lines.append(line)
                if count <= 20000:
                    count+=1
                else:
                    count = 0
                    #jobs.append(gevent.spawn(run,(lines)))
                    #self.logger.info("start subprocess for batch: %d"%batch)
                    p=Process(target=run,args=(lines,))
                    p.daemon = False
                    p.start()
                    #self.logger.info("process: %s parse batch: %s"%(p.pid,batch))
                    lines = []
                    batch += 1
            self.logger.debug("start %d process to write redis"%batch)
            lines = []
            
        self.logger.info("start prunne key that access less than 500")
        read_batch = 0
        while IP_KEY_QUEUE.qsize() < batch:
            time.sleep(3)
        self.logger.info("recive %d batch that had done"%batch)
        for x in xrange(batch):
            self.logger.debug("get ip list ....")
            keys = IP_KEY_QUEUE.get()
            self.logger.debug("get ip list done,start process : %d to prunne batch: %d redis key"%(p.pid,x))
            p = Process(target=remove_key,args=(keys,))
            p.daemon = False
            p.start()
            self.logger.debug("start process : %d to prunne batch: %d redis key done"%(p.pid,x))
        
class Log_Conf_handler(ProcessEvent):
    __doc__='''
    name: Log_Conf_handler
    description: response for specific file change event:IN_CLOSE_WRITE,IN_MODIFY,IN_MOVED_TO
    '''
    reg = re.compile(".*\.tmp")
    def my_init(self):
        __doc__ = '''
        name: Log_Conf_handler.my_init
        description: just implements supper class' abs method
        input: 
              None
        output:
              None
        '''
        global FILENME_QUEUE
        self.queue = FILENME_QUEUE
    def process_default(self,event):
        __doce__='''
        name: Log_Conf_handler.process_default
        description: process the events that this class had not specify
        inut:
             event ProcessEvent,resprent the recived event
        output:
             None
        '''
        logger.info("{0} change,methods is: {1}".format(event.pathname,event.maskname)); 
        if not Log_Conf_handler.reg.match(event.pathname):
            logger.info("{0} change,methods is: {1}".format(event.pathname,event.maskname)); 
    def process_IN_MOVE(self,event):
        __doc__ = '''
        name: Log_Conf_handler.process_IN_MOVE
        description: process IN_MOVE event.just log.
        input:
              event,ProcessEvent,resprent the IN_MOVE event
        output:
              None
        '''
        logger.info("{0} move".format(event.pathname));
    def process_IN_CREATE(self,event):
        __doc__ = '''
            name: Log_Conf_handler.process_IN_CREATE
            description: process IN_MOVE event.just log.
            input:
                  event,ProcessEvent,resprent the IN_MOVE event
            output:
                  None
            '''        
        logger.info("{0} create".format(event.pathname));
    def process_IN_CLOSE(self,event):
        __doc__ = '''
            name: Log_Conf_handler.process_IN_CLOSE
            description: process IN_CLOSE event.just log.
            input:
                  event,ProcessEvent,resprent the IN_MOVE event
            output:
                  None
            '''        
        logger.info("{0} close".format(event.pathname));    
    def process_IN_MOVED_TO(self,event):
        __doc__ = '''
            name: Log_Conf_handler.process_IN_MOVED_TO
            description: process IN_MOVED_TO event.Compress the specific file matches regular
            input:
                  event,ProcessEvent,resprent the IN_MOVE event
            output:
                  None
            '''        
        if not Log_Conf_handler.reg.match(event.pathname):
            logger.info("{0} parse starting ...".format(event.pathname));
            self.queue.put(event.pathname)
            logger.info("{0} parse complete".format(event.pathname));
    
    def process_IN_CLOSE_WRITE(self,event):
        __doc__ = '''
            name: Log_Conf_handler.process_IN_CLOSE_WRITE
            description: process IN_CLOSE_WRITE event.Compress the specific file matches regular
            input:
                  event,ProcessEvent,resprent the IN_MOVE event
            output:
                  None
            '''
        logger.info(event.pathname)
        if not Log_Conf_handler.reg.match(event.pathname,True):
            '''
            parse
            '''
            logger.info("{0} is/has a compressed file, ignored!".format(event.pathname));
    
        
    def process_IN_MODIFY(self,event):
        __doc__ = '''
            name: Log_Conf_handler.process_IN_MODIFY
            description: process IN_MODIFY event.add watch on specific path
            input:
                  event,ProcessEvent,resprent the IN_MODIFY event
            output:
                  None
            '''
        pass
    
    @staticmethod
    def main():
        __doc__ = '''
            name: Log_Conf_handler.main
            description: daemon entry
            input:
                  None
            output:
                  None
            '''         
        global daemon_list
        global wm
        global monitorerd_log_dir_list
        
        daemon_list.update([os.getpid()]);
        wm.add_watch(path=Settings.log_dir, mask=IN_CLOSE_WRITE | IN_MOVED_TO,rec=False,auto_add=True);
        logger.info("config watch for {0} use process: {1}".format(Settings.log_dir,os.getpid()));
        logger.info("start excute main entry, process {0}....".format(os.getpid()));
        handler = Log_Conf_handler();
        notifier = Notifier(watch_manager=wm, default_proc_fun=handler);
        #daemon_list.update(dict([("main",os.getpid)]))
        #notifier.loop(daemonize=False);
        def parse():
            global logger
            logger.info("start parser subprocess")
            monkey.patch_all()
            p = Parser()
            while True:
                logger.debug("start recive data from filename queue")
                filename = FILENME_QUEUE.get()
                logger.debug("recive data : %s from filename queue and parse"%filename)
                try:
                    p.parse(filename)
                except Exception as e:
                    logger.exception(e)
        parse_process = Process(target=parse)
        parse_process.daemon = False
        parse_process.start()
        open("/var/run/nac-agent.pid","a").write(" %s"%parse_process.pid);
        notify_process = Process(target=notifier.loop,args=(),kwargs={"daemonize":False})
        notify_process.daemon = False
        notify_process.start()
        open("/var/run/nac-agent.pid","a").write(" %s"%notify_process.pid);
        notify_process.join()
        logger.info("daemonized!");

def help():
    __doc__ = '''
    name: help
    description: print help message
    input:
          None
    output:
          None
    '''
    print('''Usage:
        log_transfer -h -u username -d backend_driver
            -h print help message
            -u the target user
            -d chose the storage type that store the log records''');
    sys.exit(0)

def daemon(func,args=None):
    __doc__ = '''
    name: daemon
    description: daemonize main process
    input:
          None
    output:
          None
    '''
    pid=os.fork();
    if pid > 0:
        sys.exit(0);
    elif pid == 0:
        os.chdir("/");
        os.umask(0);
        os.setsid();
        pid2=os.fork();
        if pid2 > 0:
            logger.info("daemon start with pid: {0}".format(pid2))
            open("/var/run/nac-agent.pid","w").write("%s"%pid2);
        elif pid2 == 0:
            for f in sys.stdout, sys.stderr: f.flush();
            si = file("/dev/null", 'r');
            so = open("/tmp/nac-agent.log",'a');
            os.dup2(si.fileno(), sys.stdin.fileno())
            os.dup2(so.fileno(), sys.stdout.fileno())
            os.dup2(so.fileno(), sys.stderr.fileno())
            if args:
                func(args);
            else:
                func();
        else:
            print("2 fork failed");
    else:
        print("fork failed!");

if __name__ == "__main__":
    #unittest.main();
    if not os.path.isfile("/etc/nginx_log_dir.conf"):
        os.mknod("/etc/nginx_log_dir.conf");
    daemon(Log_Conf_handler.main);
    #Log_Conf_handler.main()
