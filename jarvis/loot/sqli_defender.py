#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
from time import sleep
import os
from datetime import datetime
from datetime import timedelta
import threading
import urllib.request
import netifaces

local_ip = ''
banned = []

class LogClass:
    ip = ''
    date = ''
    code = ''
    longi = ''
    req = ''
    user_agent = ''
    so = ''
    flag = 0
    month = ''

    def __init__(self, ip, date, req, code, length, user_agent):
        self.ip = ip
        regex = '(\d+)/(.*)/(\d+):(.*) ' 
        logEx = re.match(regex, date).groups()
        self.month = str(logEx[1])
        month1 = to_dict(logEx[1])
        date = logEx[2] + '-' + month1 + '-' + logEx[0] + ' ' + logEx[3]
        self.date = date
        self.code = code
        self.length = length
        self.req = self.escape_req(req)
        self.user_agent = user_agent
        self.so = self.get_info_UA()
        self.flag = self.get_flag()
        
    def escape_req(self, req):
        if "'" in req:
            req = req.replace("'","\\'")
        return req

    def get_flag(self):
        r = urllib.parse.unquote(self.req).upper()
        flag = 0
        if self.flag != 0:
            return self.flag
        if "\'" in r or "\"" in r:
            flag = 1
        if 'ORDER' in r:
            flag = 2
        if 'UNION' in r:
            flag = 3
        if '9208%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23' in r:
            flag = 4
        return flag

    def get_info_UA(self):
        if 'Android' in self.user_agent:
            return 'Android'
        if 'Linux' in self.user_agent:
            return 'Linux'
        if 'Windows' in self.user_agent:
            return 'Windows'
        if 'sqlmap' in self.user_agent:
            self.flag = 4
            return 'Sqlmap'
        else:
            return 'Unknown'

def show_banner():
    print('\nSQL Injection Detector - @pepper\n---------------------------------\n\n')
    print(local_ip)
    
def to_dict(name):
	month_dict = {'Jan':'01', 'Feb':'02', 'Mar':'03', 'Apr':'04', 'May':'05', 'Jun':'06', 'Jul':'07', 'Aug':'08', 'Sep':'09', 'Oct':'10', 'Nov':'11', 'Dec':'12'}
	return month_dict[name]
    
def parse_log(line):
    try:
        regex = '(.*?) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
        log_ex = re.match(regex, line).groups()
        register = LogClass(log_ex[0], log_ex[1], log_ex[2], log_ex[3], log_ex[4], log_ex[6])
        return register
    except:
        return False
	
def follow(thefile):
    thefile.seek(0,2)
    while True:
        line = thefile.readline()
        if not line:
            sleep(0.01)
            continue
        yield line
        
def warn_log(attack):
    print('[+] Detected ' + str(attack.ip) + ' ' + str(attack.flag))
    cont = 0
    path = '/home/pepper/Web/Logs/'
    attack_date = attack.date.split('-')[0] + '-' + attack.month + '-' + attack.date.split('-')[2]
    if attack.flag == 4:
        threading.Thread(target=ban, args=(attack,)).start()
    if not os.path.isfile(path + attack.ip + '.txt'):
        f = open(path + attack.ip + '.txt', 'w')
        f.write(attack.ip + '\n' + '-------------' + '\n')
        f.close()
    else:
        f = open(path + attack.ip + '.txt', 'r')
        for i in f.readlines():
            if 'Attack' in i:
                cont = int(i.split(' ')[1])
        f.close()
    f = open(path + attack.ip + '.txt', 'a')
    f.write('Attack %d : Level %d : %s : %s\n\n' %((cont+1), attack.flag, attack_date, attack.req))
    f.close()

def ban(attack):
    num = 0
    print (local_ip)
    if not attack.ip in banned:
        banned.append(attack.ip)
        print(attack.ip)
        print(local_ip)
        os.system('iptables -t nat -I PREROUTING --src %s --dst %s -p tcp --dport 80 -j REDIRECT --to-ports 64999' %(attack.ip, local_ip))
        print('[+] %s banned' % attack.ip)
        banned_list = os.popen('iptables -t nat --line-numbers -L')
        for i in banned_list.read().split('\n'):
            if attack.ip in i:
                num = int(i.split(' ')[0])
        if num != 0:
            sleep(90)
            os.system('iptables -t nat -D PREROUTING %d' % num)
            banned.remove(attack.ip)
            print('[+] %s disbanned' % attack.ip)
    else:
        pass
        
if __name__ == '__main__':
    local_ip = netifaces.ifaddresses('ens33')[netifaces.AF_INET][0]['addr']
    time_counter = datetime.now()
    attackers = {}
    show_banner()
    logfile = open('/var/log/apache2/access.log','r')
    loglines = follow(logfile)
    for line in loglines:
        log = parse_log(line)
        if log:
            if time_counter + timedelta(seconds=8) < datetime.now():
                attackers[log.ip] = 0
                time_counter = datetime.now()
            if log.ip in attackers and 'room.php?cod' in log.req:
                attackers[log.ip] = attackers[log.ip] + 1
            else:
                attackers[log.ip] = 1
            if attackers[log.ip] > 5:
                log.flag = 4
            if log.flag != 0:
                warn_log(log)
