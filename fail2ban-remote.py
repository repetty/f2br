#!/root/.pyenv/shims/python

from pygtail import Pygtail
import paramiko
import time
import datetime
import sys
import re
import json
import os


settings = "/etc/fail2ban-remote.json"

def initialize(settings, debug_flag=False):
  with open(settings,"r") as settings_file: 
    settings = json.load(settings_file)

  global f2b_log
  global debug_log
  global remote_log
  global remote_object_list

  remote_object_list = []
  f2b_log = settings["config"]["log"]
  remote_log = settings["config"]["remote-log"]
  debug_log = settings["config"]["debug-log"]
   
  for host_json in settings["config"]["remote-hosts"]:
    if (host_json["name"] != "Home"):
      continue # Debugging: Process only Home
    #serverobj = remote_server_class(host_json)
    remote_object_list.append(remote_server_class(host_json, False)) # Create object and add to list.

    if debug_flag: # Write debug variables to debug log file
      with open(debug_log,"a") as debug_log:
        logstamp = datetime.now().strftime("%Y-%m-%d %X  ")
        debug_log.write(logstamp + f"Log File: {f2b_log}\n")
        debug_log.write(logstamp + f"Remote Log File: {remote_log}\n")
        debug_log.write(logstamp + f"Remote instance list = {remote_object_list}\n")



class remote_server_class:
  def __init__(self, host_json, debug_flag=False):
    global f2b_log
    global debug_log
    global remote_log
    global remote_object_list

    self.name = host_json["name"]
    self.host = host_json["host"]
    self.port = host_json["port"]
    self.user = host_json["user"]
    self.sshkeyfile = host_json["sshkeyfile"]
    self.debug_flag = debug_flag
    self.logfile = remote_log
    self.debug_log = debug_log

    if debug_flag: # Print debug variables.
      with open(debug_log,"a") as debug_log:  # Write to error log file.
        self.debug_log.write(f"self.name = {self.name}")
        self.debug_log.write(f"self.host = {self.host}")
        self.debug_log.write(f"self.port = {self.port}")
        self.debug_log.write(f"self.user = {self.user}")
        self.debug_log.write(f"self.sshkeyfile = {self.sshkeyfile}")

  def update(self, log_argument, debug_flag=False):
    sshclientobj = paramiko.SSHClient()
    sshclientobj.load_system_host_keys()
    sshclientobj.set_missing_host_key_policy(paramiko.WarningPolicy)
    sshclientobj.connect(self.host, self.port, self.user, self.sshkeyfile)
    stdin, stdout, stderr = sshclientobj.exec_command(f2bcmd)
    # print(stdout.read().decode('UTF-8'))
    sshclientobj.close()
    
    with open(self.logfile,"a") as remote_log:  # Write log file.
      remote_log.write(log_argument[:20] + self.host + log_argument[20:] + "\n")
    
    if debug_flag: # Write debug variables to debug log file.
      with open(self.debug_log,"a") as debug_log:
        debug_log.writelines(f"self.name = {self.name}")
        debug_log.writelines(f"self.host = {self.host}")
        debug_log.writelines(f"self.port = {self.port}")
        debug_log.writelines(f"self.user = {self.user}")
        debug_log.writelines(f"self.sshkeyfile = {self.sshkeyfile}")






initialize(settings, False)


pid = os.fork()
if pid:
  with open("/run/fail2ban-remote/fail2ban-remote.pid", 'w') as pidfile:
    # Used by systemctl.
    pidfile.write(str(pid))

  logline = datetime.now().strftime("%Y-%m-%d %X") + f" Daemon started with PID {pid}\n"
  # print(logline)
  # print(remote_log)
  with open(remote_log, "a") as remote_log:  # Write log file.
    remote_log.write(logline)
  os._exit(0)  # Kill original process.


print("Fork completed.")


while True:
  # print("Waited one second.")
  time.sleep(1)

  for line in Pygtail(f2b_log):

    #  2019-12-13 13:43:28,052 fail2ban.actions [12037]: NOTICE  [apache-immediate] Ban 69.162.79.242
    matches = re.findall(r'.*\[(\S+)\] Ban (.*)', line)

    if (matches):
      # If the new bad IP number does not exist in f2b on the remote server currently,
      # then execute the f2b ban command for that IP number.
      jail = matches[0][0]
      ip = matches[0][1]
      f2bcmd = f"! fail2ban-client status {jail} | grep {ip} && fail2ban-client set {jail} banip {ip}"

      f2b_remote_log_line = datetime.now().strftime("%Y-%m-%d %X") + f"  {jail} {ip}"

      # Execute an update for each host, in turn.
      for remote_server_object_instance in remote_object_list:
        remote_server_object_instance.update(f2b_remote_log_line, True)
        

