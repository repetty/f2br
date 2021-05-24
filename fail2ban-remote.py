#!/root/.pyenv/shims/python

from pygtail import Pygtail
import paramiko
import time
from datetime import datetime
import sys
import re
import json
import os


settings = "/etc/fail2ban-remote.json"

def initialize(settings):
  with open(settings,"r") as settings_file: 
    settings = json.load(settings_file)

  global f2b_log
  global remote_log
  global remote_server_list

  remote_server_list = []
  f2b_log = settings["config"]["log"]
  remote_log = settings["config"]["remote-log"]
   
  for host_json in settings["config"]["remote-hosts"]:
    if (host_json["name"] != "Home"):
      continue # Debugging: Process only Home
    #serverobj = remote_server_class(host_json)
    remote_server_list.append(remote_server_class(host_json)) # Create object and add to list.


class remote_server_class:
  def __init__(self, host_json):
    global f2b_log
    global remote_log
    #global remote_server_list

    self.name = host_json["name"]
    self.host = host_json["host"]
    self.port = host_json["port"]
    self.user = host_json["user"]
    self.sshkeyfile = host_json["sshkeyfile"]
    self.logfile = remote_log
    self.update_dict_list = []  # List of dicts:  [{"jail": "apache-immediate", "ip": "123.123.123.123"}]

  def update(self):
    if self.update_dict_list:
    
      sshclientobj = paramiko.SSHClient()
      sshclientobj.load_system_host_keys()
      sshclientobj.set_missing_host_key_policy(paramiko.WarningPolicy)

      try:

        sshclientobj.connect(self.host, self.port, self.user, self.sshkeyfile)
        
        update_dict_list_copy = self.update_dict_list
        for remote_dict_host in update_dict_list_copy:
          # remote_dict_host looks like this:  {'jail': 'apache-immediate-remote', 'ip': '34.64.218.113'}

          get_already_banned_cmd = f"fail2ban-client status {remote_dict_host['jail']}"

          # Fetch currently banned by jail into a list. Don't want to re-ban those.
          stdin, stdout, stderr = sshclientobj.exec_command(get_already_banned_cmd)
          already_banned_list = re.findall(r'\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}', \
            stdout.read().decode('UTF-8'))

          if f"{remote_dict_host['ip']}" not in already_banned_list:
            ban_cmd = f"fail2ban-client set {remote_dict_host['jail']} banip {remote_dict_host['ip']}"
            # ban_cmd like this:  fail2ban-client set apache-immediate-remote banip 34.64.218.113
            # Now ban the IP on the remote host:
            stdin, stdout, stderr = sshclientobj.exec_command(ban_cmd)

            with open(self.logfile,"a") as remote_log:
              # Write fail2ban-remote log file.
              f2b_remote_log_line = datetime.now().strftime("%Y-%m-%d %X") \
                + f" {remote_dict_host['jail']} {remote_dict_host['ip']}"
              remote_log.write(f"{f2b_remote_log_line}\n")

          else:
            # Debugging message.
            print(f"{remote_dict_host['ip']}", "is already banned.")
        
          self.update_dict_list.remove(remote_dict_host)
      except:
        # Something went wrong, probably with SSH connection, so bug out. This retains
        # the (remaining) list of ban candidates in memory for a future run.
        pass
      sshclientobj.close()
    

initialize(settings)

pid = os.fork()
if pid:
  with open("/run/fail2ban-remote/fail2ban-remote.pid", 'w') as pidfile:
    # Used by systemctl.
    pidfile.write(str(pid))

  logline = datetime.now().strftime("%Y-%m-%d %X") + f" daemon started with PID {pid}\n"
  # print(logline)
  # print(remote_log)
  with open(remote_log, "a") as remote_log:  # Write log file.
    remote_log.write(logline)
  os._exit(0)  # Kill original process.

print("Fork completed.")


while True:
  time.sleep(1)

  for logline in Pygtail(f2b_log):

    #  2019-12-13 13:43:28,052 fail2ban.actions [12037]: NOTICE  [apache-immediate] Ban 69.162.79.242
    matches = re.findall(r'.*\[(\S+)\] Ban (.*)', logline)
    # jail, ip = re.search(r'.*\[(\S+)\] Ban (.*)', logline)
    # print(jail)

    if matches:
      jail = matches[0][0]
      ip = matches[0][1]

      if not jail.endswith("-remote"):
        # Log entry not created by another fail2ban-remote instance. It's legit.

        for remotehost in remote_server_list:
          print("Jail and IP = ", f"{jail}-remote", ip)
          remotehost.update_dict_list.extend([{"jail": f"{jail}-remote", "ip": ip}])

        # f2b_remote_log_line = datetime.now().strftime("%Y-%m-%d %X") + f"  {jail}-remote {ip}"

  # Execute an update for each host, in turn.
  for remote_server_object_instance in remote_server_list:
    remote_server_object_instance.update()
