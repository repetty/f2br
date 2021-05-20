# f2br
##Daemon to Synchronize fail2ban Instances
----

f2br is a distributed service which insures that Internet hosts banned from making network connections by fail2ban on one member server are banned on all member servers.

The f2br software tails fail2ban's log file, looking for ban actions. It then executes a fail2ban client ban command on remote servers over SSH. fail2ban does not have a programming API and hacking fail2ban scripts to make this software event-driven would make the system very fragile and susceptible to changes caused by normal fail2ban software updates.

The f2br code is written in Python 3 and requires no special modules that aren't already available via pip.



References
https://www.fail2ban.org/
