# UE-DDNS
# [中文说明 ](https://blog.03k.org/post/ue-ddns.html)
## Universal Embedded DDNS Shell Script  
UE-DDNS is an embedded POSIX shell DDNS script that is designed with a modular and minimalist approach to dependencies and guided design.
- Supports both IPV4 and IPV6, and can obtain dynamic IP from URL or network interface
- Compatible with most Unix platforms, including some embedded devices with only busybox, and relies on fewer commands as much as possible
- Users only need to provide API KEY, and the rest are multiple-choice questions, directly generating custom scripts
- New domain names can be added directly in the wizard, one step at a time
- Can set proxy, set traffic to go through a specified network interface, and automatically detect openwrt installation support
- Strict IP comparison is performed to comply with API calling specifications and avoid submitting duplicate IP update requests
- Supports multiple message push methods, making it easy to receive dynamic IP update notifications on a mobile phone

Currently supported DNS service providers:  
- [Cloudflare](https://www.cloudflare.com/)
- [Dnspod.cn](https://www.dnspod.cn/)
- [Dnspod.com International ](https://www.dnspod.com/)
- [Godaddy](https://www.godaddy.com/)  

##  How to use
You can download the script from the following two url：  
`https://ddns.03k.org`  
`https://raw.githubusercontent.com/kkkgo/UE-DDNS/main/ue-ddns.sh`   
You can run the following command to start :    
```shell  
curl -skLo ue-ddns.sh ddns.03k.org  
sh ue-ddns.sh
```  
If curl not found, you can run:   
```shell
wget --no-check-certificate https://ddns.03k.org -O ue-ddns.sh
sh ue-ddns.sh
```  
After the script runs, a wizard will prompt you to choose your DNS service provider and choose IPV4/IPV6:  
```shell
=========================================
# Universal embedded DDNS Shell Script #
# https://github.com/kkkgo/UE-DDNS
# https://blog.03k.org/post/ue-ddns.html
=========================================
[1] cloudflare
[2] dnspod
[3] godaddy
Select your DNS provider[1]:1
cloudflare DDNS:
[1] IPV4 DDNS
[2] IPV6 DDNS
IPV4/IPV6 DDNS?[1]:1
```
Next, according to the DNS service provider you choose, you need to provide the corresponding API KEY, and the wizard will give a url help to apply for API KEY.If you have more than one domain name, you will see the main domain name selection list after entering the key, followed by the sub-domain name selection list. The display effect depends on the API of the DNS service provider.      
```shell
[help] https://dash.cloudflare.com/profile/api-tokens
Your cloudflare API TOKEN:***************************
[1] 03k.org
[2] example.com
Select your domain name[1]:1
Domain: 03k.org
IPV4 sub domain list:
[0] Add a new subdomain name
[1] 03k.org A 1.2.3.4
[2] office.03k.org A 5.6.7.8
[3] myhome.03k.org A 6.7.8.9
[4] www.03k.org A 1.2.3.4
Select your IPV4 subdomain name[0]:
```
You can directly select your subdomain name on the list to generate the DDNS script, and you can choose to use the URL to get the dynamic IP:  
```shell
How to get your new IP ?
[1]From IP-Check URL
[2]From Interface
Your choice [1]:1
DDNS script generation completed!
/root/myhome.03k.org@cloudflare_IPV4_URL.sh:
-rwxrwxrwx 1 root root 12K Mar  8 18:36 myhome.03k.org@cloudflare_IPV4_URL.sh
```
Or you can directly choose to specify the IP of a interface:    
```shell
How to get your new IP ?
[1]From IP-Check URL
[2]From Interface
Your choice [1]:2
[1] eth0 111.20.3.1
[2] eth1 112.30.1.4
[3] Enter the network interface manually
Please select your interface [1]
DDNS script generation completed!
/root/myhome.03k.org@cloudflare_IPV4_eth0.sh:
-rwxrwxrwx 1 root root 12K Mar  8 18:40 myhome.03k.org@cloudflare_IPV4_eth0.sh
```
If you choose Cloudflare, the script will also ask you if you want to enable the CDN proxy for this domain:   
```shell
Turn on Cloudflare CDN proxied for myhome.03k.org?
[1]Disable
[2]Enable
```
In the subdomain list menu, you can also select [0] to create your new subdomain:   
```shell
Select your IPV4 subdomain name[0]:0
Create New: Enter sub domain [ Like ddns ]:myhomeddns
Turn on Cloudflare CDN proxied for myhomeddns.03k.org?
[1]Disable
[2]Enable
Your choice [1]:1
How to get your new IP ?
[1]From IP-Check URL
[2]From Interface
Your choice [1]:1
DDNS script generation completed!
/root/myhomeddns.03k.org@cloudflare_IPV4_URL.sh:
-rwxrwxrwx 1 root root 12K Mar  8 18:57 myhomeddns.03k.org@cloudflare_IPV4_URL.sh
```  
Finally, you'll get a custom DDNS script in the current directory that you can try to `sh xxxx@xxx.sh` to test it.    
After the script is generated, you can 'rm ue-ddns.sh'.    
Depending on what DNS service provider you choose and what options you customize, the script looks like this:    
```shell
2023-03-08 23:20:58 CST
URL IP : 218.56.43.21
DNS IP : 116.78.34.11
API IP : 116.78.34.11
Trying to update: myhomeddns.mytestdomain2023.com -> 218.56.43.21
Update OK: "type":"A","content":"218.56.43.21","proxiable":true,"proxied":false
```
## How to deploy the script
- There is basically a crontab (scheduled task) on Linux systems, assuming that the script has been added with executable permissions:`chmod +x ./ddns.sh`, in `/root/ddns.sh`:   
Edit cron: `crontab -e`   
 `*/10 * * * * /root/ddns.sh &>/dev/null`    
It means every 10 minutes. The log will be blocked. Of course, if you need to log, you can redirect directly to the save path.    
- The hotplug interface can automatically execute the script when the network card IP changes. For example, openwrt, when you choose to get the IP from the network interface, the script will prompt you whether to directly generate the script in the hotplug directory：   
```shell
How to get your new IP ?
[1]From IP-Check URL
[2]From Interface
Your choice [1]:2
[1] wan 116.22.1.118
[2] br-lan 10.10.10.1
[3] Enter the network interface manually
Please select your interface [1]
Detected hotplug support, generate script in /etc/hotplug.d/iface ?
[1] No.
[2] Move to /etc/hotplug.d/iface
Your choice [1]:2
DDNS script generation completed!
/etc/hotplug.d/iface/myhome.03k.org@cloudflare_IPV4_wan.sh:
-rwxr-xr-x    1 root     root       11.1K Mar  8 23:15 /etc/hotplug.d/iface/myhome.03k.org@cloudflare_IPV4_wan-lan.sh
```

## Custom Options and Message Notifications
After the script is generated, you can also adjust some custom options within the generated script.(Region from # Customizable option area to # Customizable option end).  
Custom options：  
- **PROXY** Set a proxy for the connection API, such as PROXY="http://192.168.1.100:7890"
- **OUT** Set script network traffic to go to which network card, such as OUT="eth0" (Only curl is supported)  
- **CHECKURL** Set the URL used to detect the IP address. The script has built in some websites to get the IP address. When it fails, it will try to get it in turn.The CHECKURL you set will be tried first.    
- **ValidateCA** verifies the validity of the certificate and is disabled by default.You need to complete the CA certificate yourself for the local environment, for example, most Linux needs to install the ca-certificates package.  
  
Message notification options:    
- **ddns_ntfy_url** ntfy is a simple HTTP-based pub-sub notification service.    
Website：https://ntfy.sh/  
Example：`ddns_ntfy_url="http://ntfy.sh/yourtopic"`  
- **ddns_bark_url** Bark is an iOS App which allows you to push customed notifications to your iPhone.    
Website：https://github.com/Finb/bark-server  
Example：`ddns_bark_url="https://api.day.app/yourkey"`  
 - **ddns_sct_url** ServerChan, a push service that can be pushed to WeChat.  
Website： https://sct.ftqq.com/   
Example：`ddns_sct_url="https://sctapi.ftqq.com/yourkey.send"`    
- **ddns_pushplus_url** Pushplus, a push service that can be pushed to WeChat.   
Website：https://www.pushplus.plus/    
Example：`ddns_pushplus_url="http://www.pushplus.plus/send?token=yourkey"`     
- **ddns_dingtalk_url** dingtalk group robot push.Please add keyword: IP     
Website：https://open.dingtalk.com/document/robots/custom-robot-access/      
Example：`ddns_dingtalk_url="https://oapi.dingtalk.com/robot/send?access_token=yourkey"`     
The script only has a few built-in notification options "out of the box". If you want to use your own Webhook, you can search for push_result functions in the generated script.     

## About
License：GPLv3   
Blog: [https://blog.03k.org/post/ue-ddns.html ](https://blog.03k.org/post/ue-ddns.html)   



