#!/bin/sh
# Universal embedded DDNS Shell Script
# Github:https://github.com/kkkgo/UE-DDNS
# Blog: https://blog.03k.org/post/ue-ddns.html
#func-Universal
# [!]Be careful not to change any "#" line in the script.

#-DDNSINIT-
#Customizable option area

# Customize the network proxy that connects to the DNS provider API
# example1: PROXY="http://192.168.1.100:7890"
# example2: PROXY="socks5h://192.168.1.100:7890" (curl only)
PROXY=""

# Specifies a network interface is used to connect to the network (curl only)
# example: OUT="eth0"
OUT=""

# Custom Web sites that check IP addresses
# example: CHECKURL="http://ipsu.03k.org"
CHECKURL=""

# ValidateCA=1, will verify the validity of the HTTPS certificate.
# You need to configure the CA certificate environment on the current system,
# such as installing the ca-certificates package.
ValidateCA=0

# ntfy is a simple HTTP-based pub-sub notification service.
# https://ntfy.sh/
# ddns_ntfy_url="http://ntfy.sh/yourtopic"

# Bark is an iOS App which allows you to push customed notifications to your iPhone.
# https://github.com/Finb/bark-server
# ddns_bark_url="https://api.day.app/yourkey"

# sct is a message push platform(wechat).
# https://sct.ftqq.com/
# ddns_sct_url="https://sctapi.ftqq.com/yourkey.send"

# pushplus is a message push platform(wechat).
# https://www.pushplus.plus/
# ddns_pushplus_url="http://www.pushplus.plus/send?token=yourkey"

#Customizable option end

versionUA="github.com/kkkgo/UE-DDNS"
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin:/opt/sbin:$PATH"
IPREX4='([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
IPREX6="(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
PUBIPREX6="2[0-9a-fA-F]{3}:[0-9a-fA-F:]+"
DOMAINREX="[0-9a-z-]+\.[\.0-9a-z-]+"
date +"%Y-%m-%d %H:%M:%S %Z"
#func-DDNSINIT

export_func() {
    func_name=$1
    func_start=$(cat $0 | grep -n "$func_name" | head -1 | grep -Eo "^[0-9]+")
    func_end=$(cat $0 | grep -n "func-""$func_name" | head -1 | grep -Eo "^[0-9]+")
    sed -n "$func_start","$func_end"p $0
}

# strip IP
stripIP() {
    if [ "$2" = "6" ]; then
        echo "$1" | grep -Eo "$IPREX6" | grep -Eo "$PUBIPREX6"
    else
        echo "$1" | grep -Eo "$IPREX4"
    fi
    return $?
}
#func-stripIP

# pingDNS example.com 4/6
pingDNS() {
    if [ "$2" = "6" ]; then
        TEST=$(stripIP $"$(ping -6 -c1 -W1 "$1" 2>&1)" "6") || return 1
    else
        TEST=$(stripIP $"$(ping -4 -c1 -W1 "$1" 2>&1)" "4") || return 1
    fi
    stripIP $"$TEST" "$2" | head -1
    return 0
}
#func-pingDNS

# nslookupDNS example.com 4/6
nslookupDNS() {
    if NSTEST=$(nslookup "$1" 223.5.5.5 2>&1) || NSTEST=$(nslookup "$1" 2>&1) || NSTEST=$(nslookup 1.0.0.1 "$1" 2>&1); then
        TEST=$(stripIP $"$NSTEST" "$2") || return 1
        stripIP $"$TEST" "$2" | tail -1
        return 0
    fi
    return 1
}
#func-nslookupDNS

# curlDNS example.com 4/6
curlDNS() {
    if [ "$2" = "6" ]; then
        TEST=$(stripIP $"$(curl -6kvsL "$1" -m 1 2>&1)" "6") || return 1
    else
        TEST=$(stripIP $"$(curl -4kvsL "$1" -m 1 2>&1)" "4") || return 1
    fi
    stripIP $"$TEST" "$2" | head -1
    return 0
}
#func-curlDNS

# wgetDNS example.com 4/6 , inet*-only option only on high version wget.
wgetDNS() {
    TEST=$(stripIP $"$(wget --spider -T1 "$1" 2>&1)" "$2") || return 1
    stripIP $"$TEST" "$2" | head -1
    return 0
}
#func-wgetDNS

getDNSIP() {
    IPV="$2"
    if [ -z "$2" ]; then
        IPV="4"
    fi
    nslookupDNS "$1" "$IPV" || pingDNS "$1" "$IPV" || curlDNS "$1" "$IPV" || wgetDNS "$1" "$IPV" || echo "Get ""$1"" IPV""$IPV"" DNS IP Failed."
}
#func-getDNSIP

# genfetchCMD $URL $useProxy $fetchIPV
# postMethod=;postdata=;fetchCMD http://blog.03k.org useProxy 4/6/0
genfetchCMD() {
    if echo "$3" | grep -Eqo "^[46]{1}$"; then
        fetchIPV=$3
    else
        fetchIPV=""
    fi
    export http_proxy=""
    fetchProxy=""
    if echo "$2" | grep -qEo "useProxy"; then
        if echo $PROXY | grep -qEo ":"; then
            fetchProxy=$PROXY
            if echo $PROXY | grep -qEo "http:"; then
                export http_proxy=$fetchProxy
            fi
        fi
    fi
    fetchPost=""
    if [ -n "$postData" ]; then
        fetchPost=$postData
        postData=""
    fi
    if [ -n "$postMethod" ]; then
        fetchMethod=$postMethod
        postMethod=""
    else
        fetchMethod="POST"
    fi
    fetchLine=$OUT
    URL=$1
    fetchBIN="curl"
    curlVer=$(curl -V 2>&1) || fetchBIN="wget"
    if [ "$fetchBIN" = "curl" ]; then
        echo curl -"$fetchIPV"sL -m5 -A "$versionUA"@curl-"$(echo "$curlVer" | grep -Eo "[0-9.]+" | head -1)" \
            $(if [ "$ValidateCA" != "1" ]; then echo "-k"; fi) \
            $(if [ -n "$fetchLine" ]; then echo "--interface $fetchLine"; fi) \
            $(if [ -n "$fetchProxy" ]; then echo "-x $fetchProxy"; fi) \
            $(if [ -n "$fetchPost" ]; then echo "-X $fetchMethod -d $fetchPost"; fi) \
            "$URL"
    else
        fetchwget=$(wget -V 2>&1) || fetchwget="busybox"
        if [ "$fetchwget" = "busybox" ]; then
            # busybox wget : Not support IPV46/OUT/SOCKS/fetchMethod
            wgetVersion=$(busybox 2>&1 | grep -Eo "[0-9.]+" | head -1)
            echo wget -U "$versionUA"@wget/busybox"$wgetVersion" -q -O- -T5 -Y \
                $(if [ -n "$fetchProxy" ]; then echo "on"; else echo "off"; fi) \
                $(if [ "$ValidateCA" != "1" ]; then echo "--no-check-certificate"; fi) \
                $(if [ -n "$fetchPost" ]; then echo --post-data "$fetchPost"; fi) \
                "$URL"
        else
            # GNU wget: Not support OUT/SOKCS
            wgetVersion="GNUwget-"$(wget -V | grep -Eo "[0-9.]+" | head -1)
            echo wget -U "$versionUA"@"$wgetVersion" -q"$fetchIPV" -O- --no-check-certificate -T5 \
                $(if [ -n "$fetchProxy" ]; then echo "--no-proxy"; fi) \
                $(if [ -n "$fetchPost" ]; then echo "--method=$fetchMethod --body-data=$fetchPost"; fi) \
                "$URL"
        fi
    fi
}
#func-genfetchCMD

getURLIP() {
    IPV=$1
    if [ -z "$1" ]; then
        IPV="4"
    fi
    TESTURLS="$CHECKURL http://ipsu.03k.org http://test.ipw.cn https://www.cloudflare.com/cdn-cgi/trace http://ip.gs http://ident.me/ http://4.ipw.cn/ http://6.ipw.cn/ https://v4.ident.me/ https://v6.ident.me/"
    TESTLIST=$(echo "$TESTURLS" | grep -Eo "http[^ ]+")
    countTESTLIST=$(echo $TESTLIST | grep -Eo "http[^ ]+" | grep -c "")
    i=0
    while [ $i -ne $countTESTLIST ]; do
        i=$(($i + 1))
        testurl=$(echo "$TESTLIST" | grep -Eo "http[^ ]+" | sed -n "$i"p) || continue
        TESTURLIP=$(stripIP $($(genfetchCMD "$testurl" noproxy "$IPV") 2>&1) "$IPV") || continue
        stripIP $"$TESTURLIP" "$IPV" | tail -1
        return 0
    done
    return 1
}
#func-getURLIP

getDEVIP() {
    IPV=$1
    if [ -z "$1" ]; then
        IPV="4"
    fi
    if [ -z "$DEV" ]; then
        echo "Interface is not specified."
        exit
    fi
    getdevtest=""
    TESTDEV=$(ip addr show "$DEV" 2>&1) || TESTDEV=$(ifconfig "$DEV" 2>&1) || getdevtest=1
    if [ -n "$getdevtest" ]; then
        echo "Check DEV ""$DEV"": failed."
        return 1
    fi
    TESTDEVIP=$(stripIP $"$TESTDEV" "$IPV") || getdevtest=1
    if [ -n "$getdevtest" ]; then
        echo "Get ""$DEV"" IPV""$IPV"" IP failed."
        return 1
    fi
    stripIP $"$TESTDEVIP" "$IPV" | head -1
}
#func-getDEVIP

ddns_check_URL() {
    ddns_URLIP=$(getURLIP $ddns_IPV)
    echo "URL IP : ""$ddns_URLIP"
    ddns_DNSIP=$(getDNSIP $ddns_fulldomain $ddns_IPV)
    echo "DNS IP : ""$ddns_DNSIP"
    if [ "$ddns_URLIP" = "$ddns_DNSIP" ]; then
        echo "URL IP SAME IN DNS,SKIP UPDATE."
        exit
    fi
    ddns_newIP=$ddns_URLIP
    getIP_"$ddns_provider"
    echo "API IP : ""$ddns_API_IP"
    if [ "$ddns_URLIP" = "$ddns_API_IP" ]; then
        echo "URL IP SAME IN API,SKIP UPDATE."
        exit
    fi
}
#func-ddns_check_URL

ddns_check_DEV() {
    echo "DEV : "$DEV
    ddns_DEVIP=$(getDEVIP $ddns_IPV)
    echo "DEV IP : ""$ddns_DEVIP"
    ddns_DNSIP=$(getDNSIP $ddns_fulldomain $ddns_IPV)
    echo "DNS IP : ""$ddns_DNSIP"
    if [ "$ddns_DEVIP" = "$ddns_DNSIP" ]; then
        echo "DEV IP SAME IN DNS,SKIP UPDATE."
        exit
    fi
    ddns_newIP=$ddns_DEVIP
    getIP_"$ddns_provider"
    echo "API IP : ""$ddns_API_IP"
    if [ "$ddns_DEVIP" = "$ddns_API_IP" ]; then
        echo "DEV IP SAME IN API,SKIP UPDATE."
        exit
    fi
}
#func-ddns_check_DEV

ddns_result_print() {
    try_en=$(echo -en 1 2>&1)
    if echo $try_en | grep -q "en"; then
        echo "$ddns_result"
    else
        ddns_result=$(echo -e "$ddns_result")
        echo -e "$ddns_result"
    fi
}
#func-ddns_result_print

check_ddns_newIP() {
    if [ -z "$ddns_newIP" ]; then
        echo "Error:Failed to get new dynamic IP values."
        exit
    fi
}
#func-check_ddns_newIP

push_ntfy() {
    if echo $ddns_ntfy_url | grep -Eoq "http"; then
        postData="$ddns_fulldomain"":""$ddns_newIP"
        push_ntfy_code=$($(genfetchCMD $ddns_ntfy_url useProxy))
        postData=""
        if echo $push_ntfy_code | grep -q "message"; then
            echo "Ntfy push OK."
        else
            echo "Ntfy push Failed."$push_ntfy_code
        fi
    fi
}
#func-push_ntfy

push_bark() {
    if echo $ddns_bark_url | grep -Eoq "http"; then
        push_bark_code=$($(genfetchCMD $ddns_bark_url/$ddns_fulldomain/$ddns_newIP useProxy))
        if echo $push_bark_code | grep -q "success"; then
            echo "Bark push OK."
        else
            echo "Bark push Failed."
        fi
    fi
}
#func-push_bark

push_sct() {
    if echo $ddns_sct_url | grep -Eoq "http"; then
        push_sct_code=$($(genfetchCMD "$ddns_sct_url""?title=""$ddns_newIP""-""$ddns_fulldomain""&desp=""$filename"":""$ddns_newIP" useProxy))
        if echo $push_sct_code | grep -q "SUCCESS"; then
            echo "Sct push OK."
        else
            echo "Sct push Failed."$push_sct_code
        fi
    fi
}
#func-push_sct

push_pushplus() {
    if echo $ddns_pushplus_url | grep -Eoq "http"; then
        push_pushplus_code=$($(genfetchCMD "$ddns_pushplus_url""&title=""$ddns_newIP""-""$ddns_fulldomain""&content=""$filename"":""$ddns_newIP" useProxy))
        if echo $push_pushplus_code | grep -q "200"; then
            echo "pushplus push OK."
        else
            echo "pushplus push Failed."$push_pushplus_code
        fi
    fi
}
#func-push_pushplus

gen_ddns_script() {
    gen_stage=$1
    if [ "$gen_stage" = "init" ]; then
        ddns_fulldomain=$2
        if echo $ddns_fulldomain | grep -q "@"; then
            ddns_fulldomain=$(echo $ddns_fulldomain | sed 's/@.//g')
        fi
        ddns_script_filename="$ddns_fulldomain"@"$ddns_provider""_IPV""$ddns_IPV"
        if [ "$ddns_IPmode" = "2" ]; then
            ddns_script_filename=$ddns_script_filename"_"$DEV".sh"
            testhotplug=$(ls /etc/hotplug.d/iface 2>&1)
            if [ "$?" = "0" ]; then
                echo "Detected hotplug support, generate script in /etc/hotplug.d/iface ?"
                echo "[1] No."
                echo "[2] Move to /etc/hotplug.d/iface"
                read -p "Your choice [1]:" hotplug
                if [ "$hotplug" = "2" ]; then
                    ddns_script_filename="/etc/hotplug.d/iface/""$ddns_script_filename"
                fi
            fi
        else
            ddns_script_filename=$ddns_script_filename"_URL.sh"
        fi
        echo "#!/bin/sh" >$ddns_script_filename
        echo "filename=\"""$ddns_script_filename""\"" >>$ddns_script_filename
        export_func Universal >>$ddns_script_filename
        export_func DDNSINIT >>$ddns_script_filename
        echo "ddns_provider=\"""$ddns_provider""\"" >>$ddns_script_filename
        echo "ddns_fulldomain=\"""$ddns_fulldomain""\"" >>$ddns_script_filename
        echo "ddns_IPV=\"""$ddns_IPV""\"" >>$ddns_script_filename
        echo "ddns_IPVType=\"""$ddns_IPVType""\"" >>$ddns_script_filename
        echo "ddns_main_domain=\"""$ddns_main_domain""\"" >>$ddns_script_filename
        echo "ddns_record_domain=\"""$ddns_record_domain""\"" >>$ddns_script_filename

        if [ "$ddns_IPmode" = "2" ]; then
            echo "DEV=""$DEV" >>$ddns_script_filename
        fi
        return 0
    fi
    if [ "$gen_stage" = "comp" ]; then
        export_func stripIP >>$ddns_script_filename
        export_func pingDNS >>$ddns_script_filename
        export_func nslookupDNS >>$ddns_script_filename
        export_func curlDNS >>$ddns_script_filename
        export_func wgetDNS >>$ddns_script_filename
        export_func getDNSIP >>$ddns_script_filename
        export_func genfetchCMD >>$ddns_script_filename
        export_func "fetch_""$ddns_provider" >>$ddns_script_filename
        export_func "getIP_""$ddns_provider" >>$ddns_script_filename
        if [ "$ddns_IPmode" = "2" ]; then
            export_func getDEVIP >>$ddns_script_filename
            export_func ddns_check_DEV >>$ddns_script_filename
            echo "ddns_check_DEV" >>$ddns_script_filename
        else
            export_func getURLIP >>$ddns_script_filename
            export_func ddns_check_URL >>$ddns_script_filename
            echo "ddns_check_URL" >>$ddns_script_filename
        fi
        export_func "ddns_update_""$ddns_provider" >>$ddns_script_filename
        export_func check_ddns_newIP >>$ddns_script_filename
        echo "check_ddns_newIP" >>$ddns_script_filename
        echo "echo Trying to update: \"\$ddns_fulldomain\"\" -> \"\"\$ddns_newIP\"" >>$ddns_script_filename
        echo "ddns_update_""$ddns_provider" >>$ddns_script_filename
        export_func "ddns_result_print" >>$ddns_script_filename
        echo "ddns_result_print" >>$ddns_script_filename
        export_func "push_ntfy" >>$ddns_script_filename
        echo "push_ntfy" >>$ddns_script_filename
        export_func "push_bark" >>$ddns_script_filename
        echo "push_bark" >>$ddns_script_filename
        export_func "push_sct" >>$ddns_script_filename
        echo "push_sct" >>$ddns_script_filename
        export_func "push_pushplus" >>$ddns_script_filename
        echo "push_pushplus" >>$ddns_script_filename
    fi
    echo "DDNS script generation completed!"
    if [ "$hotplug" = "2" ]; then
        echo $ddns_script_filename":"
    else
        echo $(pwd)"/"$ddns_script_filename":"
    fi
    chmod +x $ddns_script_filename
    ls -lh $ddns_script_filename
}

check_method() {
    curlVer=$(curl -V 2>&1) || fetchwget=$(wget -V 2>&1) || echo "[Warn] Cannot find curl or GUN wget.Your DNS provider need PUT method."
}

api_help() {
    echo "[help] "$1
}

menu_domain() {
    menu_count=$(echo $ddns_main_domain_list | grep -Eo "$DOMAINREX" | grep -c "")
    if [ "$menu_count" = "0" ]; then
        echo "No domain name found for your account!"
        exit
    fi
    if [ "$menu_count" != "1" ]; then
        i=0
        while [ $i -ne $menu_count ]; do
            i=$(($i + 1))
            echo "[""$i""]" $(echo "$ddns_main_domain_list" | grep -Eo "$DOMAINREX" | sed -n "$i"p)
        done
        read -p "Select your domain name[1]:" ddns_main_domain
    fi
    if [ -z "$ddns_main_domain" ]; then
        ddns_main_domain=1
    fi
    ddns_main_domain_index=$ddns_main_domain
    ddns_main_domain=$(echo $ddns_main_domain_list | grep -Eo "$DOMAINREX" | sed -n "$ddns_main_domain"p)
    if [ -z "$ddns_main_domain" ]; then
        echo "Error domain:ddns_main_domain"
        exit
    fi
    echo "Domain: ""$ddns_main_domain"
}

menu_subdomain() {
    echo "IPV"$ddns_IPV" sub domain list:"
    echo "[0] Add a new subdomain name"
    ddns_subdomain_count=$(echo "$ddns_subdomain_list_name" | grep -Eo '[^ ]+' | grep -c "")
    i=0
    while [ $i -ne $ddns_subdomain_count ]; do
        i=$(($i + 1))
        echo "["$i"]" "$(echo "$ddns_subdomain_list_name" | grep -Eo '[^"]+' | sed -n "$i"p)" "$ddns_IPVType" "$(echo $ddns_subdomain_list_value | grep -Eo '[^ ]+' | sed -n "$i"p)"
    done
    read -p "Select your IPV"$ddns_IPV" subdomain name[0]:" ddns_record_domain
    if [ -z "$ddns_record_domain" ]; then
        ddns_record_domain=0
    fi
    if echo $ddns_record_domain | grep -vEo "^[0-9]+$"; then
        echo "Error domain:ddns_record_domain"
        exit
    fi
    if [ "$ddns_record_domain" = "0" ]; then
        read -p "Create New: Enter sub domain [ Like ddns ]:" ddns_newsubdomain
        if echo $ddns_newsubdomain".""$ddns_main_domain" | grep -Eqv "$DOMAINREX"; then
            echo "Error domain:ddns_newsubdomain"
            exit
        fi
        if [ "$ddns_IPV" = "6" ]; then
            new_initIP=$(getURLIP $ddns_IPV) || new_initIP="2a09::"
        else
            new_initIP=$(getURLIP $ddns_IPV) || new_initIP="1.1.1.1"
        fi
        addsub_"$ddns_provider"
    else
        ddns_record_domain_index=$ddns_record_domain
        ddns_not_add_sub="1"
        ddns_record_domain="$(echo "$ddns_subdomain_list_name" | grep -Eo '[^"]+' | sed -n "$ddns_record_domain"p)"
    fi
}

showDEV() {
    IPV=$1
    if [ -z "$1" ]; then
        IPV="4"
    fi
    echo "How to get your new IP ?"
    echo "[1]From IP-Check URL"
    echo "[2]From Interface"
    read -p "Your choice [1]:" ddns_IPmode
    if [ "$ddns_IPmode" = "2" ]; then
        testshowdev=$(ip -"$IPV" addr show 2>&1)
        if [ "$?" = 0 ]; then
            devlist=$(ip -"$IPV" addr show | grep -Eo "^[0-9]+:[ ]+[-0-9a-zA-Z@.]+" | grep -Eo "[^: ]+$" | grep -Ev "^lo$")
        else
            testshowdev=$(ifconfig 2>&1)
            if [ "$?" = 0 ]; then
                devlist=$(ifconfig | grep -Eo "^[-0-9a-zA-Z@.]+" | grep -Ev "^lo$")
            else
                echo "List all interface: failed."
                exit
            fi
        fi
        countDEV=$(echo $devlist | grep -Eo "[-0-9a-zA-Z@.]+" | grep -c "")
        i=0
        while [ $i -ne $countDEV ]; do
            i=$(($i + 1))
            DEV=$(echo "$devlist" | grep -Eo "[-0-9a-zA-Z@.]+" | sed -n "$i"p)
            echo "["$i"]" "$DEV" $(getDEVIP $IPV)
        done
        i=$(($i + 1))
        echo "["$i"]" "Enter the network interface manually"
        read -p "Please select your interface [1]" selDEV
        if [ -z "$selDEV" ]; then
            selDEV=1
        fi
        if [ "$selDEV" = "$i" ]; then
            read -p "Enter interface [like eth0]:" selDEV
            DEV=$selDEV
        else
            DEV=$(echo "$devlist" | grep -Eo "[-0-9a-zA-Z@.]+" | sed -n "$selDEV"p)
            if [ -z "$DEV" ]; then
                echo "Error interface."
                exit
            fi
        fi
    fi
}

fetch_cloudflare() {
    $(genfetchCMD https://api.cloudflare.com/client/v4/zones/$1 useProxy) --header "Authorization: Bearer $cloudflare_API_Token" --header "Content-Type:application/json"
}
#func-fetch_cloudflare

getIP_cloudflare() {
    test_getIP_cloudflare=$(fetch_cloudflare $cloudflare_zoneid/dns_records/$cloudflare_record_id)
    ddns_API_IP="Get ""$ddns_fulldomain"" IPV""$ddns_IPV"" API IP Failed."
    if echo $test_getIP_cloudflare | grep -qEo 'success":true'; then
        test_API_IP=$(stripIP $(echo $test_getIP_cloudflare | grep -Eo '"type":"'$ddns_IPVType'","content":"[^"]+' | grep -Eo '[^"]+' | tail -1) $ddns_IPV) || return 1
        ddns_API_IP=$test_API_IP
    fi
}
#func-getIP_cloudflare

ddns_update_cloudflare() {
    postMethod="PUT"
    postData="{\"type\":\""$ddns_IPVType"\",\"name\":\""$ddns_record_domain"\",\"content\":\""$ddns_newIP"\",\"ttl\":1,\"proxiable\":true,\"proxied\":"$cloudflare_cdn"}"
    test_ddns_result=$(fetch_cloudflare $cloudflare_zoneid/dns_records/$cloudflare_record_id)
    postData=""
    if echo $test_ddns_result | grep -q 'success":true'; then
        ddns_result="Update OK: "$(echo $test_ddns_result | grep -Eo '"type":".+"proxied":[^,]+')
    else
        error_msg=$(echo $test_ddns_result | grep -Eo "errors[^]]+" | grep -Eo "\{.+")
        ddns_result="Update failed: "$error_msg
        ddns_newIP=$error_msg
    fi
}
#func-ddns_update_cloudflare

addsub_cloudflare() {
    postData="{\"type\":\"${ddns_IPVType}\",\"name\":\""$ddns_newsubdomain".""$ddns_main_domain""\",\"content\":\"$new_initIP\",\"ttl\":1,\"proxied\":false}"
    cloudflare_record_id=$(fetch_cloudflare $cloudflare_zoneid/dns_records | grep -Eo '"id":"[0-9a-z]{32}' | grep -Eo "[0-9a-z]{32}")
    postData=""
    if [ -z "$cloudflare_record_id" ]; then
        echo "Creat new subdomain failed."
        exit
    fi
    ddns_record_domain="$ddns_newsubdomain"".""$ddns_main_domain"
}

guide_cloudflare() {
    check_method
    api_help https://dash.cloudflare.com/profile/api-tokens
    read -p "Your cloudflare API TOKEN:" cloudflare_API_Token
    # Select main domain
    cloudflare_zone_list=$(fetch_cloudflare | grep -Eo '"id":"[0-9a-z]{32}","name":"'$DOMAINREX)
    ddns_main_domain_list=$(echo $cloudflare_zone_list | grep -Eo "$DOMAINREX")
    cloudflare_zoneid_list=$(echo $cloudflare_zone_list | grep -Eo '[0-9a-z]{32}')
    menu_domain
    cloudflare_zoneid=$(echo $cloudflare_zoneid_list | grep -Eo '[0-9a-z]{32}' | sed -n "$ddns_main_domain_index"p)
    # Select sub domain
    cloudflare_record_list=$(fetch_cloudflare $cloudflare_zoneid/dns_records | grep -Eo '"id":"[0-9a-z]{32}","zone_id":"'$cloudflare_zoneid'","zone_name":"'$ddns_main_domain'","name":"[^"]+","type":"'$ddns_IPVType'","content":"[^"]+')
    cloudflare_record_list_id=$(echo $cloudflare_record_list | grep -Eo '"id":"[a-z0-9]{32}' | grep -Eo '[a-z0-9]{32}')
    ddns_subdomain_list_name=$(echo $cloudflare_record_list | grep -Eo '"name":"[^"]+' | sed 's/"name":"//g' | grep -Eo '[^"]+')
    ddns_subdomain_list_value=$(echo $cloudflare_record_list | grep -Eo '"content":"[^"]+' | sed 's/"content":"//g')
    menu_subdomain
    if [ "$ddns_not_add_sub" = "1" ]; then
        cloudflare_record_id="$(echo "$cloudflare_record_list_id" | grep -Eo '[a-z0-9]{32}' | sed -n "$ddns_record_domain_index"p)"
    fi
    if [ -z "$cloudflare_record_id" ]; then
        echo "Error domain:cloudflare_record_id"
        exit
    fi
    echo "Turn on Cloudflare CDN proxied for "$ddns_record_domain"?"
    echo "[1]Disable"
    echo "[2]Enable"
    read -p "Your choice [1]:" cloudflare_cdn
    if [ "$cloudflare_cdn" = "2" ]; then
        cloudflare_cdn="true"
    else
        cloudflare_cdn="false"
    fi
    showDEV "$ddns_IPV"
    gen_ddns_script init "$ddns_record_domain"
    echo "cloudflare_API_Token=\"""$cloudflare_API_Token""\"" >>$ddns_script_filename
    echo "cloudflare_zoneid=\"""$cloudflare_zoneid""\"" >>$ddns_script_filename
    echo "cloudflare_record_id=\"""$cloudflare_record_id""\"" >>$ddns_script_filename
    echo "cloudflare_cdn=\"""$cloudflare_cdn""\"" >>$ddns_script_filename
    gen_ddns_script comp
}

fetch_dnspod() {
    postData='login_token='"$dnspod_login_token"'&format=json&'"$postData"
    $(genfetchCMD $dnspod_api_url/$1 useProxy)
    postData=""
}
#func-fetch_dnspod

ddns_update_dnspod() {
    if [ -z "$dnspod_record_lineid" ]; then
        dnspod_record_lineid=0
    fi
    if [ -z "$dnspod_record_line" ]; then
        dnspod_record_line="default"
    fi
    if [ "$dnspod_type" = "com" ]; then
        postData="domain_id=""$dnspod_domain_id""&record_id=""$dnspod_record_id""&record_line=""$dnspod_record_line""&value=""$ddns_newIP""&sub_domain=""$ddns_record_domain"
    else
        postData="domain_id=""$dnspod_domain_id""&record_id=""$dnspod_record_id""&record_line_id=""$dnspod_record_lineid""&value=""$ddns_newIP""&sub_domain=""$ddns_record_domain"
    fi
    test_ddns_result=$(fetch_dnspod Record.Ddns)
    postData=""
    if echo $test_ddns_result | grep -q 'code":"1"'; then
        ddns_result="Update OK: "$(echo $test_ddns_result | grep -Eo '"record":\{[^}]+\}')
    else
        error_msg=$(echo $test_ddns_result | grep -Eo '"message":"[^"]+' | grep -Eo '[^"]+' | tail -1)
        error_code=$(echo $test_ddns_result | grep -Eo '"code":"[0-9]+"')
        ddns_result="Update failed: ""$error_code"" : ""$error_msg"
        ddns_newIP="$error_code"":""$error_msg"
    fi
}
#func-ddns_update_dnspod

getIP_dnspod() {
    postData="domain_id=""$dnspod_domain_id""&record_id=""$dnspod_record_id"
    test_getIP_dnspod=$(fetch_dnspod Record.Info)
    postData=""
    ddns_API_IP="Get ""$ddns_fulldomain"" IPV""$ddns_IPV"" API IP Failed."
    if echo $test_getIP_dnspod | grep -qEo '"code":"1"'; then
        test_API_IP=$(stripIP $(echo $test_getIP_dnspod | grep -Eo '"value":"[^"]+' | grep -Eo '[^"]+' | tail -1) $ddns_IPV) || return 1
        ddns_API_IP=$test_API_IP
    fi
}
#func-getIP_dnspod

addsub_dnspod() {
    if [ "$dnspod_type" = "com" ]; then
        postData="domain_id=""$dnspod_domain_id""&sub_domain=""$ddns_newsubdomain""&record_type=""$ddns_IPVType""&record_line=default&value=""$new_initIP"
    else
        postData="domain_id=""$dnspod_domain_id""&sub_domain=""$ddns_newsubdomain""&record_type=""$ddns_IPVType""&record_line_id=0&value=""$new_initIP"
    fi
    dnspod_record_id=$(fetch_dnspod Record.Create | grep -Eo '"record":\{"id":"''[0-9]+' | sed 's/"record":{"id":"//g')
    postData=""
    if [ -z "$dnspod_record_id" ]; then
        echo "Creat new subdomain failed."
        exit
    fi
    if [ "$dnspod_type" = "com" ]; then
        dnspod_record_line="default"
    else
        dnspod_record_line="默认"
    fi
}

guide_dnspod() {
    echo "Which dnspod do you use?"
    echo "[1] www.dnspod.cn"
    echo "[2] www.dnspod.com"
    read -p "Your choice [1]:" dnspod_type
    if [ "$dnspod_type" = "2" ]; then
        dnspod_type="com"
    else
        dnspod_type="cn"
    fi
    if [ "$dnspod_type" = "com" ]; then
        dnspod_api_url="https://api.dnspod.com"
        api_help https://console.dnspod.com/account/token
    else
        dnspod_api_url="https://dnsapi.cn"
        api_help https://docs.dnspod.cn/account/dnspod-token/
    fi
    read -p "Your dnspod.""$dnspod_type"" API ID:" dnspod_API_ID
    read -p "Your dnspod.""$dnspod_type"" API Token:" dnspod_API_Token
    dnspod_login_token="$dnspod_API_ID"",""$dnspod_API_Token"
    # Select main domain
    dnspod_list=$(fetch_dnspod Domain.List)
    dnspod_list_id=$(echo $dnspod_list | grep -Eo '"id":[0-9]+' | grep -Eo "[0-9]+")
    ddns_main_domain_list=$(echo $dnspod_list | grep -Eo '"name":"'$DOMAINREX | sed 's/"name":"//g')
    menu_domain
    dnspod_domain_id=$(echo $dnspod_list_id | grep -Eo "[0-9]+" | sed -n "$ddns_main_domain_index"p)
    # Select sub domain
    postData="domain_id=""$dnspod_domain_id"
    dnspod_record_list=$(fetch_dnspod Record.List | grep -Eo '"id":"[0-9]+","ttl"[^}]+"type":"'$ddns_IPVType'"')
    postData=""
    dnspod_record_lineid_list=$(echo $dnspod_record_list | grep -Eo '"line_id":"[0-9]+' | grep -Eo '[0-9]+')
    dnspod_record_id_list=$(echo $dnspod_record_list | grep -Eo '"id":"[0-9]+' | grep -Eo '[0-9]+')
    dnspod_record_line_list=$(echo $dnspod_record_list | grep -Eo '"line":"[^"]+' | sed 's/"line":"//g')
    ddns_subdomain_list_name=$(echo $dnspod_record_list | grep -Eo '"name":"[^"]+' | sed 's/"name":"//g')
    ddns_subdomain_list_value=$(echo $dnspod_record_list | grep -Eo '"value":"[^"]+' | sed 's/"value":"//g')
    menu_subdomain
    if [ "$ddns_not_add_sub" = "1" ]; then
        dnspod_record_id=$(echo "$dnspod_record_id_list" | grep -Eo '[0-9]+' | sed -n "$ddns_record_domain_index"p)
        dnspod_record_lineid=$(echo $dnspod_record_lineid_list | grep -Eo '[=0-9]+' | sed -n "$ddns_record_domain_index"p)
        dnspod_record_line=$(echo $dnspod_record_line_list | grep -Eo '[^ ]+' | sed -n "$ddns_record_domain_index"p)
    fi
    if [ "$dnspod_record_line" = "\u9ed8\u8ba4" ]; then
        dnspod_record_line="默认"
    fi
    if [ -z "$dnspod_record_id" ]; then
        echo "Error domain:dnspod_record_id"
        exit
    fi
    showDEV "$ddns_IPV"
    gen_ddns_script init "$ddns_record_domain"".""$ddns_main_domain"
    echo "dnspod_login_token=\"""$dnspod_login_token""\"" >>$ddns_script_filename
    echo "dnspod_domain_id=\"""$dnspod_domain_id""\"" >>$ddns_script_filename
    echo "dnspod_record_id=\"""$dnspod_record_id""\"" >>$ddns_script_filename
    echo "dnspod_record_line=\"""$dnspod_record_line""\"" >>$ddns_script_filename
    echo "dnspod_record_lineid=\"""$dnspod_record_lineid""\"" >>$ddns_script_filename
    echo "dnspod_type=\"""$dnspod_type""\"" >>$ddns_script_filename
    echo "dnspod_api_url=\"""$dnspod_api_url""\"" >>$ddns_script_filename
    gen_ddns_script comp
}

fetch_godaddy() {
    $(genfetchCMD https://api.godaddy.com/v1/domains/$1 useProxy) --header "Authorization: sso-key $godaddy_ssokey" --header "Content-Type:application/json"
}
#func-fetch_godaddy

ddns_update_godaddy() {
    postMethod="PUT"
    postData="[{\"data\":\"$ddns_newIP\",\"name\":\"$ddns_record_domain\",\"port\":65535,\"priority\":0,\"protocol\":\"string\",\"service\":\"string\",\"ttl\":600,\"type\":\"$ddns_IPVType\",\"weight\":0}]"
    test_ddns_result=$(fetch_godaddy $ddns_main_domain/records/$ddns_IPVType/$ddns_record_domain --header "Content-Type:application/json")
    postData=""
    if echo $test_ddns_result | grep -q '"code"'; then
        error_msg=$(echo $test_ddns_result | grep -Eo '"message":"[^}]+"' | head -1)
        ddns_result="Update failed: "$error_msg
        ddns_newIP=$error_msg
    else
        ddns_result="Update OK."$test_ddns_result
    fi
}
#func-ddns_update_godaddy

getIP_godaddy() {
    test_getIP_godaddy=$(fetch_godaddy $ddns_main_domain/records/$ddns_IPVType/$ddns_record_domain)
    ddns_API_IP="Get ""$ddns_fulldomain"" IPV""$ddns_IPV"" API IP Failed."
    if echo $test_getIP_godaddy | grep -qEo '"data":"'; then
        test_API_IP=$(stripIP $(echo $test_getIP_godaddy | grep -Eo '"data":"[^"]+' | grep -Eo '[^"]+' | tail -1) $ddns_IPV) || return 1
        ddns_API_IP=$test_API_IP
    fi
}
#func-getIP_godaddy

addsub_godaddy() {
    postMethod="PUT"
    postData="[{\"data\":\"$new_initIP\",\"name\":\"$ddns_newsubdomain\",\"port\":65535,\"priority\":0,\"protocol\":\"string\",\"service\":\"string\",\"ttl\":600,\"type\":\"$ddns_IPVType\",\"weight\":0}]"
    addsub_godaddy_result=$(fetch_godaddy $ddns_main_domain/records/$ddns_IPVType/$ddns_newsubdomain --header "Content-Type:application/json")
    postData=""
    if echo $addsub_godaddy_result | grep -q '"code"'; then
        echo "Creat new subdomain failed.""$(echo $addsub_godaddy_result | grep -Eo '"message":"[^}]+"' | head -1)"
        exit
    else
        ddns_record_domain=$ddns_newsubdomain
    fi
}

guide_godaddy() {
    check_method
    echo "[help] https://developer.godaddy.com/keys"
    read -p "Production API Key:" godaddy_apikey
    read -p "Production API Secret" godaddy_secret
    godaddy_ssokey="$godaddy_apikey"":""$godaddy_secret"
    # Select main domain
    ddns_main_domain_list=$(fetch_godaddy | grep -Eo '"domain":"[^"]+' | sed 's/"domain":"//g')
    menu_domain
    # Select sub domain
    godaddy_record_list=$(fetch_godaddy $ddns_main_domain/records/$ddns_IPVType)
    ddns_subdomain_list_name=$(echo $godaddy_record_list | grep -Eo '"name":"[^"]+' | sed 's/"name":"//g' | grep -Eo '[^"]+')
    ddns_subdomain_list_value=$(echo $godaddy_record_list | grep -Eo '"data":"[^"]+' | sed 's/"data":"//g')
    menu_subdomain
    showDEV "$ddns_IPV"
    gen_ddns_script init "$ddns_record_domain"".""$ddns_main_domain"
    echo "godaddy_ssokey=\"""$godaddy_ssokey""\"" >>$ddns_script_filename
    gen_ddns_script comp
}

echo "========================================="
echo "# Universal embedded DDNS Shell Script #"
echo "# https://$versionUA"
echo "# https://blog.03k.org/post/ue-ddns.html"
echo "========================================="
dnsProvider="cloudflare,dnspod,godaddy"
countProvider=$(echo $dnsProvider | grep -Eo "[^,]+" | grep -c "")
i=0
while [ $i -ne $countProvider ]; do
    i=$(($i + 1))
    echo "["$i"]" $(echo "$dnsProvider" | grep -Eo "[^,]+" | sed -n "$i"p)
done
read -p "Select your DNS provider[1]:" selProvider
if echo "$selProvider" | grep -Evqo "^[1-9]{1}$"; then
    selProvider=1
fi
testguide=$(echo "$dnsProvider" | grep -Eo [^,]+ | sed -n "$selProvider"p | grep -Eo "[a-zA-Z]+") || exit
echo "$testguide" DDNS:
echo "[1] IPV4 DDNS"
echo "[2] IPV6 DDNS"
read -p "IPV4/IPV6 DDNS?[1]:" ddns_IPV
if [ "$ddns_IPV" = "2" ]; then
    ddns_IPV=6
    ddns_IPVType="AAAA"
else
    ddns_IPV=4
    ddns_IPVType="A"
fi
ddns_provider=$testguide
guide_$ddns_provider
