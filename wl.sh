#!/bin/bash
# mea 

function log()
{
	path="/opt/polycom/caxis/restrictedshell/utils/whitelist/whitelistLog"
	echo $1 >> $path 2>&1

}



function startWhitelist()
{
	iptables -I WHITELIST 1 -s $1 -j RETURN
	if [[ $? -eq 0 ]]
	then 
		echo success
	else
		echo fail
	fi
#	iptables -L -n > record
#	sed -n '/Chain WHITELIST/,/DROP/p' record > iplist
#	awk '{print $4}' iplist > list1
#	sed '1,2d' list1 > list2
#	sed '$d' list2 > list3
	
#	sort list3 | uniq -c | awk '{if($1>1) print $2}' > duplicate
#	ip=$(sed '1!d' duplicate)
#	if [ -n "$ip" ];
#	then
#		iptables -D WHITELIST 1		
#	fi
#	rm -rf record iplist list1 list2 list3 duplicate

	
}
function checkChain()
{
	iptables -L -n > record
	if  grep -qn "Chain ACCESS" record && grep -qn "Chain WHITELIST" record
	then
		return 0
	else
		return 1
	fi
}
function addChain()
{
	if checkChain 
	then							
		result=1
	else
		iptables -L -n > record
		if  grep -qn "Chain ACCESS" record 
		then
			iptables -N WHITELIST
			iptables -A WHITELIST -j DROP 
		elif  grep -qn "Chain WHITELIST" record
		then
			iptables -N ACCESS 
			iptables -A ACCESS -p tcp --dport 9445 -j WHITELIST
			iptables -A ACCESS -j RETURN
		else
			iptables -N WHITELIST
			iptables -A WHITELIST -j DROP
			iptables -N ACCESS
			iptables -A ACCESS -p tcp --dport 9445 -j WHITELIST
			iptables -A ACCESS -j RETURN
		fi
		rm -rf record
	fi
}




# === FUNCTION ===================================================
# Name		:addMea
#
# Descript	:addMea ip to whitelist
# === ======== ===================================================
function addMea ()
{
	addChain
	while :
	do
		echo "input IP. format: x.x.x.x or x.x.x.x/x. if done, input exit."
		read IP
		if [ "$IP" == "exit" ];then
			echo "ready to exit."
			return 0
		else
			if [[ $IP =~ ^([0-9]+\.){3}[0-9]+$ ]] || [[ $IP =~ ^([0-9]+\.){3}[0-9]+/[0-9]+$ ]]
			then
				startWhitelist $IP		
			else
				echo "Failed, invalid IP."
			fi
		fi
	done
	
}


# === FUNCTION ===================================================
# Name		:resetMea
#
#
# Descript	:stop whitelist
# === ======== ===================================================
function resetMea ()
{
	iptables -L -n > record
	n=$(grep -En '^ACCESS' record | grep -Eo '^[^:]+')
	count=0
	for i in $n
	do 
		iptables -D INPUT $((i-2))
		((count=count+1))
	done
	na=$(sed -n '/Chain ACCESS/,/RETURN/p' record | wc -l)
	if [ $na -gt 0 ];
	then
		delna=$((na-1))
		for (( i=1;i<$delna;i++ ))
		{
			iptables -D ACCESS 1
		}
		iptables -X ACCESS
	fi					
	nw=$(sed -n '/Chain WHITELIST/,/DROP/p' record | wc -l)
	if [ $nw -gt 0 ];
	then
		delnw=$((nw-1))
		for (( i=1;i<$delnw;i++ ))
		{
			iptables -D WHITELIST 1
		}
		iptables -X WHITELIST
	fi
	rm -rf record
}

# === FUNCTION ===================================================
# Name		:listMea
#
# Descript	:show all IPs of whitelist
# === ======== ===================================================
function listMea ()
{
	iptables -L -n > record
	if  grep -qn "^ACCESS*" record 
	then				
		echo "whitelist is open"
	else
		echo "whitelist is off"
	fi
	sed -n '/Chain WHITELIST/,/DROP/p' record > check	
	awk '{print $4}' check > ipadd
	sed '1,2d' ipadd > ipadd1
	sed '$d' ipadd1 > ipadd2
	echo "IP in whitelist:"
	cat ipadd2 | sort | uniq > allIP
	sed -e "s/$1//g" allIP > Print
	sed -e "s/$2//g" Print > Print2
	grep . Print2
	rm -rf record check ipadd ipadd1 ipadd2 allIP Print Print2
}



# === FUNCTION ===================================================
# Name		:delMea
#
# Descript	:delete specified ip from whitelist
# === ======== ===================================================
function delMea ()
{
	while :
	do
		echo "input IP. format: x.x.x.x or x.x.x.x/x . if done, input exit."
		read IP
		if [ "$IP" == "exit" ];then
			return 0
		fi		
		iptables -L -n > record			
		sed -n '/Chain WHITELIST/,/DROP/p' record > check	
		awk '{print $4}' check > ipadd
		sed '1,2d' ipadd > ipadd1
		sed '$d' ipadd1 > ipadd2		
		if  grep -qxn "$IP" ipadd2;
		then		
			if [ "$1" == "$IP" ] || [ "$2" == "$IP" ]	
			then
				log "try to delete server IP, failed"
				echo "this IP is server IP, fail to delete"
			else
				number=$(grep -nwF "$IP" check | grep -Eo '^[^:]+')
				echo "number is $number"
				count=0
				for i in $number
				do
               			        ((i=i-2-count))
      				        ((count=count+1))
              			        iptables -D WHITELIST $i
					if [[ $? -eq 0 ]]
					then 
						echo success
					else
						echo fail
					fi
				done
			fi			
		else
			echo "didnot find this IP in whitelist"
		fi		
		rm -rf record check ipadd ipadd1 ipadd2		
	done
	
}
function enableMea()
{
	addChain
	iptables -L -n > record
	if grep -qEn '^ACCESS' record
	then
		result=1
	else
		iptables -I INPUT 1 -j ACCESS
		if [[ $? -eq 0 ]]
		then 
			echo success
		else
			echo fail
		fi
	fi
	rm -rf record
}
function disableMea()
{
	iptables -L -n > record
	n1=$(grep -En '^Chain INPUT' record | grep -Eo '^[^:]+')
	n2=$(grep -En '^ACCESS' record | grep -Eo '^[^:]+')
	if [[ $n2 =~ ^[0-9]+[0-9]*$ ]]
	then
		if [ $n2 > $n1 ];
		then
			((n=n2-n1-1))
			if [ $n > 0 ];
			then
				iptables -D INPUT $n
				if [ $? == 1 ];
				then
					echo "fail"
				else
					echo "success"
				fi
			fi
		fi
	else
		echo "successed"
	fi
	rm -rf record

}

function checkServerIP()
{
	iptables -L -n > record
	sed -n '/Chain WHITELIST/,/DROP/p' record > check
	if grep -qwF "$1" check
	then
		return 0
	else
		return 1
	fi
}













#WSP 
#--- FUNCTION ---------------------------------------------
#
#Name		: checkWsp
#
#Descript	: get all IPs in whitelist
#
#--- -------- ---------------------------------------------
function checkWsp ()
{
	PGPASSWORD=Polycom@12#$ psql -U postgres postgres -c 'select * from ca_wsp.whitelistswitch' > status
	result=$(sed '3!d' status)
	if [ $result -eq 0  ]
	then
        echo "whitelist is off"
	else
        echo "whitelist is open"
	fi
	
	PGPASSWORD=Polycom@12#$	psql -U postgres postgres -c 'select * from ca_wsp.whitelistconfig' > allIP
	echo "IP in whitelist:"
	grep -oP '([1-9]|[1-9][0-9]|[1-9][0-9][0-9])\.\d+\.\d+\.\d+\/\d+' allIP
	
	rm -rf status allIP
}

#--- FUNCTION ---------------------------------------------
#
#Name		: addWsp 
#
#Descript	: add IP to whitelist 
#
#--- -------- ---------------------------------------------
function addWsp ()
{
	echo "input IP. format: x.x.x.x/x"
	read IP
	if [[ $IP =~ ^([0-9]+\.){3}[0-9]+/[0-9]+$ ]]
	then		
		PGPASSWORD=Polycom@12#$	psql -U postgres postgres -qc "insert into ca_wsp.whitelistconfig values('$IP')"
		if [[ $? -eq 0 ]]
		then 
			echo success
		else
			echo fail
		fi						
	else
		echo "invalid IP"
	fi
}


#--- FUNCTION ---------------------------------------------
#
#Name		: delWsp 
#
#Descript	: remove specified IP from whitelist 
#
#--- -------- ---------------------------------------------
function delWsp ()
{
	PGPASSWORD=Polycom@12#$	psql -U postgres postgres -c 'select * from ca_wsp.whitelistconfig' > content
	cat content | awk '{print $1}' | grep -E '^[0-9]+' > iplist
	
	count=$(cat iplist | wc -l) 

	echo "input IP. format: x.x.x.x/x"
	read IP
	
	if [[ $IP =~ ^([0-9]+\.){3}[0-9]+/[0-9]+$ ]]
	then 	
		if grep -qnx "$IP" iplist 
		then
			PGPASSWORD=Polycom@12#$	psql -U postgres postgres -qc "delete from ca_wsp.whitelistconfig where subnet like '%$IP%'"
			if [[ $? -eq 0 ]]
			then 
				echo success
			else
				echo fail
			fi
		else
			echo "did not find IP in whitelist."
		fi
	else
		echo "invalid ip"
	
	fi
	rm -rf content iplist 
		
		
}

#--- FUNCTION ---------------------------------------------
#
#Name		: enableWsp 
#
#Descript	: enable whitelist function 
#
#--- -------- ---------------------------------------------
function enableWsp()
{
	
	PGPASSWORD=Polycom@12#$ psql -U postgres postgres -qc "update ca_wsp.whitelistswitch set enableflag='1'"
	if [[ $? -eq 0 ]]
	then 
		echo success
	else
		echo fail
	fi
}
function disableWsp()
{
	PGPASSWORD=Polycom@12#$ psql -U postgres postgres -qc "update ca_wsp.whitelistswitch set enableflag='0'"
	if [[ $? -eq 0 ]]
	then 
		echo success
	else
		echo fail
	fi
}

#execute program :include check add list delete
if [ "$1" != "show" -a "$1" != "add" -a "$1" != "delete" -a "$1" != "enable" -a "$1" != "disable" -a "$1" != "reset" ];
then
	echo "usage:
	whitelist add 
	whitelist show
	whitelist delete
	whitelist enable
	whitelist disable
	"
	exit
fi




if [ -d "/opt/polycom/mea" ];
then
	if [ -f /opt/polycom/mea/system-utils/whitelist-rules/rules ] && [ ! -f /opt/polycom/mea/system-utils/whitelist-rules/flag ]; 
	then 
		iptables-restore < /opt/polycom/mea/system-utils/whitelist-rules/rules
		touch /opt/polycom/mea/system-utils/whitelist-rules/flag
#		sed 's/"//g' /opt/polycom/caxis/restrictedshell/utils/whitelist/rules > /opt/polycom/caxis/restrictedshell/utils/whitelist/RULES
#		sed 's/\\n/$/g' /opt/polycom/caxis/restrictedshell/utils/whitelist/RULES > /opt/polycom/caxis/restrictedshell/utils/whitelist/RULESCOPY
#		awk 'BEGIN{FS="$"}{for(i=1;i<NF;i++){print $i}}' /opt/polycom/caxis/restrictedshell/utils/whitelist/RULESCOPY > /opt/polycom/caxis/restrictedshell/utils/whitelist/ipta
#		iptables-restore < /opt/polycom/caxis/restrictedshell/utils/whitelist/ipta
#		rm -rf /opt/polycom/caxis/restrictedshell/utils/whitelist/rules /opt/polycom/caxis/restrictedshell/utils/whitelist/RULES /opt/polycom/caxis/restrictedshell/utils/whitelist/RULESCOPY /opt/polycom/caxis/restrictedshell/utils/whitelist/ipta
#		touch /opt/polycom/caxis/restrictedshell/utils/whitelist/flag

	fi
	#get server IP	
	serverHost=$(grep "external_secure" /opt/polycom/mea/settings.json | awk  '{print $2}' | awk 'BEGIN{FS="\""}{print $2}'| awk 'BEGIN{FS="//"}{print $2}')	
	serverIP=$(host $serverHost|awk '{print $4}')
	localhostIP="127.0.0.1"


	case $1 in
		add)
			addMea
			;;
		show)
			listMea $serverIP $localhostIP
			;;
		delete)
			delMea $serverIP $localhostIP
			;;
		enable)
			enableMea
			;;
		disable)
			disableMea
			;;
		reset)
			resetMea
			;;
		*)
			echo "invalid input"
			;;
	esac
	if  checkServerIP $serverIP 
	then 
		log "server IP $serverIP is in the whitelist"		
	else
		addChain
		iptables -I WHITELIST 1 -s $serverIP -j RETURN	
	fi
	
	if  checkServerIP $localhostIP 
	then 
		log "127.0.0.1 is in the whitelist"		
	else
		addChain
		iptables -I WHITELIST 1 -s $localhostIP -j RETURN	
	fi
	

	iptables-save > /opt/polycom/mea/system-utils/whitelist-rules/rules
	chmod a+rwx /opt/polycom/mea/system-utils/whitelist-rules/rules
	service iptables save > sis
	rm -rf sis
	
	
	
else
	case $1 in
		add)
			addWsp
			;;
		show)
			checkWsp
			;;
		delete)
			delWsp
			;;
		enable)
			enableWsp
			;;
		disable)
			disableWsp
			;;
		*)
			echo "invalid input"
			;;
	esac		
fi
