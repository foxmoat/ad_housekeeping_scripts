$globalAD = "global.com" #Domain DNSRoot of the Global domain

################################################
# FUNCTION WRITE OUTPUT TO SCREEN AND LOG FILE
################################################

function writeLog([string]$entry,[bool]$type = $true, [bool]$terminate = $false){

    $logFileName = "$(hostname).log"
    $logFilePath = "$env:TEMP" 
    $logFile = "$logFilePath\$logFileName"

    if(-not (test-path($logFile))){New-Item -Name $logFileName -Path $logFilePath -ItemType file}

    if (!$type){
        write-host "$(Get-Date -Format "MM-dd-yyyy_HH-mm-ss") ERROR: $entry"
        "$(Get-Date -Format "MM-dd-yyyy_HH-mm-ss") ERROR: $entry`n" >> $logFile
    }else{
        write-host "$(Get-Date -Format "MM-dd-yyyy_HH-mm-ss"): $entry" 
        "$(Get-Date -Format "MM-dd-yyyy_HH-mm-ss"): $entry`n" >> $logFile
    }

    if ($terminate){
        copyLog
        exit
    }
}

function copyLog(){
    if (Test-Path "\\10.94.230.99\questresourceupdatinglogs$\profiles"){
        copy $logFile "\\10.94.230.99\questresourceupdatinglogs$\profiles" -Force
    }else{
        writeLog "Unable to access remote log folder" $false
    }
}

################################################
# FUNCTION TO CONVERT THE ENDIANESS OF THE 
# OBTAINED GUID VALUE TO ENSURE LOOKUP ACCURACY 
# WITH QUEST MIGRATION TOOL
################################################

Function Convert-GUIDEndian ([guid] $ObjectGUID){

#Break up the GUID into its parts. UInt32-UInt16-UInt16-Byte[2]-Byte[6]
		$Guidparts = $Objectguid.Guid.Split('-')

#Part 1 = UInt32
		$part1 = [system.uint32]::Parse($Guidparts[0], [System.Globalization.NumberStyles]::HexNumber)
		$part1 = ([BitConverter]::GetBytes($part1))
		[array]::Reverse($part1)
		$part1 = [BitConverter]::ToInt32($part1, 0)

#Part 2 = UInt16
		$part2 = [system.uint16]::Parse($Guidparts[1], [System.Globalization.NumberStyles]::HexNumber)
		$part2 = ([BitConverter]::GetBytes($part2))
		[array]::Reverse($part2)
		$part2 = [BitConverter]::ToInt16($part2, 0)

#Part 3 = UInt16
		$part3 = [system.uint16]::Parse($Guidparts[2], [System.Globalization.NumberStyles]::HexNumber)
		$part3 = ([BitConverter]::GetBytes($part3))
		[array]::Reverse($part3)
		$part3 = [BitConverter]::ToInt16($part3, 0)

#Part 4 = Byte[8]
		$part4 = [system.uint64]::Parse($Guidparts[3]+$Guidparts[4], [System.Globalization.NumberStyles]::HexNumber)
		$part4 = ([BitConverter]::GetBytes($part4))
#Fix for that Intel cpus are Little Endian
		[array]::Reverse($part4)


#Build the new GUID and return it.		
		return (new-object system.guid ($part1, $part2, $part3, $part4)).guid.replace("-","").toupper()
}

################################################
# GENERATE HASH TABLE LOOKUP FOR ALL CHILD 
# DOMAINS WILL USE THE OBJECT SID VALUE OF THE  
# MEMBER OBJECTS TO PERFORM THE LOOKUP
################################################
writeLog "################################################"
writeLog "Start Execution for $(hostname)"
writeLog "################################################"

[Hashtable]$lookup = $null

try{
    $Root = [ADSI]"LDAP://RootDSE"
    $oForestConfig = $Root.Get("configurationNamingContext")
    $oSearchRoot = [ADSI]("LDAP://CN=Partitions," + $oForestConfig)
    $AdSearcher = [adsisearcher]"(&(objectcategory=crossref)(netbiosname=*))"
    $AdSearcher.SearchRoot = $oSearchRoot
    $domains = $AdSearcher.FindAll()
    foreach ($domain in $domains)
    {
        [string]$dnsroot = $domain.Properties.dnsroot
        $sid = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $(([ADSI]"LDAP://$($domain.properties.dnsroot)").objectsid), 0).value
        $lookup += New-Object PSObject -Property @{DNSRoot = $dnsroot;SID = $sid}|Group-Object -AsHashTable -AsString -Property sid
    
    }
}catch{
    writeLog "Unable to enumerate list of domains. Code failed with error:`n $($_.exception.message)" $false
    break
}

################################################
# ENUMERATE THE LIST OF PROFILELIST SIDS IN
# HKLM:\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\PROFILELIST\
################################################

try{

    $sids = (Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"| `
    ?{$_.PSChildName -match [regex]"S-1-5-21-\d+-\d+\-\d+\-\d+"} |select PSChildName).PSChildName

}catch{
    writeLog "Unable to enumerate local machine ProfileList. Code failed with error:`n $($_.exception.message)" $false
    break
}


foreach ($sid in $sids)
{
    $LSid = $sid.Substring("0", $sid.LastIndexOf("-"))

    if ($LSid -in $lookup.Values.sid)
    #sid entry maps to a valid domain in the forest, so perform query

    {
        ################################################
        # PERFORM QUERY USING THE OBJECTSID VALUE
        # TO PERFORM A LOOKUP OF THE DOMAIN HASH TABLE
        ################################################
        writeLog "`nSearching for $sid in domain $($lookup[$LSid].DNSRoot)" 

        $LSearcher = [adsisearcher]""
        $LSearcher.searchroot = [ADSI]"LDAP://$($lookup[$LSid].DNSRoot)"
        $LSearcher.Filter = "(&(objectcategory=user)(objectsid=$sid))"
        $LUsr = $LSearcher.FindOne()

        if ($LUsr){
            writeLog "Found $($LUsr.Properties.name) {$sid} in domain $($lookup[$LSid].DNSRoot)" 

            $LSid = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $($LUsr.properties.objectsid), 0).value
            $LGuid = ([system.guid]$($LUsr.properties.objectguid)).guid
            $PIM = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid").ProfileImagePath
        
            ################################################
            # PERFORM A SEARCH ON THE GLOBAL DOMAIN FOR 
            # EACH QUERIED OBJECT AND WRITE THE NECESSARY  
            # VALUES TO THE REGISTRY. (WHATIF FLGAS IN EFFECT)
            ################################################

            try{
                $GSearcher = [adsisearcher]""
                $GSearcher.searchroot = [ADSI]"LDAP://$globalAD"
                $GSearcher.Filter = "(&(objectcategory=user)(extensionattribute15=$(Convert-GUIDEndian $LGuid)))"
                $GUsr = $GSearcher.FindOne()
            }catch{
                writeLog "Unable to connect to $globalAD domain. Code failed with error:`n $($_.exception.message)" $false $true
                
            }
            if ($GUsr){
            

                $GSid = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $($GUsr.properties.objectsid), 0).value
                $GGuid = ([system.guid]$($GUsr.properties.objectguid)).guid

                try{
                    if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$GSid"))
                    {
                        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$GSid"  -ErrorAction Stop -ErrorVariable ev|Out-Null
                        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$GSid" -PropertyType "ExpandString" -Name "ProfileImagePath" -Value $PIM -ErrorAction Stop -ErrorVariable ev|Out-Null
                        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$GSid" -PropertyType "String" -Name "Guid" -Value "{$GGuid}" -ErrorAction Stop -ErrorVariable ev|Out-Null
                        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$GSid" -PropertyType "DWORD" -Name "Flags" -Value "0x00000000" -ErrorAction Stop -ErrorVariable ev|Out-Null
                        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$GSid" -PropertyType "DWORD" -Name "State" -Value "0x00000204"  -ErrorAction Stop -ErrorVariable ev|Out-Null
                        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$GSid" -PropertyType "DWORD" -Name "ProfileAttemptedProfileDownloadTimeLow" -Value "0x00000000" -ErrorAction Stop -ErrorVariable ev|Out-Null
                        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$GSid" -PropertyType "DWORD" -Name "ProfileAttemptedProfileDownloadTimeHigh" -Value "0x00000000" -ErrorAction Stop -ErrorVariable ev|Out-Null
                        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$GSid" -PropertyType "DWORD" -Name "ProfileLoadTimeLow" -Value "0x00000000" -ErrorAction Stop -ErrorVariable ev|Out-Null
                        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$GSid" -PropertyType "DWORD" -Name "ProfileLoadTimeHigh" -Value "0x00000000" -ErrorAction Stop -ErrorVariable ev|Out-Null
                        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$GSid" -PropertyType "DWORD" -Name "RefCount" -Value "0x00000003" -ErrorAction Stop -ErrorVariable ev|Out-Null
                        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$GSid" -PropertyType "Binary" -Name "Sid" -Value $($GUsr.properties.objectsid) -ErrorAction Stop -ErrorVariable ev|Out-Null
                        
                        writeLog "Registry values successfully written for HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$GSid" 
                    }else {
                        writeLog "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$GSid key already exists on this machine. No further action required" $false
                    }
                }catch{
                    writeLog "Unable to write to local machine ProfileList. Code failed with error:`n $($_.exception.message)" $false
                    
                }
            }
            else{
                writeLog "`tUser object with extensionattribute15 $(Convert-GUIDEndian $LGuid) not found in domain $globalAD." $false
            }

        }else{
            writeLog "`tUser object with SID $sid not found in domain $($lookup[$LSid].DNSRoot)." $false
        }

    }
    else
    {
        writeLog "Domain with SID: {$LSid} not found in forest" $false
    }
}

copyLog



