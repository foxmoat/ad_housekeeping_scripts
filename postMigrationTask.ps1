 param (
    [switch]$modify,
    [switch]$Frankfurt
     )

$AllUsers = @()
$migratedUsers = @()
$profilePathUsers = @()
$proxyAddressesUsers = @()

$sourceDomain = "UK.foxmoat.COM"
$destDomain = "GLOBAL.foxmoat.COM"
$sourcePath = "OU=Migrated Users,DC=uk,DC=foxmoat,DC=com"

if ($Frankfurt){
    $destPath = "OU=Users,OU=Frankfurt,OU=EMEA,OU=EUC,DC=global,DC=foxmoat,DC=com"
}else{
    $destPath = "OU=OU=London,OU=EMEA,OU=EUC,DC=global,DC=foxmoat,DC=com"
}


function writeLog([string]$entry,[bool]$yellow = $true){

    $logFileName = "postmigrationtask.log"
    $logFilePath = "c:\scripts\"
    $logFile = "c:\scripts\postmigrationtask.log"

    if(-not (test-path($logFile))){New-Item -Name $logFileName -Path $logFilePath -ItemType file}

    if ($yellow){
        write-host "$(Get-Date -Format "MM-dd-yyyy_HH-mm-ss"): $entry" -ForegroundColor Yellow
    }else{
        write-host "$(Get-Date -Format "MM-dd-yyyy_HH-mm-ss"): $entry" -ForegroundColor Green
    }

    "$(Get-Date -Format "MM-dd-yyyy_HH-mm-ss"): $entry`n" >> $logFile
}

function sendNotification{
    param([string]$body)
    
    $emailTo = "onedesknotification@foxmoat.com"
    $emailFrom = "postmigrationtask@foxmoat.com" 
    $subject="Post Migration Task Report"

     Send-MailMessage -From $emailFrom -To $emailTo `
    -Subject $subject `
    -SmtpServer intmail.foxmoat.com `
    -Body $body

}


function getAllUsers{
    ########################################################################################
    # This function returns a list of all migrated users in the GLOBAL Domain
    # The values returned are used by the following functions:
    # getProxyAddresses()
    ########################################################################################
    writelog "Retrieving all users..."

    Get-ADUser -server $destDomain -filter * -properties mail,department,userprincipalname,homedrive,distinguishedname `
    -SearchBase $destPath|?{($_.homedrive -like "E:") -and ($_.mail -ne $null) -and ($_.department -ne $null)}
}

function getMigratedUsers{
    ########################################################################################
    # This function returns a list of recently migrated users based on pre-specified filters
    # The values returned are used by the following functions:
    # updateHouseIdentifier()
    # forcePasswordChange()
    # updateLyncProfile()
    ########################################################################################
    writelog "Retrieving migrated users..."

    Get-ADUser -server $destDomain -filter * -SearchBase $destPath `
    -properties houseIdentifier,mail,department,userprincipalname,distinguishedname,'msRTCSIP-PrimaryUserAddress',carlicense,homeDirectory,proxyaddresses `
    |?{!($_.houseIdentifier -like "foxmoat") -and ($_.mail -ne $null) -and ($_.department -ne $null)}
}

function getProfilePath{
    ########################################################################################
    # This function returns a list of migrated Users with entries in their 
    # profilePath AD attributes
    # User array returned is used by the clearProfilePath() function
    ########################################################################################
    writelog "Retrieving Profile Path information..."

    Get-ADUser -server $destDomain -filter * -properties mail,department,homedrive,distinguishedname,profilePath `
    -SearchBase $destPath|?{($_.homedrive -like "E:") -and ($_.mail -ne $null) -and ($_.department -ne $null) -and !($_.profilePath -eq $null)}
}

function getProxyAddresses{
    ########################################################################################
    # This function returns a list of migrated Users with entries in their 
    # source Domain proxyAddresses AD attributes
    # User array returned is used by the clearProxyAddresses() function
    ########################################################################################
    writelog "Retrieving proxyAddresses value..."

    # = Get-ADUser -server $sourceDomain -SearchBase $sourcePath -filter * -Properties proxyAddresses
    $l = @()
    #

    foreach ($usr in $migratedUsers)
    { 
        $ukusr = Get-ADUser -server $sourceDomain -filter {samaccountname -eq $usr.samaccountname} -Properties proxyAddresses
        if (($ukusr|select -ExpandProperty proxyAddresses).count -ge 1)
        {
            $l += $ukusr
        }            
    }
    
    $l
}

function getExistingGroups{
    ########################################################################################
    # This function returns a list of all migrated Users with existing group 
    # memberships in their source Domain accounts
    # User array returned is used by the clearGroupMembership() function
    ########################################################################################
    writelog "Retrieving existing group memberships..."
    
    $output = @()     

    foreach ($usr in $migratedUsers)
    { 
        $ukusr = Get-ADUser -server $sourceDomain -filter {samaccountname -like $usr.samaccountname} -Properties Enabled

        $isDirty = $false
        $missingGrp = @()

        $grps = get-ADPrincipalGroupMembership $ukusr -server $sourceDomain -Credential $cred

        if ($grps.count -ge "2")
        {   
            $gbusr = [ADSI]"LDAP://$destDomain/$((get-aduser -server $destDomain -filter {samaccountname -like $ukusr.samaccountname} `
            -properties distinguishedname|select distinguishedname).distinguishedname)"
        
            foreach ($l in $grps){
                $grpPath = "LDAP://$destDomain/$l"
                $adsigrp = New-Object System.DirectoryServices.DirectoryEntry($grpPath,$username,$password)
                
                $domain = $([ADSI]"LDAP://$($([string]$l).substring($([string]$l).indexof("DC=")))").dc
            
                if ($l.name -ne "Domain Users"){

                    if (!($adsigrp.IsMember($gbusr.ADsPath) -eq $True)){
                        $isDirty = $true


                        $Obj = New-Object -TypeName PsObject
		                $Obj | Add-Member -MemberType NoteProperty -Name Domain -Value $domain
		                $Obj | Add-Member -membertype NoteProperty -name Name -value $adsigrp.Name
                        
                        $missingGrp += $obj
                    }
                }
            }

            if ($isDirty){
                $Obj = New-Object -TypeName PsObject
		        $Obj | Add-Member -MemberType NoteProperty -Name User -Value $ukusr
		        $Obj | Add-Member -membertype NoteProperty -name Group -value $missingGrp
        

                $output += $Obj 
            }
        }            
    }

    $output
}


function updateHouseIdentifier{
    #########################################################################################
    # This function adds the string foxmoat to migrated users' houseIdentifier AD attribute and
    # disables the ActiveSync by setting the msExchOmaAdminWirelessEnable attribute to BIT
    # value 0x011 (3) uses the getMigratedUsers function to retrieve the list of users to set
    #########################################################################################

    echo ""
    echo ""
    writelog "Updating houseIdentifier Attributes..."
    
    foreach ($usr in $migratedUsers)
    {
        $usr|set-aduser -Add @{houseIdentifier="foxmoat"}
        $usr|set-aduser -Replace @{msExchOmaAdminWirelessEnable = 7}        
        Get-ADGroup -id "Global_L_DynamicCachedmodePoC_Users"|Add-ADGroupMember -Members $usr
        writelog "`tUpdated houseIdentifier Attributes for $($usr.name)" -yellow $false
    }
 }

function forcePasswordChange{
    #This function sets the flag to force password change for migrated users
    #uses the getMigratedUsers function to retrieve the list of users to set
    
    echo ""
    echo ""
    writelog "Setting Password Change At Next Logon..." 
    
     
    foreach ($usr in $migratedUsers)
    {
        try{        
            if (($usr|set-aduser -ChangePasswordAtLogon $true -ErrorAction Stop) -eq $null){

                writelog "`tSet password attribute for $($usr.name)" -yellow $false
            }
        }catch [Microsoft.ActiveDirectory.Management.ADException]{
        
            writelog "`tPassword cannot be set for $($usr.Name). Check that Password never expires is not set"

        }catch [System.Exception]{
            
            writelog "`tAn error occured. Please check the `$error variable for more information"
        }
    }    
}

function moveSourceAccounts{
    #uses the getMigratedUsers function to retrieve the list of users to set

    echo ""
    echo ""
    writelog "Moving UK User Objects..."
    
    foreach ($str in $migratedUsers)
    {
        $usr = $str.samaccountname


        $tmp = get-aduser -server $sourceDomain -Filter {samaccountname -like $usr} -Properties manager,carlicense
        if ($tmp.carlicense.count -gt 1){
            writeLog "`tCarLicense attribute is not empty for $($tmp.name)" -yellow $true
        }else{
            $tmp|Set-ADUser -Clear carlicense
            $tmp|Set-ADUser -Add @{carlicense = $(([ADSI]([ADSI]"LDAP://$($tmp.distinguishedname)").parent).distinguishedname)} 
        }
        
        $tmp|Set-ADUser -Clear manager -Server $sourceDomain
        $tmp|move-adobject -targetpath $sourcePath -Server $sourceDomain

        writelog "`tMoved foxmoat\$usr to $sourcePath" -yellow $false
    }
    
}



function updateLyncProfile{
    $lyncSession = New-PSSession -ConnectionUri "https://lyncpool.foxmoat.com/ocspowershell" -Credential $cred
    Import-PSSession $lyncSession -AllowClobber |Out-Null

    #This function checks all migrated Users', disables the associated UK Lync accounts
    #if still enabled and enables the GLOBAL domain Lync accounts if not yet enabled

    #uses the getMigratedUsers function to retrieve the list of users to set
    
    echo ""
    echo ""
    writelog "Updating Lync Profiles..." 
        foreach ($str in $migratedUsers)
    { 
        $usr = $str.samaccountname
        try{        
           
            if ($(Get-CsAdUser -OU $sourcePath -DomainController $sourceDomain |?{$_.samaccountname -eq $usr}|select enabled).enabled -eq $true)
            {
                Get-CsAdUser -OU $sourcePath -DomainController $sourceDomain |?{$_.samaccountname -eq $usr}| Disable-CsUser            
                writelog "`tDisabled Lync account for: foxmoat\$usr" -yellow $false
            }
        }catch [Microsoft.Rtc.Management.AD.ManagementException]{
            
            writelog "`tCheck that user exist in source domain"

        }catch [Exception]{
            
            writelog "Error type: $_.Exception.GetType().FullName"

            writelog "Message: $_.Exception.Message"
        }
    }

    Start-Sleep -s 60
    echo ""

    #############################################
    # Enable LYNC account for each user.
    # Check to make sure source domain account
    # is disabled, otherwise pause for 20 seconds
    #############################################

    foreach ($str in $migratedUsers)
    { 
        $usr = $str.samaccountname
        $count = 1
        try{  
            while (($(Get-CsAdUser -OU $sourcePath -DomainController $sourceDomain |?{$_.samaccountname -eq $usr}|select enabled).enabled -eq $true) -and ($count -lt 2)){ 
            
                writelog "`tIt appears foxmoat\$usr is still enabled for Lync. Pausing for 20 seconds..." -yellow $true
                $count++
                Start-Sleep -Seconds 20
            }
            
            if ((!$(Get-CsAdUser -OU $destPath -DomainController $destDomain |?{$_.samaccountname -eq $usr}|select enabled).enabled -eq $true) `
             -and (!($(Get-CsAdUser -OU $sourcePath -DomainController $sourceDomain |?{$_.samaccountname -eq $usr}|select enabled).enabled -eq $true)))
            {                        
                Get-CsAdUser -OU $destPath -DomainController $destDomain |?{$_.samaccountname -eq $usr} `
                |Enable-CsUser -RegistrarPool "lyncpool.foxmoat.com" -SipAddressType "EmailAddress" -SipDomain "foxmoat.com" -DomainController $destDomain -ErrorAction Stop
                writelog "`tEnabled Lync account for: GLOBAL\$usr" -yellow $false         
                  
            }else{writelog "`tThere was a problem setting up Lync account for: GLOBAL\$usr`n"}

        }catch{writelog "`tError setting up Lync account for: GLOBAL\$usr`n"}

    }

    Start-Sleep -s 10
    echo ""

    #############################################
    # Configure LYNC and for default setting
    # Audio/Video Disabled
    #############################################

    foreach ($str in $migratedUsers)
    { 
        $usr = $str.samaccountname
        $count = 1
        
        try {  
            while (($(Get-CsAdUser -OU $destPath -DomainController $destDomain |?{$_.samaccountname -eq $usr}|select enabled).enabled -ne $true) -and ($count -lt 3)){ 
            
                writelog "`tUser GLOBAL\$usr not yet enabled for Lync. Pausing for 10 seconds..." -yellow $true
                $count++
                Start-Sleep -Seconds 10
            }
            
            if ($(Get-CsAdUser -OU $destPath -DomainController $destDomain |?{$_.samaccountname -eq $usr}|select enabled).enabled -eq $true)
            {                        
                Get-CsUser -OU $destPath -DomainController $destDomain |?{$_.samaccountname -eq $usr}|set-csuser `
                        –AudioVideoDisabled $True –RemoteCallControlTelephonyEnabled $False –EnterpriseVoiceEnabled $False -DomainController $destDomain -ErrorAction Stop
            
                writelog "`tConfigured Lync account for: GLOBAL\$usr" -yellow $false           
            }else{writelog "`tCheck that GLOBAL\$usr is setup correctly for Lync.`n"}

        }catch{writelog "`tThere was an error configuring Lync for GLOBAL\$usr`n"}
    }
    Remove-PSSession $lyncSession
}

function clearProfilePath{
    #This function clears the profilePath AD attributes
    #Uses the getProfilePath function to retrieve the list of users to set
    
    echo ""
    echo ""
    writelog "Removing ProfilePath attributes..." 
    
    foreach ($usr in $profilePathUsers)
    {
        $usr|set-aduser -Clear profilePath
        writelog "`tRemoved ProfilePath attribute for $($usr.name)" -yellow $false
    }
}

function clearProxyAddresses{
    #This function checks that all migrated Users' source domain accounts no longer
    #have entries in their proxyAddresses AD attributes

    #uses the getUKProxyAddresses function to retrieve the list of users to set
    
    echo ""
    echo ""
    writelog "Removing UK Account proxyAddresses attributes..."
        
    foreach ($ukUsr in $proxyAddressesUsers)
    {         
        $ukUsr|Set-ADUser -Clear proxyAddresses        
        writelog "`tRemoved ProxyAddresses attribute for $($ukUsr.name)" -yellow $false
    }
}

function clearGroupMembership{
    ###############################################################################
    # This function checks that all migrated Users' source domain accounts no longer
    # belong to any groups as this would mean this group membership was not copied
    # uses the getExistingGroups function to retrieve the list of users to set
    ###############################################################################

    echo ""
    echo ""
    writelog "Removing UK Account group membership..."

 
    foreach ($usr in $existingGroups)
    { 
        $ukusr = $usr.User
        $grps = get-ADPrincipalGroupMembership $ukusr -server $sourceDomain -Credential $cred

        if ($grps.count -ge "2")
        {   
            $gbusr = [ADSI]"LDAP://$destDomain/$((get-aduser -server $destDomain -filter {samaccountname -like $ukusr.samaccountname} `
            -properties distinguishedname|select distinguishedname).distinguishedname)"
        
            foreach ($l in $grps){
                $grpPath = "LDAP://$destDomain/$l"
                $adsigrp = New-Object System.DirectoryServices.DirectoryEntry($grpPath,$username,$password)
 
                if ($l.name -ne "Domain Users"){

                    if (!($adsigrp.IsMember($gbusr.ADsPath) -eq $True)){ 
                        $domain = $($([ADSI]"LDAP://$($([string]$l).substring($([string]$l).indexof("DC=")))").dc).ToUpper()

                        $ukadsiusr = [ADSI]"LDAP://$sourceDomain/$((get-aduser -server $sourceDomain -filter {samaccountname -like $ukusr.samaccountname} `
                        -properties distinguishedname|select distinguishedname).distinguishedname)"

                        $adsigrp.Add($gbusr.Path) 
                        $adsigrp.commitchanges()
                        writelog "`Added GLOBAL\$($gbusr.Name) to the $domain group $($adsigrp.Name)" -yellow $false
                        
                        $adsigrp.Remove($ukadsiusr.Path)
                        $adsigrp.commitchanges()
                        writelog "`Removed foxmoat\$($gbusr.Name) from the $domain group $($adsigrp.Name)" -yellow $false

                        echo ""
                    }
                }
            }        
        }            
    }
}

function updateHomeDirectory{
    if ($Frankfurt){
        foreach ($str in $migratedUsers){ 
            $drive = "\\foxmoat.com\foxmoatroot\Global\EMEA\Frankfurt\User\$($str.samaccountname)"
            $usr = $str.samaccountname

            if ($str.homeDirectory -notlike "" -and (Test-Path $drive)){
                Set-ADObject -Identity $str `
                -Replace @{homedirectory="\\foxmoat.com\foxmoatroot\Global\EMEA\Frankfurt\User\$($str.samaccountname)"}
            }else{writelog "`tError updating the E drive for: GLOBAL\$usr`n"}
        }
    }
}


if(!(Get-Module -name "activedirectory")){Import-Module activedirectory}


###############################################################################
# Get credentials to modify groups in different domains
###############################################################################

$pass = Get-Content \\foxmoat.com\foxmoatroot\Global\Migration\pass.txt
$key = Get-Content \\foxmoat.com\foxmoatroot\Global\Migration\key.txt

$cred = New-Object -TypeName System.Management.Automation.PSCredential -argumentlist “foxmoatroot\qmmoperator”,$($pass| ConvertTo-SecureString -Key $key)
$username = $cred.username
$password = $cred.GetNetworkCredential().password


$AllUsers = getAllUsers
$migratedUsers = getMigratedUsers
$profilePathUsers = getProfilePath
$proxyAddressesUsers = getProxyAddresses
$existingGroups = getExistingGroups


if ($modify)
{
    updateHouseIdentifier
    forcePasswordChange
    updateLyncProfile
    updateHomeDirectory

    clearProfilePath
    clearProxyAddresses
    clearGroupMembership
    moveSourceAccounts
    
    if ($Frankfurt){SCHTASKS /run /s gb01winfapp01p /TN updateMSOL_FFT}else{SCHTASKS /run /s gb01winfapp01p /TN updateMSOL}
}
else
{
    echo ""
    echo ""
    write-host "Task: Update HouseIdentifier Attribute" -BackgroundColor DarkGreen -ForegroundColor Black
    $migratedUsers|select Name,HouseIdentifier|ft Name,@{Expression={$_.HouseIdentifier};Label="House Identifier"}
    echo ""
    echo ""

    write-host "Task: Force Password Change" -BackgroundColor DarkGreen -ForegroundColor Black
    $migratedUsers|select Name,Mail|ft
    echo ""
    echo ""

    write-host "Task: Update Lync Profile" -BackgroundColor DarkGreen -ForegroundColor Black
    $migratedUsers|select Name,'msRTCSIP-PrimaryUserAddress'|ft Name,@{Expression={$_.'msRTCSIP-PrimaryUserAddress'};Label="SIP Address"}
    echo ""
    echo ""

    write-host "Task: Clear ProfilePath Attribute" -BackgroundColor DarkGreen -ForegroundColor Black
    $profilePathUsers|select Name,ProfilePath|ft Name,@{Expression={$_.ProfilePath};Label="Profile Path"}
    echo ""
    echo ""

    write-host "Task: Clear Source Account ProxyAddresses Attribute" -BackgroundColor DarkGreen -ForegroundColor Black
    $proxyAddressesUsers|select Name,ProxyAddresses|ft Name,@{Expression={$_.ProxyAddresses};Label="Proxy Addresses"}
    echo ""
    echo ""

    write-host "Task: Clear Source Account Group Memberships" -BackgroundColor DarkGreen -ForegroundColor Black
    $existingGroups|%{$tmp = $_.user.name;$_|select -ExpandProperty group|%{$_|select @{e={$tmp};n="User"},@{e={$_.name};n="Group"},@{e={$_.domain};n="Domain"}}}|ft -AutoSize
    echo ""
    echo ""
    
    write-host "Task: Move Source Accounts" -BackgroundColor DarkGreen -ForegroundColor Black
    $migratedUsers|select Name,Distinguishedname|ft -AutoSize
    echo ""
    echo ""
}