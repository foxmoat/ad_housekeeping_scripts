Param(
    [string]$sourceUPN,
    [string]$targetUPN,
    [System.Management.Automation.PSCredential]$sourceSA,
    [System.Management.Automation.PSCredential]$targetSA,
    [string]$sourceDomain,
    [string]$targetDomain= "foxmoat.com"

)
 
################ function to get SID of user ##################### 
function Get-SID ([string]$User) 
{ 
    $objUser = New-Object System.Security.Principal.NTAccount($User) 
    $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]) 
    $strSID.Value 
} 


function Move-Computer{ 

    try{
        $DomainJoinResult = Add-Computer -DomainName $targetDomain -Credential $targetSA -PassThru -EA Stop -WarningAction SilentlyContinue 
        Start-Sleep 1;              ## Time wait before domain user SID is fetched. 
    } 
    catch{ 
        Write-Host -Fore Red "Cannot join to domain. This may be due to:" 
        Write-Host -Fore Red "1) Incorrect username & password." 
        Write-Host -Fore Red "2) Windows Powershell Console is not Run as Administrator." 
    } 

    return $DomainJoinResult
}

function Set-RegistryACL() { 

    Write-Host -Fore Green "The computer has been successfully joined to domain." 
    ################ Get current user SID & new user SID ############ 
    $targetUserSID = Get-SID $targetUPN 
    $homePath = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'|?{$_.pschildName -eq $sourceUserSID}|Get-ItemProperty|select ProfileImagePath).ProfileImagePath
        
        
    ##################### Assign full permission of Current User's home directory to new user ################ 
    $Acl = (Get-Item $homePath).GetAccessControl('Access') 
    $Ar = New-Object system.security.accesscontrol.filesystemaccessrule($targetUPN,"FullControl","ContainerInherit,ObjectInherit","None","Allow") 
    $Acl.SetAccessRule($Ar) 
    $Acl | Set-Acl -Path $homePath 
 
    ###################### Backup current user's SID to file in home directory################# 
    Write-Host "$sourceUPN`'s SID $sourceUserSID is saved to file in $homePath\UserSID.txt." 
    Set-Content $homePath\UserSID.txt "SID of $sourceUPN `r`n$sourceUserSID`r`n`r`nSID of $targetUPN SID `r`n$targetUserSID" 
 
    ####################### If AD Join is OK, then change registry of current user SID to new user SID ############## 
    Rename-Item "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\$sourceUserSID" -NewName $targetUserSID 
 
    ####################### Change Security Permission of Current User's SID Profile and Profile's SID_Classes key registry ############### 
    $Acl = Get-Acl "Registry::HKU\$sourceUserSID" 
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($targetUPN,"FullControl","ContainerInherit,ObjectInherit","None","Allow") 
    $Acl.SetAccessRule($rule) 
    $Acl |Set-Acl -Path "Registry::HKU\$sourceUserSID" 
 
    $Acl = Get-Acl "Registry::HKU\$($sourceUserSID)_Classes" 
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($targetUPN,"FullControl","ContainerInherit,ObjectInherit","None","Allow") 
    $Acl.SetAccessRule($rule) 
    $Acl |Set-Acl -Path "Registry::HKU\$($sourceUserSID)_Classes" 
    Write-Host -Fore Green "Current $sourceUPN`'s profile has been migrated successfully to new $targetUPN."  
} 
 
$sourceUserSID = Get-SID $sourceUPN 
Move-Computer
Set-RegistryACL