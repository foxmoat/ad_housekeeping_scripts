param (
    [string]$Group,
    [string]$Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
 )

function indentString([string]$s,[bool]$yellow = $false)
{
    $indt = 1
    do {$s = "`t" + $s;$indt++}
    while ($indt -le $i)
    if ($yellow){write-host $s -ForegroundColor Yellow}else{write-host $s}
}

function getSubUsers ([String]$vGroup){
    $i++    
    $tmpMembers = ([ADSI]"LDAP://$vGroup").properties.item("member")
    $tmpMembers = $tmpMembers|sort

    if ($tmpMembers.count -gt 0)
    {
        foreach ($str in $tmpMembers){
            $member = [ADSI]"LDAP://$str"
            $i++
                if ($member.properties.item("objectclass") -like "user" -or $member.properties.item("objectclass") -like "contact")
                {
                    $arry.add("$($member.properties.item("mail"))")|out-null
                    indentString "$($member.properties.item("mail"))"
                }else{
                    indentString "$($member.name)"
                    getSubUsers($member.distinguishedName)
                }
            $i--
        }
    }     
}

if(!(Get-Module -name "ActiveDirectory")){Import-Module ActiveDirectory}
Write-Host "Generating Report for Group: $($group.toUpper()) in Domain: $($domain.toUpper())`n" -ForegroundColor Green


$arry = New-Object System.Collections.ArrayList($null)
$members = Get-ADGroup -Identity $group -Properties members -Server $domain |select -ExpandProperty members
$members = $members|sort
$i = 0
foreach ($str in $members){
    $member = [ADSI]"LDAP://$str"
    $i++
        if ($member.properties.item("objectclass") -like "user" -or $member.properties.item("objectclass") -like "contact")
        {
            $arry.add("$($member.properties.item("mail"))")|out-null
            indentString "$($member.properties.item("mail"))"
        }else{
            indentString "$($member.name)" -yellow $true
            getSubUsers($member.distinguishedName)
        }
    $i--
}
Write-Host "`nSummary of Users" -ForegroundColor Yellow
$arry|sort -Unique
$arry.Count
