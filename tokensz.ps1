 param (
    [string]$username = $ENV:username,
    [string]$path = "DC=uk,DC=foxmoat,DC=com"
 )

$groupfile = $username + "_groups.txt"
$tokenfile = $username + "_tokeninfo.txt"


function global:Count-Groups {


    param($CN)


    $LDAP="LDAP://"+$CN

    write-host $CN
    $CN  | out-file $groupfile -append

    $user = [adsi]$LDAP
    $groupSearcher = New-Object DirectoryServices.DirectorySearcher($user)
    $groupSearcher.PageSize = 1000
    $results = $groupSearcher.FindOne()


    if ($results.properties.item("groupType") -eq "-2147483646") {$Type="Global"}
    if ($results.properties.item("groupType") -eq "-2147483644") {$Type="DomainLocal"}
    if ($results.properties.item("groupType") -eq "-2147483640") {$Type="Universal"}


    if ($Groups -notcontains $CN) {
        $script:Groups += $CN
        if ($Type -eq "Global") {$script:GlobalGroups += $CN}
        if ($Type -eq "DomainLocal") {$script:DomainLocalGroups += $CN}
        if ($Type -eq "Universal") {$script:UniversalGroups += $CN}
    }


    foreach ($Group in $results.properties.item("memberOf")) {
        if ($Groups -notcontains $Group) {
            Count-Groups($Group)
        }
    }
}


function global:Estimate-Token {


    param($Name,[string]$ADSPath)

    $ADSPath = $ADSPath.Replace("LDAP://","")

    Set-Variable -Name Groups -Value @() -Scope Script
    Set-Variable -Name GlobalGroups -Value @() -Scope Script
    Set-Variable -Name DomainLocalGroups -Value @() -Scope Script
    Set-Variable -Name UniversalGroups -Value @() -Scope Script


    Count-Groups $ADSPath


    $TokenSize =  1200 + ($DomainLocalGroups.Count * 40) + ($UniversalGroups.Count * 40) + ($GlobalGroups.Count * 8)
    $DCTokenSize = $TokenSize * 2


    [string]$TokenInfo = $Name + "," + $TokenSize + "," + $DCTokenSize + "," + $Groups.Count + "," + $DomainLocalGroups.Count  + "," + $UniversalGroups.Count + "," +  $GlobalGroups.Count + "," + $ADSPath

    write-host $TokenSize : $ADSPath

    $TokenInfo.Replace(" ","") | out-file $tokenfile -append


}


$Header = "Name,Token Size,Double Token Size,Groups,Domain Local Grops,Universal Groups,Global Groups"
$Header | out-file $tokenfile -append


$strFilter = "(&(objectCategory=person)(objectClass=user)(samaccountname=$username))"

$objDomain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://" + $path)


$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
$objSearcher.SearchRoot = $objDomain
$objSearcher.PageSize = 1000
$objSearcher.Filter = $strFilter
$objSearcher.SearchScope = "Subtree"


$objSearcher.PropertiesToLoad.Add("name")


$colResults = $objSearcher.FindAll()


foreach ($objResult in $colResults) {
    $objItem = $objResult.Properties
    Estimate-Token $objItem.name $objItem.adspath
}