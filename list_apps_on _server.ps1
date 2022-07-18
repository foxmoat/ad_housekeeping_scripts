$AV = @("sophos anti-virus","symantec endpoint")
$BK = @("Veritas NetBackup Client","backup")
$HP = @("HP OpenView E/A Agent","Monitoring")

$comps = @()
$tmp = @()
$apps = @()
$arr = @()
$compObjs = @()
$err = @()

#$arr = Get-ADComputer -server foxmoat.com -filter *  -properties operatingsystem|?{($_.operatingsystem -like "*server*")}|select name
$arr = import-csv C:\Scripts\machinelist.txt

foreach ($l in $arr){
    $comp = $l.name
    try{
        if (Test-WSMan -ComputerName $comp -ErrorAction SilentlyContinue)
        {
            $comps += $comp
        }else{$err += $comp}
    }catch{$err += $comp}
}

$sessions = New-PSSession -ComputerName $comps

Write-Host "Checking for software on servers"
$apps = Invoke-Command  -ErrorAction silentlycontinue -Session $sessions {Get-WmiObject -Class Win32_Product| `
select PSComputerName,name,version} `

$tmp = $apps| select PSComputerName  -Unique
$compObjs = @()
foreach ($p in $tmp){
    
    #echo "`n" $p.PSComputerName   
    $compObj = New-Object -TypeName PsObject
	$compObj  | Add-Member -type NoteProperty -name ComputerName -value $p.PSComputerName

    $compObj  | Add-Member -type NoteProperty -name AV -Value $false
    $compObj  | Add-Member -type NoteProperty -name AVName -Value ""
    $compObj  | Add-Member -type NoteProperty -name AVVersion -Value ""

    $compObj  | Add-Member -type NoteProperty -name BK -Value $false
    $compObj  | Add-Member -type NoteProperty -name BKName -Value ""
    $compObj  | Add-Member -type NoteProperty -name BKVersion -Value ""

    $compObj  | Add-Member -type NoteProperty -name HPOV -Value $false
    $compObj  | Add-Member -type NoteProperty -name HPOVName -Value ""
    $compObj  | Add-Member -type NoteProperty -name HPOVVersion -Value ""
        
    foreach ($l in $apps){
        if (($l.name -in $AV) -and ($l.PSComputerName -like $p.PSComputerName)){
            
            $compObj.AV = $true
            $compObj.AVName = $l.name
            $compObj.AVVersion = $l.version
        }

        if (($l.name -in $BK) -and ($l.PSComputerName -like $p.PSComputerName)){
            
            $compObj.BK = $true
            $compObj.BKName = $l.name
            $compObj.BKVersion = $l.version
        }

        if (($l.name -in $HP) -and ($l.PSComputerName -like $p.PSComputerName)){
            
            $compObj.HPOV = $true
            $compObj.HPOVName = $l.name
            $compObj.HPOVVersion = $l.version
        }    
    }

    $compObjs += $compObj
}

$compObjs|select computername,av,hpov,bk

Write-Host "Checking for Timezone information on servers"
Invoke-Command  -ErrorAction silentlycontinue -Session $sessions {[System.TimeZone]::CurrentTimeZone}|ft

Get-PSSession|Remove-PSSession



echo ""
echo "Servers not accessible"
$err

