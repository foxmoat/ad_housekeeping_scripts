$subnet = @()
$output = @()
[int] $IPv4Mask = 24
$objRootDSE = [System.DirectoryServices.DirectoryEntry] "LDAP://rootDSE"

function Compute-IPv4 ( $Obj, $ObjInputAddress, $IPv4Mask ){
	$Obj | Add-Member -type NoteProperty -name Type -value "IPv4"
	
	# Compute IP length
    [int] $IntIPLength = 32 - $IPv4Mask
		
	# Returns the number of block-size
	[int] $BlockBytes = [Math]::Floor($IntIPLength / 8)
	
	$NumberOfIPs = ([System.Math]::Pow(2, $IntIPLength)) -1

	$IpStart = Compute-IPv4NetworkAddress $ObjInputAddress $BlockBytes $IPv4Mask
	$Obj | Add-Member -type NoteProperty -name Subnet -value "$($IpStart)/$($IPv4Mask)"
	$Obj | Add-Member -type NoteProperty -name IpStart -value $IpStart

	$ArrBytesIpStart = $IpStart.GetAddressBytes()
	[array]::Reverse($ArrBytesIpStart)
	$RangeStart = [system.bitconverter]::ToUInt32($ArrBytesIpStart,0)

	$IpEnd = $RangeStart + $NumberOfIPs

	If (($IpEnd.Gettype()).Name -ine "double")
	{
		$IpEnd = [Convert]::ToDouble($IpEnd)
	}

	$IpEnd = [System.Net.IPAddress] $IpEnd
	$Obj | Add-Member -type NoteProperty -name IpEnd -value $IpEnd

	$Obj | Add-Member -type NoteProperty -name RangeStart -value $RangeStart
	
	$ArrBytesIpEnd = $IpEnd.GetAddressBytes()
	[array]::Reverse($ArrBytesIpEnd)
	$Obj | Add-Member -type NoteProperty -name RangeEnd -value ([system.bitconverter]::ToUInt32($ArrBytesIpEnd,0))
	
	Return $Obj
}

function Compute-IPv4NetworkAddress ( $Address, $nbBytes, $IPv4Mask ){
	$ArrBytesAddress = $Address.GetAddressBytes()
	[array]::Reverse($ArrBytesAddress)

	# Sets a Block-Size to 0 if it is a part of the network length
	for ( $i=0; $i -lt $nbBytes; $i++ )
	{
		$ArrBytesAddress[$i] = 0
	}
	
	# Returns the remaining bits of the prefix
	$Remaining =  $obj.Prefix % 8
	
	if ( $Remaining -gt 0 )
	{
		$Mask = ([Math]::Pow(2,$Remaining)-1)*([Math]::Pow(2,8-$Remaining))
		$BlockBytesValue = $ArrBytesAddress[$i] -band $Mask
		$ArrBytesAddress[$i] = $BlockBytesValue
	}

	[array]::Reverse($ArrBytesAddress)
	$NetworkAddress = [System.Net.IPAddress] $ArrBytesAddress
	
	Return $NetworkAddress
}

function Get-NetlogonPath ( $hostname ){
	try
	{
		$WMIObj = Get-WmiObject Win32_OperatingSystem -Property systemDirectory
		$Path = "\\"+$hostname+"\"+((split-path $WMIObj.SystemDirectory -Parent) -replace ':','$')+"\debug\netlogon.log"
		Return $Path
	}
	catch
	{
		Write-Host "Unable to retrieve netlogon.log path with WMI." -ForegroundColor Red
		Return $null
	}
}

$ADSIForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
			
# Retrieve the list of all DCs within the forest
foreach ( $ADSIDomain in $ADSIForest.Domains ){
    Write-Host "`nParsing Domain $ADSIDomain" -ForegroundColor Green
    $LogEntries = @()
    $ArrIPs = @()

    foreach ($comp in $ADSIDomain.DomainControllers){
        $LogEntry = @()
        $filepath = Get-NetlogonPath $comp
    
        if (Test-Path $filepath){
            write-host "`tParsing file $filepath..." -ForegroundColor Yellow
        
            $file = Get-Content -path "$filepath" -Tail 500          
            Foreach ( $line in $file ){
			    if ( $line -match 'NO_CLIENT_SITE:\s*(.*?)\s*(\d*\.\d*\.\d*\.\d*)' ){				
				    $Obj = New-Object -TypeName PsObject
			        $Obj | Add-Member -type NoteProperty -name IpAddress -value ($matches[2])
				    $LogEntry += $Obj
			    }
		    }
        
            $LogEntries = $LogEntry|select IpAddress -Unique
        }
    }
    
    if ($LogEntries.Count -gt 0){
	   
	    # Each IP is converted to a subnet based on the IPv4Mask argument (24 bits by default)
	    foreach ( $Entry in $LogEntries ){
		    $ObjIP = [System.Net.IPAddress] $Entry.IpAddress
		
		    $SubnetObj = New-Object -TypeName PsObject
		
		    if ( $ObjIP.AddressFamily -match "InterNetwork" ){
			    $SubnetObj = Compute-IPv4 $SubnetObj $ObjIP $IPv4Mask
			    $ArrIPs += $SubnetObj
	        }
	    }

	    # Remove duplicated subnets
	    $ArrIPs = $ArrIPs | Sort-Object rangeStart | Select * -Unique
	
	    # Retrieve AD subnets to check if missing subnets found in the netlogon files have not been added during the interval
	    Write-Host "`tRetrieving AD subnets for domain $ADSIDomain" -ForegroundColor Yellow
	
	    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
	    $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://cn=subnets,cn=sites,"+$objRootDSE.ConfigurationNamingContext)
	    $Searcher.PageSize = 10000
	    $Searcher.SearchScope = "Subtree"
	    $Searcher.Filter = "(objectClass=subnet)"

	    $Properties = @("cn","location","siteobject")
	    $Searcher.PropertiesToLoad.AddRange(@($Properties))
	    $Subnets = $Searcher.FindAll()

	    $selectedProperties = $Properties | ForEach-Object {@{name="$_";expression=$ExecutionContext.InvokeCommand.NewScriptBlock("`$_['$_']")}}
	    [Regex] $RegexCN = "CN=(.*?),.*"
	    $SubnetsArray = @()

	    foreach ( $Subnet in $Subnets ){
		    # Construct the subnet object
		    $SubnetObj = New-Object -TypeName PsObject
		    $SubnetObj | Add-Member -type NoteProperty -name Name -value ([string] $Subnet.Properties['cn'])
		    $SubnetObj | Add-Member -type NoteProperty -name Location -value ([string] $Subnet.Properties['location'])
		    $SubnetObj | Add-Member -type NoteProperty -name Site -value ([string] $RegexCN.Match( $Subnet.Properties['siteobject']).Groups[1].Value)
	     
		    $InputAddress = (($SubnetObj.Name).Split("/"))[0]
		    $ADSubnetPrefix = (($SubnetObj.Name).Split("/"))[1]
		
		    # Construct System.Net.IPAddress 
	        $ObjInputAddress = [System.Net.IPAddress] $InputAddress
		
		    # Check if IP is a IPv4 (IPv6 not collected)
		    if ( $ObjInputAddress.AddressFamily -eq "InterNetwork" ){
			    $SubnetObj = Compute-IPv4 $SubnetObj $ObjInputAddress $ADSubnetPrefix
			    $SubnetsArray += $SubnetObj
	        }
	    }
	
	    $Subnets = $SubnetsArray | Sort-Object -Property RangeStart

	    # Check if subnets are not already created
	    foreach ($Item in $ArrIPs){
		    $SubnetIsExisting = $Subnets | Where-Object { ($Item.RangeStart -ge $_.RangeStart) -and ($Item.RangeEnd -le $_.RangeEnd) }
		
		    if ( ($SubnetIsExisting) -and ($ArrIPs.Count -gt 1) ){
			    [array]::Clear($ArrIPs,([array]::IndexOf($ArrIPs, $Item)),1)
		    }
	    }

	    # Export Missing subnets
	    if ( $ArrIPs )	    {
            foreach ($l in $ArrIPs){
                $tmp = New-Object -TypeName PsObject
		        $tmp | Add-Member -type NoteProperty -name Domain -value $ADSIDomain
		        $tmp | Add-Member -type NoteProperty -name Subnets -Value $($l|select subnet).subnet
                $output += $tmp
            }
	    }else{
		    Write-Host "`nNo Missing subnet found. Try with a greater netmask." -ForegroundColor Yellow
	    }
    }else{Write-Host "`tNo Missing subnet found." -ForegroundColor Green}  
}


$output|select *|sort domain|ft -AutoSize