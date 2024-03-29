param (
   [string]$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name,
   [string]$recipient
)

$workingDir = "C:\Scripts\DiskSpace"
$dte = (get-date).AddDays(-31)
if(!(Get-Module -name "activedirectory")){Import-Module activedirectory}
$computers = Get-ADComputer -Filter {passwordlastset -ge $dte -and operatingsystem -like "*server*"} `
-Properties operatingsystem, passwordlastset -Server $domain|select name|sort name

$servers =@()
foreach ($comp in $computers){$servers +=$comp.name}
$servers = $servers|sort

$outfile = "$workingDir\output.csv"
$output = @(); 
"server,drive,total,free,percent"|out-file $outfile

$passwords = @(GCI "$workingDir\passwords\")
$passwords = @($passwords | sort name)
$creds = @()

foreach ($pw in $passwords){
	$secure = get-content $pw.fullname | ConvertTo-SecureString
	
    if($pw.name.contains("^")){
        $user = $pw.name.replace("^","\").replace(".txt","").replace("£","")
    }else{
        $user = $pw.name.replace(".txt","").replace("£","")
    }
	
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $user ,$secure		
    $creds += $cred
}

$Throttle = 20 #threads
 
$ScriptBlock = {
   Param (
      [string]$comp,
      $Credentials
        
   )
   foreach ($credential in $credentials){
        #$resl_2 += $credential
        try{
            
            $RunResult = gwmi -query "Select * from Win32_LogicalDisk where drivetype = 3" `
            -ComputerName $comp -Credential $Credential -ErrorAction SilentlyContinue -ErrorVariable ev 2>&1
            
            if ($RunResult -ne $null){break}
        }catch{}
    }
    Return $RunResult
}
 
$RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $Throttle)
$RunspacePool.Open()
$Jobs = @()
 
foreach ($server in $servers){
    $Job = [powershell]::Create().AddScript($ScriptBlock).AddArgument($server).AddArgument($creds)

    $Job.RunspacePool = $RunspacePool
    $Jobs += New-Object PSObject -Property @{
        RunNum = $server
        Pipe = $Job
        Result = $Job.BeginInvoke()
    }
}
 
Write-Host "Waiting.." -NoNewline
Do {
   Write-Host "." -NoNewline

   Start-Sleep -Seconds 1
} While ( (($jobs | % { $_.result }) | Select -ExpandProperty IsCompleted) -contains $false)
Write-Host "All jobs completed!"
 
$Results = @()
ForEach ($Job in $Jobs)
{   $Results += $Job.Pipe.EndInvoke($Job.Result)
    $job.Pipe.Dispose()
}

$RunspacePool.Close()
#$Results
foreach ($drive in $Results){
    if ($drive.freespace -ne $null){
                                
		$free = [Math]::Round($drive.freespace/1gb,2)
		$size = [Math]::Round($drive.size/1gb,2)
		if ($size -eq 0){

			$percent = 0
		}else{

			$percent = [Math]::Round((($free / $size) * 100),2)
		}	
                
        if ($percent -le "10" -or $free -le "5"){
            [string]::join(',',($drive.SystemName,$drive.deviceid,$size,$free,$percent))|out-file $outfile -append
        }
    }
}



$CSV = import-csv $outfile
$html = @(); $html += "<table"
$html += "<tr><td>" + "<b>ServerName</b>" + "</td><td>&nbsp;</td><td>" + "<b>Drive Letter</b>" + "</td><td>&nbsp;</td><td>" + "<b>Total Size (GB)</b>" + "</td><td>&nbsp;</td><td>" + "<b>Free Space (GB)</b>" + "</td><td>&nbsp;</td><td>" + "<b>Percent Free</b>" + "</td></tr>"
foreach ($line in $CSV)
{
	if(([int]$line.percent -ne $null) -and ([int]$line.percent -lt 5))
	{
		$html += "<tr><td>" + "<font color=`"red`">$($line.server)</font>" + "</td><td>&nbsp;</td><td>" + "<font color=`"red`">$($line.drive)</font>" + "</td><td>&nbsp;</td><td>" + "<font color=`"red`">$($line.total)</font>" + "</td><td>&nbsp;</td><td>" + "<font color=`"red`">$($line.free)</font>" + "</td><td>&nbsp;</td><td>" + "<font color=`"red`">$($line.percent)</font>" + "</td></tr>"
	}
	elseif(([int]$line.percent -ne $null) -and ([int]$line.percent -lt 20))
	{
		$html += "<tr><td>" + "<font color=`"orange`">$($line.server)</font>" + "</td><td>&nbsp;</td><td>" + "<font color=`"orange`">$($line.drive)</font>" + "</td><td>&nbsp;</td><td>" + "<font color=`"orange`">$($line.total)</font>" + "</td><td>&nbsp;</td><td>" + "<font color=`"orange`">$($line.free)</font>" + "</td><td>&nbsp;</td><td>" + "<font color=`"orange`">$($line.percent)</font>" + "</td></tr>"
	}
	else
	{
		$html += "<tr><td>" + "<font color=`"green`">$($line.server)</font>" + "</td><td>&nbsp;</td><td>" + "<font color=`"green`">$($line.drive)</font>" + "</td><td>&nbsp;</td><td>" + "<font color=`"green`">$($line.total)</font>" + "</td><td>&nbsp;</td><td>" + "<font color=`"green`">$($line.free)</font>" + "</td><td>&nbsp;</td><td>" + "<font color=`"green`">$($line.percent)</font>" + "</td></tr>"
	}
}
$html += "</table>"



$smtpServer="mailrelay.uk.foxmoat.com"
$msg = new-object System.Net.Mail.MailMessage
$msg.isbodyhtml = $true
$msg.From = "powershell@foxmoat.com"
$to = New-Object System.Net.Mail.MailAddress $recipient
$msg.To.Add($to)
$msg.Subject = "Disk Space Report on $domain server drives for SoB"
$msg.Body = $html
$msg.Attachments.Add($outfile)
$smtpClient = New-Object System.Net.Mail.SmtpClient $smtpServer
$smtpClient.Send($Msg)

foreach ($att in $msg.Attachments){
    $att.Dispose();
}