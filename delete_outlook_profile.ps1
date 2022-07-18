

function Remove-RegKey ([string] $ProfilePath)
{   
    $hivePath = Join-Path -Path $ProfilePath -ChildPath "NTUser.dat"
    if  (-Not (Test-Path $hivePath))
    {
        Write-Output "NTUser.dat file does not exist"
        Return
    }

    Copy-Item -Path $hivePath "$hivePath.old"
    Reg load HKU\TempUsr $hivePath

    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS|Out-Null

    if (Test-Path -Path HKU:\TempUsr\Software\Microsoft\Office\16.0\Outlook\Profiles)
    {
        foreach ($key in (Get-ChildItem HKU:TempUsr\Software\Microsoft\Office\16.0\Outlook\Profiles))
        {
            reg delete $key.Name /f
        }
    }
    if (Test-Path -Path HKU:TempUsr\Software\Microsoft\Office\15.0\Outlook\Profiles\)
    {
        foreach ($key in (Get-ChildItem HKU:TempUsr\Software\Microsoft\Office\15.0\Outlook\Profiles))
        {
            reg delete $key.Name /f
        }
    }

}

function Get-HiveList ()
{
    return Get-Childitem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | `
    ForEach-Object {if (Test-Path "$($._)\ProfileImagePath"){Get-ItemProperty "$($._)\ProfileImagePath"}}
}

