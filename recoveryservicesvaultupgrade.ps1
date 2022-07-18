param(
	[Parameter(Mandatory=$true)]
    [string]
	$SubscriptionId="",             # Subscription Id of Azure account
	
	[Parameter(Mandatory=$true)]
	[string]
	$VaultName="",                  # Vault name
	
	[Parameter(Mandatory=$true)]
	[string]
	$Location="",                   # Vault's geo
	
	[Parameter(Mandatory=$true)]
	[string]
	$ResourceType="",               # Vault type: "HyperVRecoveryManagerVault" for Azure Site Recovery vaults and "BackupVault" for Backup vaults
	
	[Parameter(Mandatory=$true)]
	[string]
	$TargetResourceGroupName="",    # Resource group in which the upgraded vault will be placed.
	
	[Parameter(Mandatory=$false)]
    [ValidateSet("AzureCloud", "AzureChinaCloud", "AzureUSGovernment")]
	[string]
	$EnvironmentName="AzureCloud"
)

# Code to be returned when operation completes successfully
$SUCCEED = 0

# Code to be returned when operation fails.
$FAILED = 1

# Shows the final message to the user and exits the script.
function ExitProgram( [Int] $exitCode, [string] $message) {
	if($exitCode -eq $FAILED){
		$fc = $host.UI.RawUI.ForegroundColor;
		$host.UI.RawUI.ForegroundColor = "red";
		Write-Output "`n$message`n" 
		$host.UI.RawUI.ForegroundColor = $fc
	} else {
		Write-Output "`n$message" 
	}
		
	exit $exitCode
}

# Validate module's version.
function ValidateRDFEModuleVersion ()
{
	$moduleInfo = Get-Module -ListAvailable -Name Azure
	if ($moduleInfo -eq "null" -Or !($moduleInfo.Version.Major -gt 3 -Or ($moduleInfo.Version.Major -eq 3 -And $moduleInfo.Version.Minor -ge 8)))
	{
		ExitProgram $FAILED "Install/Upgrade Azure module version to atleast 3.8.0"
	}
}

# Validate the parameters
function ValidateParameters()
{
	if ($SubscriptionId -notmatch "^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$")
	{
		ExitProgram $FAILED "The provided subscription id $SubscriptionId is not a valid GUID. Please provide a valid GUID."
	}

	$resourceGroupDisallowedCharacters = "\s~!@#$%^&*+=<>,\?/\\\:;'`"\[\]\{\}\|"
	$regEx = -join("^[^",$resourceGroupDisallowedCharacters,"]*[^.",$resourceGroupDisallowedCharacters,"]$")
	if ($TargetResourceGroupName.length -gt 90)
	{
		ExitProgram $FAILED "Resource group name only allows up to 90 characters."
	}
	elseif ($TargetResourceGroupName -notmatch $regEx)
	{
		ExitProgram $FAILED "Resource group name can only include alphanumeric characters, periods, underscores, hyphens and parenthesis and cannot end in a period."
	}
}

# Exit in case of unexpected errors
function HandleErrorsIfAny()
{
    if ($error.Count -ne 0)
    {
	    ExitProgram $FAILED "Unexpected error occured. Please re-run the script. If the issue still persists, please contact Microsoft Support."
    }
}

# Register resource provider, if not already registered
function RegisterProviderIfRequired([string] $providerNamespace)
{
	$regState = (Get-AzureRmResourceProvider -ProviderNamespace $providerNamespace).RegistrationState 
	if($regState -eq $null -Or $regState -eq "Registered")
	{ 
		Return
	}
	elseif ($regState -eq "Pending" -Or $regState -eq "Registering")
	{
		Write-Output "$providerNamespace Provider: Status is $regState. Waiting for registration to get complete..." -BackgroundColor Yellow -ForegroundColor Red
	} 
	else
	{
		Write-Output "Registering with $providerNamespace..."
		Register-AzureRmResourceProvider -ProviderNamespace $providerNamespace
	}
	
	# Keep checking the registration status after every 10 seconds.
	$startTime = Get-Date
	$allowedSpan = New-TimeSpan -Hours 1
	Do
	{
		Start-Sleep -s 10
		$regState = (Get-AzureRmResourceProvider -ProviderNamespace $providerNamespace).RegistrationState
		$endTime = Get-Date
		$span = New-TimeSpan -Start $startTime -End $endTime
	}
	While (($regState -eq "Pending" -Or $regState -eq "Registering") -And ($allowedSpan - $span -gt 0))
	
	if ($regState -eq "Pending" -Or $regState -eq "Registering")
	{
		ExitProgram $FAILED "Registering with '$providerNamespace' failed. Please try after sometime. If the issue persists, contact Microsoft support."
	}
	
	if ($regState -ne $null)
	{
		Write-Output "Registration with $providerNamespace is successful."
	}
}

ValidateRDFEModuleVersion
ValidateParameters

if ($ResourceType -eq "HyperVRecoveryManagerVault")
{
	Write-Output "`nVault upgrade is a permanent change and you will be able to access the upgraded vault only from the new Azure portal, once the upgrade is completed. You will have to update your automation/operationalization scripts to handle the Resource Manager deployment model once the upgrade is completed. Your on-going replication will not be impacted, but you will not be allowed to enable protection, failover or failback of machines during the time of upgrade."
}
else
{
	Write-Output "`nVault upgrade is a permanent change and you will be able to access the upgraded vault only from the new Azure portal, once the upgrade is completed. You will have to update your operationalization scripts to handle the Resource Manager deployment model once the upgrade is completed. You will not be allowed to configure backup for new machines or perform restore operations for IaaS VMs during the time of upgrade."
}

# Checking if user has already logged in into ARM Azure account.
$account = $null
try
{
	$account = Get-AzureRmContext 
}
catch
{
}

$error.Clear()
if ($account -eq $null -Or $account.Subscription.SubscriptionId -ne $SubscriptionId)
{
	# Login into ARM Azure account. 
	Write-Output "`nLogin into Azure ARM Account..."
	$account = Login-AzureRmAccount -EnvironmentName $EnvironmentName
	if ($account -eq $null)
	{
		ExitProgram $FAILED "Couldn't authenticate the user. Please re-run the script with valid credentials."
	}
	Write-Output "Logged in successfully." 
	
	# Validate the subscription id
	$subscriptions = Get-AzureRmSubscription
	[bool] $isSubscriptionPresent = $false
	[bool] $useOldProperty = $true
	if ($subscriptions.Count -ne 0)
	{
		if ($subscriptions[0].SubscriptionId -eq $null)
		{
			$useOldProperty = $false;
		}
	}
	
	foreach ($subscription in $subscriptions)
	{
		$id = If ($useOldProperty) {$subscription.SubscriptionId} Else {$subscription.Id};
		if ($id -eq $SubscriptionId)
		{
			$isSubscriptionPresent = $true
			break
		}
	}

	if (!$isSubscriptionPresent)
	{
		ExitProgram $FAILED "The subscription id $SubscriptionId does not exist in this account. Exiting vault upgrade."
	}
}

# Set Subscription Context
Select-AzureRmSubscription -SubscriptionId $SubscriptionId

# Register "Microsoft.RecoveryServices" if not already registered. 
RegisterProviderIfRequired "Microsoft.RecoveryServices"
HandleErrorsIfAny

# Check if the subscription is whitelisted for vault upgrade and is registered with the required resource providers.
$regState = (Get-AzureRmProviderFeature -FeatureName "VaultUpgrade" -ProviderNamespace Microsoft.RecoveryServices).RegistrationState
HandleErrorsIfAny
if ($regState -eq "Pending" -Or $regState -eq "Registering") {
	ExitProgram $FAILED "Please wait till your subscription gets approved for vault upgrade and then re-run this script. Status: $regState. " 
} elseif ($regState -ne "Registered") {
	ExitProgram $FAILED "Your subscription $SubscriptionId has not been enabled for vault upgrade. Please wait till you are notified."
}

# Register "Microsoft.SiteRecovery" if not already registered.
RegisterProviderIfRequired "Microsoft.SiteRecovery"
HandleErrorsIfAny

# Validation for resource id uniqueness
$resourceGroups = Get-AzureRmResourceGroup
HandleErrorsIfAny
[bool] $isResourceGroupPresent = $false;
foreach ($resourceGroup in $resourceGroups)
{
	if ($resourceGroup.ResourceGroupName -eq $TargetResourceGroupName)
	{
		$isResourceGroupPresent = $true
		break
	}
}

if ($isResourceGroupPresent)
{
	$vaults = Get-AzureRmRecoveryServicesVault -ResourceGroupName $TargetResourceGroupName
	HandleErrorsIfAny
	foreach ($vault in $vaults)
	{
		if ($vault.Name -eq $VaultName)
		{
			# If there already exists a vault with the given name, check if it's a vault with upgrade in progress or a vault for which upgrade got failed.
			if($vault.Properties.ProvisioningState -ne "Provisioning")
			{
				ExitProgram $FAILED "A vault with name $VaultName already exists in resource group $TargetResourceGroupName. Please re-run the script with a different Resource Group name."
			}
			else
			{
				break
			}
		}
	} 
}
else
{
	$GetResponse = Read-Host "`nCouldn't find ResourceGroup $TargetResourceGroupName in $Location under $SubscriptionId.
Do you want us to create a new resource group? 
Press 'yes[Y]' to confirm, or 'no[N]' to exit..." 
	if ($GetResponse -ine "yes" -And $GetResponse -ine 'y')
	{
		ExitProgram $FAILED "Exiting vault upgrade."
	}
	else
	{
		Write-Output "`nResource Group $TargetResourceGroupName will get created as part of vault upgrade..."
	}
}

HandleErrorsIfAny

# Get the list of all logged-in RDFE Azure accounts
$accounts = Get-AzureAccount
$subscriptionFound = $false
foreach($account in $accounts)
{
	if ($account.Subscriptions.Contains($SubscriptionId))
	{
		$subscriptionFound = $true
		break
	}
}

if (!$subscriptionFound)
{
	# Login into RDFE Azure account. 
	Write-Output "`nLogin into Azure RDFE Account..."  
	$account = Add-AzureAccount -Environment $EnvironmentName
	if ($account -eq $null)
	{
		ExitProgram $FAILED "Couldn't authenticate the user. Please re-run the script with valid credentials."
	}
	Write-Output "Logged in successfully."  

	# Validate the subscription id
	$subscriptions = Get-AzureSubscription
	[bool] $isSubscriptionPresent = $false
	foreach ($subscription in $subscriptions)
	{
		if ($subscription.SubscriptionId -eq $SubscriptionId)
		{
			$isSubscriptionPresent = $true
			break
		}
	}

	if (!$isSubscriptionPresent)
	{
		ExitProgram $FAILED "The subscription id $SubscriptionId does not exist in this account. Exiting vault upgrade."
	}
}

# Setting Subscription context again
Select-AzureSubscription -SubscriptionId $SubscriptionId

Write-Output "`nChecking prerequisites for vault upgrade."
Write-Output "Upon successful verification, the upgrade process will be initiated and can take 15-30 minutes....."

# Start Vault upgrade.
Invoke-AzureRecoveryServicesVaultUpgrade -ResourceType $ResourceType -VaultName $VaultName -Location $Location -TargetResourceGroupName $TargetResourceGroupName
ExitProgram $Success
# SIG # Begin signature block
# MIIaygYJKoZIhvcNAQcCoIIauzCCGrcCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUR1NA6Wr8iLsip3TJt356Y9Zv
# vjCgghWDMIIEwzCCA6ugAwIBAgITMwAAAMZ4gDYBdRppcgAAAAAAxjANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTYwOTA3MTc1ODUz
# WhcNMTgwOTA3MTc1ODUzWjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OkY1MjgtMzc3Ny04QTc2MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArQsjG6jKiCgU
# NuPDaF0GhCh1QYcSqJypNAJgoa1GtgoNrKXTDUZF6K+eHPNzXv9v/LaYLZX2GyOI
# 9lGz55tXVv1Ny6I1ueVhy2cUAhdE+IkVR6AtCo8Ar8uHwEpkyTi+4Ywr6sOGM7Yr
# wBqw+SeaBjBwON+8E8SAz0pgmHHj4cNvt5A6R+IQC6tyiFx+JEMO1qqnITSI2qx3
# kOXhD3yTF4YjjRnTx3HGpfawUCyfWsxasAHHlILEAfsVAmXsbr4XAC2HBZGKXo03
# jAmfvmbgbm3V4KBK296Unnp92RZmwAEqL08n+lrl+PEd6w4E9mtFHhR9wGSW29C5
# /0bOar9zHwIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFNS/9jKwiDEP5hmU8T6/Mfpb
# Ag8JMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAJhbANzvo0iL5FA5Z5QkwG+PvkDfOaYsTYksqFk+MgpqzPxc
# FwSYME/S/wyihd4lwgQ6CPdO5AGz3m5DZU7gPS5FcCl10k9pTxZ4s857Pu8ZrE2x
# rnUyUiQFl5DYSNroRPuQYRZZXs2xK1WVn1JcwcAwJwfu1kwnebPD90o1DRlNozHF
# 3NMaIo0nCTRAN86eSByKdYpDndgpVLSoN2wUnsh4bLcZqod4ozdkvgGS7N1Af18R
# EFSUBVraf7MoSxKeNIKLLyhgNxDxZxrUgnPb3zL73zOj40A1Ibw3WzJob8vYK+gB
# YWORl4jm6vCwAq/591z834HDNH60Ud0bH+xS7PowggTtMIID1aADAgECAhMzAAAB
# QJap7nBW/swHAAEAAAFAMA0GCSqGSIb3DQEBBQUAMHkxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBMB4XDTE2MDgxODIwMTcxN1oXDTE3MTEwMjIwMTcxN1owgYMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIx
# HjAcBgNVBAMTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBANtLi+kDal/IG10KBTnk1Q6S0MThi+ikDQUZWMA81ynd
# ibdobkuffryavVSGOanxODUW5h2s+65r3Akw77ge32z4SppVl0jII4mzWSc0vZUx
# R5wPzkA1Mjf+6fNPpBqks3m8gJs/JJjE0W/Vf+dDjeTc8tLmrmbtBDohlKZX3APb
# LMYb/ys5qF2/Vf7dSd9UBZSrM9+kfTGmTb1WzxYxaD+Eaxxt8+7VMIruZRuetwgc
# KX6TvfJ9QnY4ItR7fPS4uXGew5T0goY1gqZ0vQIz+lSGhaMlvqqJXuI5XyZBmBre
# ueZGhXi7UTICR+zk+R+9BFF15hKbduuFlxQiCqET92ECAwEAAaOCAWEwggFdMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBSc5ehtgleuNyTe6l6pxF+QHc7Z
# ezBSBgNVHREESzBJpEcwRTENMAsGA1UECxMETU9QUjE0MDIGA1UEBRMrMjI5ODAz
# K2Y3ODViMWMwLTVkOWYtNDMxNi04ZDZhLTc0YWU2NDJkZGUxYzAfBgNVHSMEGDAW
# gBTLEejK0rQWWAHJNy4zFha5TJoKHzBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8v
# Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNDb2RTaWdQQ0Ff
# MDgtMzEtMjAxMC5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY0NvZFNpZ1BDQV8wOC0z
# MS0yMDEwLmNydDANBgkqhkiG9w0BAQUFAAOCAQEAa+RW49cTHSBA+W3p3k7bXR7G
# bCaj9+UJgAz/V+G01Nn5XEjhBn/CpFS4lnr1jcmDEwxxv/j8uy7MFXPzAGtOJar0
# xApylFKfd00pkygIMRbZ3250q8ToThWxmQVEThpJSSysee6/hU+EbkfvvtjSi0lp
# DimD9aW9oxshraKlPpAgnPWfEj16WXVk79qjhYQyEgICamR3AaY5mLPuoihJbKwk
# Mig+qItmLPsC2IMvI5KR91dl/6TV6VEIlPbW/cDVwCBF/UNJT3nuZBl/YE7ixMpT
# Th/7WpENW80kg3xz6MlCdxJfMSbJsM5TimFU98KNcpnxxbYdfqqQhAQ6l3mtYDCC
# BbwwggOkoAMCAQICCmEzJhoAAAAAADEwDQYJKoZIhvcNAQEFBQAwXzETMBEGCgmS
# JomT8ixkARkWA2NvbTEZMBcGCgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UE
# AxMkTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTEwMDgz
# MTIyMTkzMloXDTIwMDgzMTIyMjkzMloweTELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQ
# Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCycllcGTBkvx2aYCAg
# Qpl2U2w+G9ZvzMvx6mv+lxYQ4N86dIMaty+gMuz/3sJCTiPVcgDbNVcKicquIEn0
# 8GisTUuNpb15S3GbRwfa/SXfnXWIz6pzRH/XgdvzvfI2pMlcRdyvrT3gKGiXGqel
# cnNW8ReU5P01lHKg1nZfHndFg4U4FtBzWwW6Z1KNpbJpL9oZC/6SdCnidi9U3RQw
# WfjSjWL9y8lfRjFQuScT5EAwz3IpECgixzdOPaAyPZDNoTgGhVxOVoIoKgUyt0vX
# T2Pn0i1i8UU956wIAPZGoZ7RW4wmU+h6qkryRs83PDietHdcpReejcsRj1Y8wawJ
# XwPTAgMBAAGjggFeMIIBWjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTLEejK
# 0rQWWAHJNy4zFha5TJoKHzALBgNVHQ8EBAMCAYYwEgYJKwYBBAGCNxUBBAUCAwEA
# ATAjBgkrBgEEAYI3FQIEFgQU/dExTtMmipXhmGA7qDFvpjy82C0wGQYJKwYBBAGC
# NxQCBAweCgBTAHUAYgBDAEEwHwYDVR0jBBgwFoAUDqyCYEBWJ5flJRP8KuEKU5VZ
# 5KQwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
# aS9jcmwvcHJvZHVjdHMvbWljcm9zb2Z0cm9vdGNlcnQuY3JsMFQGCCsGAQUFBwEB
# BEgwRjBEBggrBgEFBQcwAoY4aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNyb3NvZnRSb290Q2VydC5jcnQwDQYJKoZIhvcNAQEFBQADggIBAFk5
# Pn8mRq/rb0CxMrVq6w4vbqhJ9+tfde1MOy3XQ60L/svpLTGjI8x8UJiAIV2sPS9M
# uqKoVpzjcLu4tPh5tUly9z7qQX/K4QwXaculnCAt+gtQxFbNLeNK0rxw56gNogOl
# VuC4iktX8pVCnPHz7+7jhh80PLhWmvBTI4UqpIIck+KUBx3y4k74jKHK6BOlkU7I
# G9KPcpUqcW2bGvgc8FPWZ8wi/1wdzaKMvSeyeWNWRKJRzfnpo1hW3ZsCRUQvX/Ta
# rtSCMm78pJUT5Otp56miLL7IKxAOZY6Z2/Wi+hImCWU4lPF6H0q70eFW6NB4lhhc
# yTUWX92THUmOLb6tNEQc7hAVGgBd3TVbIc6YxwnuhQ6MT20OE049fClInHLR82zK
# wexwo1eSV32UjaAbSANa98+jZwp0pTbtLS8XyOZyNxL0b7E8Z4L5UrKNMxZlHg6K
# 3RDeZPRvzkbU0xfpecQEtNP7LN8fip6sCvsTJ0Ct5PnhqX9GuwdgR2VgQE6wQuxO
# 7bN2edgKNAltHIAxH+IOVN3lofvlRxCtZJj/UBYufL8FIXrilUEnacOTj5XJjdib
# Ia4NXJzwoq6GaIMMai27dmsAHZat8hZ79haDJLmIz2qoRzEvmtzjcT3XAH5iR9HO
# iMm4GPoOco3Boz2vAkBq/2mbluIQqBC0N1AI1sM9MIIGBzCCA++gAwIBAgIKYRZo
# NAAAAAAAHDANBgkqhkiG9w0BAQUFADBfMRMwEQYKCZImiZPyLGQBGRYDY29tMRkw
# FwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0MS0wKwYDVQQDEyRNaWNyb3NvZnQgUm9v
# dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMDcwNDAzMTI1MzA5WhcNMjEwNDAz
# MTMwMzA5WjB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCfoWyx39tIkip8ay4Z4b3i48WZUSNQrc7dGE4kD+7R
# p9FMrXQwIBHrB9VUlRVJlBtCkq6YXDAm2gBr6Hu97IkHD/cOBJjwicwfyzMkh53y
# 9GccLPx754gd6udOo6HBI1PKjfpFzwnQXq/QsEIEovmmbJNn1yjcRlOwhtDlKEYu
# J6yGT1VSDOQDLPtqkJAwbofzWTCd+n7Wl7PoIZd++NIT8wi3U21StEWQn0gASkdm
# EScpZqiX5NMGgUqi+YSnEUcUCYKfhO1VeP4Bmh1QCIUAEDBG7bfeI0a7xC1Un68e
# eEExd8yb3zuDk6FhArUdDbH895uyAc4iS1T/+QXDwiALAgMBAAGjggGrMIIBpzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQjNPjZUkZwCu1A+3b7syuwwzWzDzAL
# BgNVHQ8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwgZgGA1UdIwSBkDCBjYAUDqyC
# YEBWJ5flJRP8KuEKU5VZ5KShY6RhMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
# BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eYIQea0WoUqgpa1Mc1j0BxMuZTBQBgNVHR8E
# STBHMEWgQ6BBhj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9k
# dWN0cy9taWNyb3NvZnRyb290Y2VydC5jcmwwVAYIKwYBBQUHAQEESDBGMEQGCCsG
# AQUFBzAChjhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFJvb3RDZXJ0LmNydDATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0B
# AQUFAAOCAgEAEJeKw1wDRDbd6bStd9vOeVFNAbEudHFbbQwTq86+e4+4LtQSooxt
# YrhXAstOIBNQmd16QOJXu69YmhzhHQGGrLt48ovQ7DsB7uK+jwoFyI1I4vBTFd1P
# q5Lk541q1YDB5pTyBi+FA+mRKiQicPv2/OR4mS4N9wficLwYTp2OawpylbihOZxn
# LcVRDupiXD8WmIsgP+IHGjL5zDFKdjE9K3ILyOpwPf+FChPfwgphjvDXuBfrTot/
# xTUrXqO/67x9C0J71FNyIe4wyrt4ZVxbARcKFA7S2hSY9Ty5ZlizLS/n+YWGzFFW
# 6J1wlGysOUzU9nm/qhh6YinvopspNAZ3GmLJPR5tH4LwC8csu89Ds+X57H2146So
# dDW4TsVxIxImdgs8UoxxWkZDFLyzs7BNZ8ifQv+AeSGAnhUwZuhCEl4ayJ4iIdBD
# 6Svpu/RIzCzU2DKATCYqSCRfWupW76bemZ3KOm+9gSd0BhHudiG/m4LBJ1S2sWo9
# iaF2YbRuoROmv6pH8BJv/YoybLL+31HIjCPJZr2dHYcSZAI9La9Zj7jkIeW1sMpj
# tHhUBdRBLlCslLCleKuzoJZ1GtmShxN1Ii8yqAhuoFuMJb+g74TKIdbrHk/Jmu5J
# 4PcBZW+JC33Iacjmbuqnl84xKf8OxVtc2E0bodj6L54/LlUWa8kTo/0xggSxMIIE
# rQIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSMw
# IQYDVQQDExpNaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQQITMwAAAUCWqe5wVv7M
# BwABAAABQDAJBgUrDgMCGgUAoIHKMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSw
# V8pAlzCxTTMPRUgbm+0hbUqr8jBqBgorBgEEAYI3AgEMMVwwWqA8gDoATQBpAGMA
# cgBvAHMAbwBmAHQAIABBAHoAdQByAGUAIABTAGkAdABlACAAUgBlAGMAbwB2AGUA
# cgB5oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASC
# AQDMEVSaaVEdHeq28Ikj2nr1ZAtVO3q2grFoLRG5st6jemIS/hwcA2Ai7mPkgOiF
# Gq177HJl1dNvYWJteFEhYiPM9vYb85Jzf0k3VsQJ5STf4g2gHlFOdGgqtH31E922
# q3azXZy+QjxwBwPk9wTjt9g+/JOSGUT+gG63vYgNB9GM5n9/mrbkC2GZvn1x2MXr
# +eydd0BxemVNc+mPnoRnxSJGo/VCvvbbQ+V6jU2n5uiXR5E3OY8KnUCGtq1ziPmW
# qGDmo3H5xSQgLJxqRZb4cT5w+kv7rJjmgjSHI8/jUnzes3ErW8Yxk5/7mkmXFSiY
# q2g4m8Rn+OpI094zU+1DEHU4oYICKDCCAiQGCSqGSIb3DQEJBjGCAhUwggIRAgEB
# MIGOMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAfBgNV
# BAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQQITMwAAAMZ4gDYBdRppcgAAAAAA
# xjAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG
# 9w0BCQUxDxcNMTcwNjIzMDgwNDIyWjAjBgkqhkiG9w0BCQQxFgQUIUZlv5eKJtoL
# ur9z+WAjPlG8NFIwDQYJKoZIhvcNAQEFBQAEggEAC0QROytk43SAd9QiBSKT7TdR
# KyelqY4Y0SCPu2q013KBRag8/lN6/aMu1PVO9Yuyh1Lk/22ALF2MKnMUZZfHDFrx
# X0hTkYcIXsvPYU+c0mXd5Go7dMPbhHplyFbUxx7eMm9B0ouS0gnEjAoUqWZ9MC+R
# JNDuCZq3QUwMrHBwDdHgBY1x8iSYI4cEBOuF8ynDdHor5Ni33lSj9rZ2A2+oPTW3
# beuxDT9l/pukoehFgwRoafnk/TUtn54+2pJ4FWszAkmjsSdUkO/sfqLqJj4lzpu9
# OBcQzRhc9dMIl09d0kVI8kTPChu6+acJWm1YzggpqjMSM9LkKVqwkN/SIC2f8g==
# SIG # End signature block
