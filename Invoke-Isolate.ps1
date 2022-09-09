<# Isolate Host #>

function Invoke-Isolate {

	$AllowedHosts = "google.com", '192.168.63.3'

	Write-Host "Checking all IPs for hosts"

	$ConvertedHosts = foreach ($Remotehost in $AllowedHosts) {
		$IsIp = ($RemoteHost -as [ipaddress]) -as [bool]
		if ($IsIp) {
			$ipList = $Remotehost
		}
		else {
			$IPList = (Resolve-DnsName $Remotehost).ip4address
		}
		Foreach ($IP in $IPList) {
			[PSCustomObject]@{
				Hostname = $Remotehost
				IP = $IP
			}
		}
	}


	Write-Host "Checking if Windows firewall is enabled" -ForegroundColor Green
	$WindowsFirewall = Get-NetFirewallProfile | Where-Object { $_.Enabled -ne $false }

	if (!$WindowsFirewall) {
		Write-Host "Windows firewall is enabled. Moving onto next task" -ForegroundColor Green
	}
	else {
		Write-Host "Windows Firewall is not enabled. Enabling for extra isolation" -ForegroundColor Yellow
		$WindowsFirewall | Set-NetFirewallProfile -Enabled:True
	}
		
	Write-Host "Preparing Windows Firewall isolation rule" -ForegroundColor Green
	$ExistingRule = Get-NetFirewallRule -DisplayName "ISOLATION: Allowed Hosts" -ErrorAction SilentlyContinue
		
	if ($ExistingRule) {
		Write-Host "Setting existing Windows Firewall isolation rule" -ForegroundColor Green
		Get-NetFirewallRule -Direction Outbound | Set-NetFirewallRule -Enabled:False
		Set-NetFirewallRule -Direction Outbound -Enabled:True -Action Allow -RemoteAddress $ConvertedHosts.IP -DisplayName "ISOLATION: Allowed Hosts"
		Get-NetFirewallProfile | Set-NetFirewallProfile -DefaultOutboundAction Block
	}
	else {
		Write-Host "Creating Firewall isolation rule" -ForegroundColor Green
		Get-NetFirewallRule -Direction Outbound | Set-NetFirewallRule -Enabled:False
		New-NetFirewallRule -Direction Outbound -Enabled:True -Action Allow -RemoteAddress $ConvertedHosts.IP -DisplayName "ISOLATION: Allowed Hosts"
		Get-NetFirewallProfile | Set-NetFirewallProfile -DefaultOutboundAction Block
	}

	Write-Host "Adding list of hostnames to host file" -ForegroundColor Green

	foreach ($HostEntry in $ConvertedHosts) {
		Add-Content -Path "$($ENV:windir)/system32/drivers/etc/hosts" -Value "`n$($HostEntry.IP)`t`t$($HostEntry.Hostname)"
		Start-Sleep -Milliseconds 200
	}

	Write-Host 'Setting DNS to a static server that does not exist' -ForegroundColor Green
	Get-DnsClientServerAddress | Set-DnsClientServerAddress -ServerAddresses 127.0.0.127
	Write-Host "Clearing DNS cache" -ForegroundColor Green
	Clear-DnsClientCache

	Write-Host 'Isolation performed. Please, contact with the SOC team ASAP.' -ForegroundColor Green
}