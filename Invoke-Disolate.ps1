<# Disolate host #>

function Invoke-Disolate {

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

	Write-Host "Undoing isolation process." -ForegroundColor Green
	Write-Host "Setting existing Windows Firewall isolation rule to allow traffic" -ForegroundColor Green
	Get-NetFirewallRule -Direction Outbound | Set-NetFirewallRule -Enabled:True
	Remove-NetFirewallRule -DisplayName "ISOLATION: Allowed Hosts" -ErrorAction SilentlyContinue
	Get-NetFirewallProfile | Set-NetFirewallProfile -DefaultOutboundAction Allow

	Write-host "Removing list of hostnames from host file" -ForegroundColor Green

	foreach ($HostEntry in $ConvertedHosts) {
		$HostFile = Get-Content "$($ENV:windir)/system32/drivers/etc/hosts"
		$NewHostFile = $HostFile -replace "`n$($HostEntry.IP)`t`t$($HostEntry.Hostname)", ''
		Set-Content -Path "$($ENV:windir)/system32/drivers/etc/hosts" -Value $NewHostFile
		Start-Sleep -Milliseconds 200
	}

	Write-Host "Clearing DNS cache" -ForegroundColor Green
	Clear-DnsClientCache
	Write-Host "Setting DNS back to DHCP" -ForegroundColor Green
	Get-DnsClientServerAddress | Set-DnsClientServerAddress -ResetServerAddresses
	Write-Host 'Undo Isolation performed.' -ForegroundColor Green
}