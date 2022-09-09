<#  
   ___        __  ___  __     _            _     
  / _ \      /__\/   \/__\   /_\  _ __ ___| |__  
 / /_)/____ /_\ / /\ / \//  //_\\| '__/ __| '_ \ 
/ ___/_____//__/ /_// _  \ /  _  \ | | (__| | | |
\/         \__/___,'\/ \_/ \_/ \_/_|  \___|_| |_|
									 ooo,    .____.								
									 o`  o   /    |\________________			
								   o`    'oooo()  | ________   _   _)				
									`oo   o` \    |/        | | | |				
									   ooo'   `____'         "-"|_|
									   
											By: Fco Javier Pérez
	
	Available features:

	-Kill process
	-Kill parent process and processes depending of it
	-YARA rules analysis for file content
	-Stop network connections
	-Add firewall rules
	-Shutdown system
	-Desktop notification for endpoint user
	-Terminate injected threads
	-Remove file after YARA detection
	-System dis/isolation
	-RAM dumping from process
	-Based on MITRE ATT&CK for alerting

#>
<# Import tools and modules #>

$yararules = "C:\ProgramData\edr\YARA_RULES\index.yar"
$procdump = "C:\ProgramData\edr\procdump64.exe"
$yaraexe = "C:\ProgramData\edr\yara64.exe"
$dumpsfolder = "C:\ProgramData\edr\dumps\"
$movedumps = "C:\ProgramData\edr\*.dmp"
Import-Module C:\ProgramData\edr\Invoke-DropNet.ps1
Import-Module C:\ProgramData\edr\Stop-Thread.ps1
Import-Module C:\ProgramData\edr\Invoke-Isolate.ps1
Import-Module C:\ProgramData\edr\Invoke-Disolate.ps1

<# Active response feature starting #>

$notification = "An anomaly was detected in the events of your system. A report was sent to the SOC team with the details. Report them ASAP via socteam@corporation.com"
Register-WmiEvent -Query "Select * From __InstanceCreationEvent Where TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.LogFile='Microsoft-Windows-Sysmon/Operational' AND TargetInstance.Message Like '%Alert%'" -SourceIdentifier "Sysmon"

Write-Host "[+] Starting P-EDR Arch"

<# Event filtering #>

Try{
	While ($True) {
		$NewEvent = Wait-Event -SourceIdentifier Sysmon
		$Log = $NewEvent.SourceEventArgs.NewEvent.TargetInstance
		$LogName  = $Log.LogFile
		$SourceName   = $Log.SourceName
        $Category = $Log.CategoryString
		$EventID  = $Log.EventCode
		$Time = $Log.TimeGenerated
		$Year =  $Time.SubString(0, 4)
		$Month = $Time.SubString(4, 2)
		$Day =  $Time.SubString(6, 2)
		$Hour = $Time.SubString(8, 2)
		$Minutes =  $Time.SubString(10, 2)
		$Date = $Year + "/" + $Month + "/" + $Day + " " + $Hour + ":" + $Minutes
		$Date = (([DateTime]$Date)).AddHours(9).ToString("yyyy/MM/dd HH:mm:ss")
		$Message = $Log.Message
		#
        #Process Create Event Detection and Response
		if($EventID -eq 1)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 1
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$FileVersion = $sysmon."FileVersion"
			$Description = $sysmon."Description"
			$Product = $sysmon."Product"
			$Company = $sysmon."Company"
			$OriginalFileName = $sysmon."OriginalFileName"
			$CommandLine = $sysmon."CommandLine"
			$CurrentDirectory = $sysmon."CurrentDirectory"
			$User = $sysmon."User"
			$LogonGuid = $sysmon."LogonGuid"
			$LogonId = $sysmon."LogonId"
			$TerminalSessionId = $sysmon."TerminalSessionId"
			$Hashes = $sysmon."Hashes"
			$Hashes2 = $Hashes -split ','
			$Hashtable = $Hashes2 | ConvertFrom-StringData
			$MD5 = $Hashtable."MD5"
			$SHA256 = $Hashtable."SHA256"
			$IMPHASH = $Hashtable."IMPHASH"
			$ParentProcessId = $sysmon."ParentProcessId"
			$ParentImage = $sysmon."ParentImage"
			$ParentCommandLine = $sysmon."ParentCommandLine"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
                Write-Host "[+] Alert: $Alert User: $User Executed $CommandLine within $CurrentDirectory from $ParentImage at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + " User: $User Executed $CommandLine within $CurrentDirectory from $ParentImage at $UtcTime" + "`n" + "$notification"
                $message | msg *
                
				# Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Parent Process Killer
				if($msg[1].ToLower().Contains("kpp=y")){
					Write-Host "[+] Killing: $ParentProcessId"
					taskkill /F /T /PID $ParentProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Firewall Process
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId"
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = $yaraexe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
		#
        #A process changed a file creation time
		if($EventID -eq 2)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 2
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$TargetFileName = $sysmon."TargetFileName"
			$CreationUtcTime = ([DateTime]$sysmon."CreationUtcTime").toLocalTime()
			$PreviousCreationUtcTime = ([DateTime]$sysmon."PreviousCreationUtcTime").toLocalTime()
			$User = $sysmon."User"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
                Write-Host "[+] Alert: $Alert User: $User Changed File Creation Time From $TargetFilename From $PreviousCreationUtcTime to $CreationUtcTime Using $Image ($ProcessId) at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + " User: $User Changed File Creation Time ($PreviousCreationUtcTime to $CreationUtcTime) From $TargetFileName Using $Image ($ProcessId) at $UtcTime" + "`n" + "$notification"
                $message | msg *

				# Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Firewall Process
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = $yaraexe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
        #Network Connect Event Detection and Response
		if($EventID -eq 3)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			#
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 3 
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$User = $sysmon."User"
			$Protocol = $sysmon."Protocol"
			$Initiated = $sysmon."Initiated"
			$SourceIsIpv6 = $sysmon."SourceIsIpv6"
			$SourceIp = $sysmon."SourceIp"
			$SourceHostname = $sysmon."SourceHostname"
			$SourcePort = $sysmon."SourcePort"
			$SourcePortName = $sysmon."SourcePortName"
			$DestinationIsIpv6 = $sysmon."DestinationIsIpv6"
			$DestinationIp = $sysmon."DestinationIp"
			$DestinationHostname = $sysmon."DestinationHostname"
			$DestinationPort = $sysmon."DestinationPort"
			$DestinationPortName = $sysmon."DestinationPortName"
			#
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
                Write-Host "[+] Alert: $Alert"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" +"User: $User Initiated network connection with $Image to IP: $DestinationIp Host: $DestinationHostname" + "`n" +"$notification"
                $message | msg *

				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Connection Killer
				if($msg[1].ToLower().Contains("kc=y")){
					Write-Host "[+] Killing connection to: $DestinationIp"
					Invoke-DropNet -ProcessID $ProcessId
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = $yaraexe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
            }
            else {
            }
        }
		#Process Terminated
		if($EventID -eq 5)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			#
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 5 
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$User = $sysmon."User"
			#
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
                Write-Host "[+] Alert: $Alert $User Terminated Critical Process $Image with PID $ProcessId at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" +"User: $User Terminated Critical Process $Image with PID $ProcessId at $UtcTime" + "`n" +"$notification"
                $message | msg *

				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] Shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
            }
            else {
            }
        }
		#Image Loaded
		if($EventID -eq 7)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 7
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$ImageLoaded = $sysmon."ImageLoaded"
			$FileVersion = $sysmon."FileVersion"
			$Description = $sysmon."Description"
			$Product = $sysmon."Product"
			$Company = $sysmon."Company"
			$OriginalFileName = $sysmon."OriginalFileName"
			$Hashes = $sysmon."Hashes"
			$Signed = $sysmon."Signed"
			$Signature = $sysmon."Signature"
			$SignatureStatus = $sysmon."SignatureStatus"
			$User = $sysmon."User"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert User: $User Loaded Image $ImageLoaded ($Description) Using $Image with PID $ProcessId at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + " $Alert Process in: $Image ($ProcessId) Loaded $ImageLoaded ($Description) at $UtcTime" + "`n" + "$notification"
                $message | msg *

				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] Shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $ImageLoaded in" protocol=tcp dir=in enable=yes action=block profile=any program="$ImageLoaded"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $ImageLoaded out" protocol=tcp dir=out enable=yes action=block profile=any program="$ImageLoaded"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $ImageLoaded with Yara..."
					$result = $yaraexe -c $yararules "$ImageLoaded"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $ImageLoaded as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $ImageLoaded"
						Remove-Item -Path "$ImageLoaded" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
        #Remote Thread Events
		if($EventID -eq 8)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 8
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$SourceProcessGuid = $sysmon."SourceProcessGuid"
			$SourceProcessId = $sysmon."SourceProcessId"
			$SourceImage = $sysmon."SourceImage"
			$TargetProcessGuid = $sysmon."TargetProcessGuid"
			$TargetProcessId = $sysmon."TargetProcessId"
			$TargetImage = $sysmon."TargetImage"
			$NewThreadId = $sysmon."NewThreadId"
			$StartModule = $sysmon."StartModule"
			$StartFunction = $sysmon."StartFunction"
			$SourceUser = $sysmon."SourceUser"
			$TargetUser = $sysmon."TargetUser"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert Process: $SourceImage Created Remote Thread within $TargetImage with Function $StartFunction from Thread ID: $NewThreadId at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + " $Alert Process: $SourceImage Created Remote Thread within $TargetImage with Function $StartFunction from Thread ID: $NewThreadId at $UtcTime" + "`n" + "$notification"
                $message | msg *

				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $SourceProcessId"
					taskkill /F /T /PID $SourceProcessId
				}
				#Injected Thread Killer
				if($msg[1].ToLower().Contains("ki=y")){
					Write-Host "[+] Killing Remote Thread: $NewThreadId"
					Stop-Thread -ThreadID $NewThreadId
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $SourceImage from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $SourceImage in" protocol=tcp dir=in enable=yes action=block profile=any program="$SourceImage"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $SourceImage out" protocol=tcp dir=out enable=yes action=block profile=any program="$SourceImage"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $SourceImage with Yara..."
					$result = $yaraexe -c $yararules "$SourceImage"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $SourceImage as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $SourceImage"
						Remove-Item -Path "$SourceImage" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
		#Remote Thread Events
		if($EventID -eq 9)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 9
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$Device = $sysmon."Device"
			$User = $sysmon."User"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert User: $User Used $Image with PID $ProcessId with objective $Device at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "User: $User Used $Image with PID $ProcessId with objective $Device at $UtcTime" + "`n" + "$notification"
                $message | msg *

				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] Shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $SourceImage from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$SourceImage"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = $yaraexe -c $yararules "$Image"
					if($result -gt "0"){ 
						Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
						if($msg[1].ToLower().Contains("ydel=y")){
							Write-Host "[+] Deleting file $Image"
							Remove-Item -Path "$Image" -Force
						}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
		if($EventID -eq 10)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 10
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$SourceProcessGUID = $sysmon."SourceProcessGUID"
			$SourceProcessId = $sysmon."SourceProcessId"
			$SourceThreadId = $sysmon."SourceThreadId"
			$SourceImage = $sysmon."SourceImage"
			$TargetProcessGUID = $ysmon."TargetProcessGUID"
			$TargetProcessId = $sysmon."TargetProcessId"
			$TargetImage = $sysmon."TargetImage"
			$GrantedAccess = $sysmon."GrantedAccess"
			$CallTrace = $sysmon."CallTrace"
			$functions = $sysmon."functions"
			$SourceUser = $sysmon."SourceUser"
			$TargetUser = $sysmon."TargetUser"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert User: $SourceUser Used $SourceImage with PID $SourceProcessId with objective $TargetImage with PID $TargetProcessId. CallTrace: ($CallTrace) at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "User: $SourceUser Used $SourceImage with PID $SourceProcessId with objective $TargetImage with PID $TargetProcessId ($CallTrace) at $UtcTime" + "`n" + "$notification"
                $message | msg *
				
				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $SourceProcessId"
					taskkill /F /T /PID $SourceProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] Shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $SourceImage from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $SourceImage in" protocol=tcp dir=in enable=yes action=block profile=any program="$SourceImage"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $SourceImage out" protocol=tcp dir=out enable=yes action=block profile=any program="$SourceImage"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $SourceImage with Yara..."
					$result = $yaraexe -c $yararules "$SourceImage"
					if($result -gt "0"){ 
						Write-Host "[+] Yara detected file $SourceImage as malicious or suspicious..."
						if($msg[1].ToLower().Contains("ydel=y")){
							Write-Host "[+] Deleting file $Image"
							Remove-Item -Path "$SourceImage" -Force
						}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
        #File Create Event Detection and Response
		if($EventID -eq 11)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 11
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$TargetFilename = $sysmon."TargetFilename"
			$CreationUtcTime = $sysmon."CreationUtcTime"
			$User = $sysmon."User"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] User: $User Alert: $Alert Process: $Image Created $TargetFilename with Process ID: $ProcessId at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "User: $User executed Process: $Image Creating $TargetFilename with Process ID: $ProcessId at $UtcTime" + "`n" + "$notification"
                $message | msg *
				
				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] Shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $TargetFilename with Yara..."
					$result = $yaraexe -c $yararules "$TargetFilename"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $TargetFilename as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $TargetFilename"
						Remove-Item -Path "$TargetFilename" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
		#Registry Items
		if($EventID -eq 12)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 12
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$EventType = $sysmon."EventType"
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$TargetObject = $sysmon."TargetObject"
			$User = $sysmon."User"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert User: $User Process: $Image Created Registry Item $TargetObject from Process ID: $ProcessId at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "User: $User Process: $Image Created $TargetFilename with Process ID: $ProcessId at $UtcTime" + "`n" + "$notification"
                $message | msg *

				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $Image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = $yaraexe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
        #Registry Items
		if($EventID -eq 13)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 13
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$TargetObject = $sysmon."TargetObject"
			$EventType = $sysmon."EventType"
			$Details = $sysmon."Details"
			$User = $sysmon."User"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert User: $User Process: $Image Created Registry Item $TargetObject with details: $Details from Process ID: $ProcessId at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "User: $User Process: $Image Created $TargetFilename with Process ID: $ProcessId at $UtcTime" + "`n" + "$notification"
                $message | msg *
				
				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = $yaraexe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
		#Registry Key and Value Rename
		if($EventID -eq 14)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 14
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$TargetObject = $sysmon."TargetObject"
			$EventType = $sysmon."EventType"
			$NewName = $sysmon."NewName"
			$User = $sysmon."User"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert User: $User Process: $Image Modified Registry Item $TargetObject with name: $NewName from Process ID: $ProcessId at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "User: $User Process: $Image Modified $TargetFilename with name $NewName and Process ID: $ProcessId at $UtcTime" + "`n" + "$notification"
                $message | msg *

				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = $yaraexe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
		#Registry Key and Value Rename
		if($EventID -eq 15)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			#
            #Debug $Message uncomment to remove
            #foreach($i in $msg){Write-Host $i}
			#
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 15
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$TargetFilename = $sysmon."TargetFilename"
			$CreationUtcTime = $sysmon."CreationUtcTime"
			$Hash = $sysmon."Hash"
			$User = $sysmon."User"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert User: $User Process: $Image ($ProcessId) Created Stream Hash as $TargetFilename ($Hash - $CreationUtcTime) at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "User: $User Process: $Image ($ProcessId) Created Stream Hash as $TargetFileName ($Hash) at $CreationUtcTime" + "`n" + "$notification"
                $message | msg *

				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = $yaraexe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
		#PipeEvent-Pipe Created
		if($EventID -eq 17)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 17
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$PipeName = $sysmon."PipeName"
			$EventType = $sysmon."EventType"
			$Image = $sysmon."Image"
			$User = $sysmon."User"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert User: $User Process: $Image ($ProcessId) Created Pipe as $PipeName at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "User: $User Process: $Image ($ProcessId) Created Pipe as $PipeName at $UtcTime" + "`n" + "$notification"
                $message | msg *

				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = $yaraexe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
		#PipeEvent-Pipe Connected
		if($EventID -eq 18)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 18
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$PipeName = $sysmon."PipeName"
			$EventType = $sysmon."EventType"
			$Image = $sysmon."Image"
			$User = $sysmon."User"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert User: $User Process: $Image ($ProcessId) Connected Pipe as $PipeName at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "User: $User Process: $Image ($ProcessId) Connected Pipe as $PipeName at $UtcTime" + "`n" + "$notification"
                $message | msg *

				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = $yaraexe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
		#WMI event (WmiEventFilter activity detected)
		if($EventID -eq 19)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 19
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$EventType = $sysmon."EventType"
			$Operation = $sysmon."Operation"
			$User = $sysmon."User"
			$EventNamespace = $sysmon."EventNamespace"
			$Name = $sysmon."Name"
			$Query = $sysmon."Query"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert User: $User Started $Name of Type $EventType in $EventNamespace with Query $Query at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "User: $User Started $Name of Type $EventType in $EventNamespace with Query $Query at $UtcTime" + "`n" + "$notification"
                $message | msg *

				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
			}
            else {
            }
        }
		#WMIEvent - WmiEventConsumer activity detected (consume)
		if($EventID -eq 20)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 20
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$EventType = $sysmon."EventType"
			$Operation = $sysmon."Operation"
			$User = $sysmon."User"
			$Name = $sysmon."Name"
			$Type = $sysmon."Type"
			$Destination = $sysmon."Destination"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert User: $User Consumed $Name of Type $EventType in $Destination - $Operation at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "User: $User Consumed $Name of Type $EventType in $Destination - $Operation at $UtcTime" + "`n" + "$notification"
                $message | msg *

				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
			}
            else {
            }
        }
		#WMIEvent - WmiEventConsumer activity detected (bind)
		if($EventID -eq 21)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 21
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$EventType = $sysmon."EventType"
			$Operation = $sysmon."Operation"
			$User = $sysmon."User"
			$Consumer = $sysmon."Consumer"
			$Filter = $sysmon."Filter"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert User: $User Binded $Consumer to $Filter at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "User: $User Binded $Consumer to $Filter at $UtcTime" + "`n" + "$notification"
                $message | msg *

				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
			}
            else {
            }
        }
        #DNS Events
		if($EventID -eq 22)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 22
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$QueryName = $sysmon."QueryName"
			$QueryResults = $sysmon."QueryResults"
			$QueryStatus = $sysmon."QueryStatus"
			$User = $sysmon."User"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert User: $User Process: $Image Initiated DNS Request to $QueryName with the results: $QueryResults from Process ID: $ProcessId at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "User: $User Process: $Image Initiated DNS Request to $QueryName with the results: $QueryResults from ProcessID: $ProcessId at $UtcTime" + "`n" + "$notification"
                $message | msg *

				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = $yaraexe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
        #File Delete Events
		if($EventID -eq 23)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 23
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$User = $sysmon."User"
			$Image = $sysmon."Image"
			$TargetFilename = $sysmon."TargetFilename"
			$Hashes = $sysmon."Hashes"
			$IsExecutable = $sysmon."IsExecutable"
			$Archived = $sysmon."Archived"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert Process: $Image Deleted File $TargetFilename ($Hashes) from Process ID: $ProcessId at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "Process: $Image Deleted File $TargetFilename($Hashes) from Process ID: $ProcessId at $UtcTime" + "`n" + "$notification"
                $message | msg *

				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = $yaraexe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
				# File Restore
				if($msg[1].ToLower().Contains("rf=y")){
					$pattern = "(MD5=|\,SHA256=|\,IMPHASH=)"
					$File = $Hashes -replace $pattern
					$TargetFilename -match ".([A-Za-z0-9]+)$"
					$ext = $matches[0]
					$TargetFilename -match "^([a-z]):"
					$drv = $matches[0]
					Write-Host "[+] Restoring: $drv\DeletedFiles\$file$ext to Original Location: $TargetFilename..."
					Move-Item -Path "$drv\DeletedFiles\$File$ext" -Destination "$TargetFilename" -Force
				}
			}
            else {
            }
        }
		#Clipboard events
		if($EventID -eq 24)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 24
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$Session = $sysmon."Session"
			$ClientInfo = $sysmon."ClientInfo"
			$Hashes = $sysmon."Hashes"
			$Archived = $sysmon."Archived"
			$User = $sysmon."User"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert User: $User Process: $Image with PID ($ProcessId) copied to clipboard ($Hash) at $UtcTime. RDP host: $ClientInfo"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "User: $User Process: $Image with PID ($ProcessId) copied to clipboard ($Hash) at $UtcTime. Rdp Host: $ClientInfo" + "`n" + "$notification"
                $message | msg *
				
				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = $yaraexe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
		#Process Tampering
		if($EventID -eq 25)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 25
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$User = $sysmon."User"
			$Image = $sysmon."Image"
			$Type = $sysmon."Type"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert Process: $Image with PID $ProcessId $Type at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "Process: $Image with PID $ProcessId $Type at $UtcTime" + "`n" + "$notification"
                $message | msg *

				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = $yaraexe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
		#File Delete Events
		if($EventID -eq 26)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select-Object -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 26
			$UtcTime = ([DateTime]$sysmon."UtcTime").toLocalTime()
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$User = $sysmon."User"
			$Image = $sysmon."Image"
			$TargetFilename = $sysmon."TargetFilename"
			$Hashes = $sysmon."Hashes"
			$IsExecutable = $sysmon."IsExecutable"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert Process: $Image with PID $ProcessId Deleted $TargetFilename ($Hashes) at $UtcTime"
                $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + "Process: $Image with PID $ProcessId Deleted $TargetFilename ($Hashes) at $UtcTime" + "`n" + "$notification"
                $message | msg *

				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				#System isolation
				if($msg[1].toLower().Contains("si=y")){
					Write-Host "[+] Isolating system. Please, don't power off the computer..."
					Invoke-Isolate
				}
				#RAM dump process
				if($msg[1].toLower().Contains("dp=yes")){
					Write-Host "[+] Dumping full memory process to EDR folder..."
					Start-Process -FilePath $procdump -ArgumentList "-ma $ProcessId" 
					Move-Item -Path $movedumps -Destination $dumpsfolder
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = $yaraexe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
        Remove-Event Sysmon
	}
Catch{
	Write-Warning "Error"
	Write-Output "$Date" $Error[0]| Out-file "C:\ProgramData\edr\errorlog.txt" -append
    $Error[0] }
}Finally{
    Get-Event | Remove-Event 
    Get-EventSubscriber | Unregister-Event 
}