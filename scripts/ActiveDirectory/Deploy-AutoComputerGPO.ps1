if (-not(Get-ScheduledTask -TaskName 'Auto Computer GPUpdate' -ErrorAction SilentlyContinue)) {

    $file = 'C:\Windows\RunComputerGPO.vbs'
    $Value1 = 'Set objShell = WScript.CreateObject(\""WScript.Shell\"")'
    $Value2 = 'Result = objShell.Run (\""cmd /c echo n | gpupdate /target:computer /force\"",0,true)'
    $Value3 = 'Wscript.quit(Result)'
    if (-not (Test-Path -Path $File)) {
        Add-Content -Path $File -Value $Value1 -Force
        Add-Content -Path $File -Value $Value2 -Force
        Add-Content -Path $File -Value $Value3 -Force
    }
    
    Register-ScheduledTask -TaskName 'Auto Computer GPUpdate' -Trigger (New-ScheduledTaskTrigger -Once -RepetitionInterval `
        (New-TimeSpan -Hours 2) -At (Get-Date)) -Action (New-ScheduledTaskAction -Execute `
        (Get-Command -Name wscript.exe -Erroraction SilentlyContinue).Path -Argument 'C:\Windows\RunComputerGPO.vbs /NoLogo') `
        -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -DontStopIfGoingOnBatteries `
        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 10)) -Principal (New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' `
        -LogonType ServiceAccount -Id 'Author' -RunLevel Highest) `
        -Description 'Automatically perform group policy updates for Computers every 2 hours.'
} else {
    Write-Output 'Task already exists!'
}

<#
powershell.exe -NoLogo -NoProfile -ExecutionPolicy bypass -Command "& {if (-not(Get-ScheduledTask -TaskName 'Auto Computer GPUpdate' -ErrorAction SilentlyContinue)) {$file = 'C:\Windows\RunComputerGPO.vbs'; $Value1 = 'Set objShell = WScript.CreateObject(\""WScript.Shell\"")'; $Value2 = 'Result = objShell.Run (\""cmd /c echo n | gpupdate /target:computer /force\"",0,true)'; $Value3 = 'Wscript.quit(Result)'; if (-not (Test-Path -Path $File)) { Add-Content -Path $File -Value $Value1 -Force; Add-Content -Path $File -Value $Value2 -Force; Add-Content -Path $File -Value $Value3 -Force;} Register-ScheduledTask -TaskName 'Auto Computer GPUpdate' -Trigger (New-ScheduledTaskTrigger -Once -RepetitionInterval (New-TimeSpan -Hours 2) -At (Get-Date)) -Action (New-ScheduledTaskAction -Execute (Get-Command -Name wscript.exe -Erroraction SilentlyContinue).Path -Argument 'C:\Windows\RunComputerGPO.vbs /NoLogo') -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 10)) -Principal (New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -Id 'Author' -RunLevel Highest) -Description 'Automatically perform group policy updates for Computers every 2 hours.';} else { Write-Output 'Task already exists!';}}"
#>
