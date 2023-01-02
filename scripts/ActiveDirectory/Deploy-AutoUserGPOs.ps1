# The below code will deploy a task scehduler to run every 2 hours to apply User GPO Updates.
# The Scheduled Task uses a VBS script to hide any command prompt / PowerShell windows.
# NOTE: This looks for usernames that have the regular express match of 'firstName.lastName', you may want to modify that.
if (-not(Get-ScheduledTask -TaskName 'Auto User GPUpdate' -ErrorAction SilentlyContinue)) {
    $quserResult = quser /server:$env:COMPUTERNAME 2>&1
    $UserIds = ($quserResult | ForEach-Object -Process { $_ -replace '\s{2,}',',' } | ConvertFrom-Csv)
    $UserName = $UserIDs | Where-Object {$_.USERNAME -match '[a-zA-Z].*\.[a-zA-Z].*' -and $_.STATE -eq 'ACTIVE'} `
        | Select-Object -ExpandProperty Username

    if ($null -ne $UserName) {
        $file = 'C:\Windows\RunUserGPO.vbs'
        $Value1 = 'Set objShell = WScript.CreateObject(\""WScript.Shell\"")'
        $Value2 = 'Result = objShell.Run (\""cmd /c echo n | gpupdate /target:user /force\"",0,true)'
        if (-not (Test-Path -Path $File)) { 
            Add-Content -Path $File -Value $Value1 -Force
            Add-Content -Path $File -Value $Value2 -Force
            Add-Content -Path $File -Value 'Wscript.quit(Result)' -Force
        }
        
        Register-ScheduledTask -TaskName 'Auto User GPUpdate' -Trigger (New-ScheduledTaskTrigger -Once -RepetitionInterval `
            (New-TimeSpan -Hours 2) -At (Get-Date)) -Action (New-ScheduledTaskAction -Execute `
            (Get-Command -Name wscript.exe -Erroraction SilentlyContinue).Path -Argument 'C:\Windows\RunUserGPO.vbs /NoLogo') `
            -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -DontStopIfGoingOnBatteries `
            -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 10)) -Principal (New-ScheduledTaskPrincipal -UserId $UserName) `
            -Description 'Testing Remote Scheduled task.'
    } else { 
        Write-Output 'No Active Users exist.'
    }
} else {
    Write-Output 'Task already exists!'
}

# To deploy this code as a one-liner remotely (e.g., through ConnectWise, run the following command:
# Note, There's RegEx for our usernames, which are firstName.lastName. 
<#
powershell.exe -NoLogo -NoProfile -ExecutionPolicy bypass -Command "& {if (-not(Get-ScheduledTask -TaskName 'Auto User GPUpdate' -ErrorAction SilentlyContinue)) {$quserResult = quser /server:$env:COMPUTERNAME 2>&1; $UserIds = ($quserResult | ForEach-Object -Process { $_ -replace '\s{2,}',',' } | ConvertFrom-Csv); $UserName = $UserIDs | Where {$_.USERNAME -match '[a-zA-Z].*\.[a-zA-Z].*' -and $_.STATE -eq 'ACTIVE'} | Select-Object -ExpandProperty Username; if ($null -ne $UserName) {$file = 'C:\Windows\RunUserGPO.vbs'; $Value1 = 'Set objShell = WScript.CreateObject(\""WScript.Shell\"")'; $Value2 = 'Result = objShell.Run (\""cmd /c echo n | gpupdate /target:user /force\"",0,true)'; if (-not (Test-Path -Path $File)) { Add-Content -Path $File -Value $Value1 -Force; Add-Content -Path $File -Value $Value2 -Force; Add-Content -Path $File -Value 'Wscript.quit(Result)' -Force;} Register-ScheduledTask -TaskName 'Auto User GPUpdate' -Trigger (New-ScheduledTaskTrigger -Once -RepetitionInterval (New-TimeSpan -Hours 2) -At (Get-Date)) -Action (New-ScheduledTaskAction -Execute (Get-Command -Name wscript.exe -Erroraction SilentlyContinue).Path -Argument 'C:\Windows\RunUserGPO.vbs /NoLogo') -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 10)) -Principal (New-ScheduledTaskPrincipal -UserId $UserName) -Description 'Testing Remote Scheduled task.'} else { Write-Output 'No Active Users exist.'}} else {Write-Output 'Task already exists!'}}"
#>
