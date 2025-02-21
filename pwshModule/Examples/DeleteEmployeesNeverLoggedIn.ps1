# Load ShareFileShell module.
$Module = [System.IO.FileInfo](Join-Path -Path $([System.IO.FileInfo]$PSScriptRoot).DirectoryName -ChildPath 'ShareFileShell.psd1')
Import-Module -Force -Name $Module

# Get the ID of the user any items or groups should be reassigned to. No aarguments means the user ths script is running as.
$ReassignTo = (Get-SfUser).Id

# Get ShareFile employees.
$SfEmployee = Get-SfEmployee

# Select the value (array of employees).
$Employees = $SfEmployee.value

# Filter all that have never logged in.
$Filtered = $Employees | Where-Object { $_.LastAnyLogin -lt (Get-Date -Date '1900-01-02') }

# Pass the filtered users to the Remove-SfUser Cmdlet.
$Filtered | Remove-SfUser -Completely -Force -ReassignTo $ReassignTo