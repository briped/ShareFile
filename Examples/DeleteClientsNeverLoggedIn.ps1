# Load ShareFileShell module
$Module = [System.IO.FileInfo](Join-Path -Path $([System.IO.FileInfo]$PSScriptRoot).DirectoryName -ChildPath 'ShareFileShell.psd1')
Import-Module -Force -Name $Module

# Get ShareFile clients
$SfClient = Get-SfClient

# Select the value (array of clients)
$Clients = $SfClient.value

# Filter all that have never logged in, and are created more than 1 year ago
$Filtered = $Clients | Where-Object { $_.LastAnyLogin -lt (Get-Date -Date '1900-01-02') -and $_.CreatedDate -lt (Get-Date).AddYears(-1) }

# Can only delete 100 at a time, so submit batches of up to 100
$Total = $Filtered.Count
$Start = 0
$Limit = 100
$Remaining = $Total - $Start
while ($Remaining -gt 0) {
	$End = if ($Remaining -lt $Limit) { $Start + $Remaining } else { $Start + ($Limit - 1) }
	$Batch = $Filtered[$($Start)..$($End)].Id
	Remove-SfClient -Force -Id $Batch
	$Start += $Limit
	$Remaining = $Total - $End
	Write-Host "Remaining: $($Remaining)"
}
