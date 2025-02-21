function Receive-Item {
	# https://api.sharefile.com/docs/resource?name=Items#Download_Item_Content
	[CmdletBinding()]
	param (
		# Item identifier
		[Parameter(Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[string]
		$Id
		,
		# Redirect to download link if set to true (default), or return a DownloadSpecification object if set to false
		[Parameter()]
		[switch]
		$Redirect
		,
		# For folder downloads only, includes old versions of files in the folder in the zip when true, current versions only when false (default)
		[Parameter()]
		[switch]
		$AllVersions
		,
		# For FINRA or other archive enabled account only, Super User can set includeDelete=true to download archived item. The default value of includeDeleted is false
		[Parameter()]
		[switch]
		$Deleted
	)
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Items($($Id))/Download?"
	$Data = @{
		redirect = $Redirect
		includeAllVersions = $AllVersions
		includeDeleted = $Deleted
	}
	$Query = @()
	foreach ($k in $Data.Keys) {
		$Query += "$($k)=$($Data[$k])"
	}
	$Uri += $Query -join '&'
	$Splatter = @{
		ContentType = 'application/json'
		Method = 'GET'
		Uri = $Uri
		Header = $Header
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-WebRequest @Splatter
}
