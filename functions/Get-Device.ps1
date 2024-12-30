function Get-Device {
	# https://api.sharefile.com/docs/resource?name=Devices
	[CmdletBinding()]
	param (
		# Get Device by ID
		[Parameter(Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
		,
		# Get Devices for UserID
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]
		$UserId
	)
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3"
	if ($UserId) {
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting devices for UserID: $($UserId)"
		$Uri += "/User($($UserId))/Devices"
	}
	elseif ($Id) {
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting device by ID: $($Id)"
		$Uri += "/Devices($($Id))"
	}
	else {
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting devices for current user."
		$Uri += "/Devices"
	}
	$Splatter = @{
		ContentType = 'application/json'
		Method = 'GET'
		Uri = $Uri
		Header = $Header
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-RestMethod @Splatter
}
