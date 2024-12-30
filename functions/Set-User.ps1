function Set-User {
	# https://api.sharefile.com/docs/resource?name=Users#Update_User
	[CmdletBinding()]
	param (
		# User ID to update
		[Parameter(Mandatory = $true
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
		,
		[Parameter()]
		[ValidatePattern('^[\w-\.]+@([a-z0-9-]+\.)+[a-z0-9-]{2,4}$')]
		[ValidateNotNullOrEmpty()]
		[string]
		$Email
		,
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]
		$Username
	)
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users($Id)"
	$Data = @{
		Email = $Email
		Username = $Username
	}
	$Splatter = @{
		ContentType = 'application/json'
		Method = 'PATCH'
		Uri = $Uri
		Header = $Header
		Body = $Data | ConvertTo-Json -Compress
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-RestMethod @Splatter
}
