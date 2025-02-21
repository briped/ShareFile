function Get-User {
	# https://api.sharefile.com/docs/resource?name=Users#Get_User
	[CmdletBinding(DefaultParameterSetName = 'Id')]
	param (
		# User ID to lookup
		[Parameter(ParameterSetName = 'Id'
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
		,
		# User email address to lookup
		[Parameter(ParameterSetName = 'Email')]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('^[\w-\.]+@([a-z0-9-]+\.)+[a-z0-9-]{2,4}$')]
		[string]
		$Email
	)
	begin {
		$Script:Token = Get-Token
		$Header = @{
			Authorization = "Bearer $($Script:Token.access_token)"
		}
	}
	process {
		$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users"
		if ($Id) {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting user by ID: $($Id)"
			$Uri += "($($Id))"
		}
		elseif ($PSCmdlet.ParameterSetName -eq 'Email') {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting user by email: $($Email)"
			$Uri += "?emailaddress=$($Email)"
		}
		else {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting current user."
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
}
