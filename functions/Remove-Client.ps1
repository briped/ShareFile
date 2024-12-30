function Remove-Client {
	# https://api.sharefile.com/docs/resource?name=Users#Delete_multiple_client_users
	[CmdletBinding(SupportsShouldProcess = $true
				,  ConfirmImpact = 'High')]
	param (
		# GUID of the client to be deleted.
		[Parameter(Mandatory = $true
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string[]]
		$Id
		,
		# Force remove. Don't ask for confirmation unless explicitly specified.
		[Parameter()]
		[switch]
		$Force
	)
	begin {
		$Script:Token = Get-Token
		if ($Force -and !$Confirm) {
			$ConfirmPreference = 'None'
		}
		$Header = @{
			Authorization = "Bearer $($Script:Token.access_token)"
		}
	}
	process {
		if ($id.Count -gt 1) {
			$UserIds = $Id
			$Message = "Removing $($Id.Count) clients."
		}
		else {
			$SfUser = Get-User -Id $Id[0]
			$UserIds = @($SfUser.Id)
			$Message = "Removing 'Client': '$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id))."
		}
		$Splatter = @{
			ContentType = 'application/json'
			Header = $Header
			Method = 'DELETE'
			Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users/Clients"
			Body = $UserIds | ConvertTo-Json -AsArray -Compress
			#Method = 'POST'
			#Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users/Clients/BulkDelete"
			#Body = @{UserIds = $UserIds} | ConvertTo-Json -Compress
		}
		if ($Script:Config.Proxy) {
			$Splatter.Proxy = $Script:Config.Proxy
		}
	
		if ($PSCmdlet.ShouldProcess($Message)) {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : $($Message)"
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
			Invoke-RestMethod @Splatter
		}
	}
}
