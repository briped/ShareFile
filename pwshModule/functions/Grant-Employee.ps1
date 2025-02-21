function Grant-Employee {
	# https://api.sharefile.com/docs/resource?name=Users#Update_Employee_or_Promote_Customer
	[CmdletBinding(SupportsShouldProcess = $true
				,  ConfirmImpact = 'Medium')]
	param (
		# GUID of the user to have employee status granted.
		[Parameter(Mandatory = $true
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
		,
		# Force grant. Don't ask for confirmation unless explicitly specified.
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
		$Data = @{
			isEmployee = $true
		}
	}
	process {
		$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users/AccountUser($($Id))"
		$SfUser = Get-User -Id $Id
		if ($PSCmdlet.ShouldProcess("'$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id)).")) {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Granting 'Employee' status to user: '$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id))."
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
	}
	end {}
}
