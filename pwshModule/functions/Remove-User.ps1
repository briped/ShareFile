function Remove-User {
	# https://api.sharefile.com/docs/resource?name=Users#Delete_User
	[CmdletBinding(DefaultParameterSetName = 'ReassignAll'
				,  SupportsShouldProcess = $true
				,  ConfirmImpact = 'High')]
	param (
		# GUID of the user to be deleted.
		[Parameter(Mandatory = $true
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
		,
		# Combined ReassignItemsTo and ReassignGroupsTo. If set, all user item and group records will be reassigned to the user provided.
		[Parameter(ParameterSetName = 'ReassignAll')]
		[string]
		$ReassignTo
		,
		# If set, all user item records will be reassigned to the user provided.
		[Parameter(ParameterSetName = 'Reassign')]
		[string]
		$ReassignItemsTo
		,
		# If set, all user group records will be reassigned to the user provided.
		[Parameter(ParameterSetName = 'Reassign')]
		[string]
		$ReassignGroupsTo
		,
		# If set, all user records will be removed. Otherwise, the user will be disabled, but not removed from the system. A complete removal is not recoverable.
		[Parameter()]
		[switch]
		$Completely
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
		$Data = @{
			completely = $Completely
		}
		if ($ReassignTo) {
			$ReassignUser = Get-User -Id $ReassignTo
			if (!$ReassignUser) {
				throw 'ReassignTo user does not exist.'
			}
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Reassigning to: '$($ReassignUser.FullName)' ($($ReassignUser.Username)) ($($ReassignUser.Id))."
			$Data.itemsReassignTo = $ReassignTo
			$Data.groupsReassignTo = $ReassignTo
		}
	}
	process {
		$Query = @()
		foreach ($k in $Data.Keys) {
			$Query += "$($k)=$($Data[$k])"
		}
		$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users($($Id))?"
		$Uri += $Query -join '&'
		$SfUser = Get-User -Id $Id
		if ($PSCmdlet.ShouldProcess("'$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id)).")) {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Deleting user: '$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id))."
			$Splatter = @{
				ContentType = 'application/json'
				Method = 'DELETE'
				Uri = $Uri
				Header = $Header
			}
			if ($Script:Config.Proxy) {
				$Splatter.Proxy = $Script:Config.Proxy
			}
			try {
				Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
				Invoke-RestMethod @Splatter
			}
			catch {
				Write-Error -Message "$($MyInvocation.MyCommand.Name) : ERROR : Deleting user: '$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id))." + $Error
			}
		}
	}
}
