function Revoke-Employee {
	# https://api.sharefile.com/docs/resource?name=Users#Downgrade_multiple_employee_users_to_clients
	[CmdletBinding(DefaultParameterSetName = 'ReassignAll'
				,  SupportsShouldProcess = $true
				,  ConfirmImpact = 'High')]
	param (
		# GUID of the user to have employee status revoked.
		[Parameter(Mandatory = $true
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string[]]
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
		# Force revoke. Don't ask for confirmation unless explicitly specified.
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
		if ($ReassignTo) {
			$ReassignToUser = Get-User -Id $ReassignTo
			if (!$ReassignToUser) {
				throw 'ReassignTo user does not exist.'
			}
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Reassigning to: '$($ReassignToUser.FullName)' ($($ReassignToUser.Username)) ($($ReassignToUser.Id))."
			$ItemsReassignTo = $ReassignToUser.Id
			$GroupsReassignTo = $ReassignToUser.Id
		}
		if ($ReassignItemsTo) {
			$ReassignItemsToUser = Get-User -Id $ReassignItemsTo
			if (!$ReassignItemsToUser) {
				throw 'ReassignItemsTo user does not exist.'
			}
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Reassigning items to: '$($ReassignItemsToUser.FullName)' ($($ReassignItemsToUser.Username)) ($($ReassignItemsToUser.Id))."
			$ItemsReassignTo = $ReassignItemsToUser.Id
		}
		if ($ReassignGroupsTo) {
			$ReassignGroupsToUser = Get-User -Id $ReassignGroupsTo
			if (!$ReassignGroupsToUser) {
				throw 'ReassignGroupsTo user does not exist.'
			}
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Reassigning groups to: '$($ReassignGroupsToUser.FullName)' ($($ReassignGroupsToUser.Username)) ($($ReassignGroupsToUser.Id))."
			$GroupsReassignTo = $ReassignGroupsToUser.Id
		}
		$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users/Employees/Downgrade"
	}
	process {
		if ($id.Count -gt 1) {
			$UserIds = $Id
			$Message = "Revoking 'Employee' status from $($Id.Count) users."
		}
		else {
			$SfUser = Get-User -Id $Id[0]
			$UserIds = @($SfUser.Id)
			$Message = "Revoking 'Employee' status from user: '$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id))."
		}
		$Data = @{
			UserIds = $UserIds
			ReassignItemsToId = $ItemsReassignTo
			ReassignGRoupsToId = $GroupsReassignTo
		}
		if ($PSCmdlet.ShouldProcess($Message)) {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : $($Message)"
			$Splatter = @{
				ContentType = 'application/json'
				Method = 'POST'
				Uri = $Uri
				Header = $Header
				Body = $Data | ConvertTo-Json -Compress
			}
			if ($Script:Config.Proxy) {
				$Splatter.Proxy = $Script:Config.Proxy
			}
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
			try {
				Invoke-RestMethod @Splatter
			}
			catch {
				$Message = "Failed revoking 'Employee' status from user: '$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id)). Error: $($_)"
				Write-Warning -Message $Message
			}
		}
	}
	end {}
}
