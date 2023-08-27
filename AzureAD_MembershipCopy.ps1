############################################################################
#    Email   = "github@myqnet.io"                                          #
#    GitHub  = "https://github.com/1yv0s"                                  #
#    Version = "1.0"                                                       #
#    Prerequisite   : AzureAD and Exchange Online PowerShell modules       #
#    License: GNU General Public License                                   #
############################################################################

# Define log file path
$logFilePath = "C:\Scripts\Powershell\Logs\AzureAD_MembershipCopy_Log.txt"

# Function to write log messages
function Write-Log {
    param(
        [string]$message,
        [string]$level
    )

    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$level] $message"

    # Display the log message in the console
    Write-Host $logMessage

    # Write the log message to the log file
    $logMessage | Out-File -FilePath $logFilePath -Append
}

# Function to validate email address format
function Validate-EmailAddress {
    param(
        [string]$email
    )

    if ($email -match "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$") {
        return $true
    } else {
        return $false
    }
}

# Function to get user input for email address
function Get-ValidEmailInput {
    param(
        [string]$prompt
    )

    $email = $null
    while (-not (Validate-EmailAddress $email)) {
        $email = Read-Host $prompt
        if (-not (Validate-EmailAddress $email)) {
            Write-Host "Invalid email address format. Please enter a valid email address."
        }
    }
    return $email
}

# Function to install and import a module
function Install-AndImportModule {
    param(
        [string]$moduleName,
        [string]$moduleCheckCommand
    )

    if (-not (Get-Module -Name $moduleName -ListAvailable)) {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if (-not $isAdmin) {
            Write-Log "This script requires administrator rights to install the $moduleName module. Please run the script as an administrator." "error"
            exit
        }

        Write-Log "Installing $moduleName module..." "info"
        Install-Module -Name $moduleName -Force
    }
    Import-Module $moduleName -ErrorAction Stop
}

# Function to connect to Azure AD
function Connect-ToAzureAD {
    Connect-AzureAD
}

# Function to connect to Exchange Online
function Connect-ToExchangeOnline {
    Connect-ExchangeOnline
}

# Function to add user to group
function Add-UserToGroup {
    param(
        [string]$userObjectId,
        [string]$groupObjectId,
        [string]$userUpn,
        [string]$groupName
    )

    try {
        Add-AzureADGroupMember -ObjectId $groupObjectId -RefObjectId $userObjectId -ErrorAction Stop
        Write-Log "Added $userUpn to Azure AD group $groupName (ObjectId: $groupObjectId)" "info"
    } catch {
        Write-Log "Failed to add $userUpn to Azure AD group $groupName (ObjectId: $groupObjectId)" "error"
    }
}

# Function to process group membership
function Process-GroupMembership {
    param(
        [string]$upn1,
        [string]$upn2,
        [string]$user1ObjectId,
        [string]$user2ObjectId,
        [array]$user1Groups,
        [array]$user2Groups
    )

    foreach ($group1 in $user1Groups) {
        $group1Details = Get-AzureADGroup -ObjectId $group1.ObjectId
        $groupId = $group1Details.ObjectId

        if ($user2Groups.ObjectId -contains $groupId) {
            Write-Log "$upn2 is already a member of Azure AD group $($group1Details.DisplayName) (ObjectId: $groupId)." "info"
        } else {
            Add-UserToGroup -userObjectId $user2ObjectId -groupObjectId $groupId -userUpn $upn2 -groupName $group1Details.DisplayName
        }
    }

    Write-Log "$upn2 has been added to Azure AD groups that $upn1 is a member of." "info"
}

# Function to process distribution group membership
function Process-DistributionGroupMembership {
    param(
        [string]$upn1,
        [string]$upn2
    )

    Connect-ToExchangeOnline

    $groups = Get-DistributionGroup -ResultSize Unlimited | Where-Object { Get-DistributionGroupMember $_ | Where-Object { $_.PrimarySmtpAddress -eq $upn1 } }

    foreach ($group in $groups) {
        $groupDisplayName = $group.DisplayName
        $isMember = Get-DistributionGroupMember -Identity $groupDisplayName | Where-Object { $_.PrimarySmtpAddress -eq $upn2 }

        if ($isMember) {
            Write-Log "User $upn2 is already a member of $groupDisplayName" "info"
        } else {
            Add-DistributionGroupMember -Identity $groupDisplayName -Member $upn2 -BypassSecurityGroupManagerCheck
            Write-Log "Added $upn2 to $groupDisplayName" "info"
        }
    }

    Disconnect-ExchangeOnline -Confirm:$false
}

# Main script logic
function Main {
    Write-Log "Starting script execution." "info"

    # Prompt for valid user email input
    $upn1 = Get-ValidEmailInput "Enter the email to copy from (e.g., example@gmail.com)"
    $upn2 = Get-ValidEmailInput "Enter the email to copy to (e.g., example@gmail.com)"

    Install-AndImportModule -moduleName "AzureAD" -moduleCheckCommand "Get-Module -Name AzureAD -ListAvailable"
    Install-AndImportModule -moduleName "ExchangeOnlineManagement" -moduleCheckCommand "Get-Module -Name ExchangeOnlineManagement -ListAvailable"

    Connect-ToAzureAD

    # Get both users' ObjectIds
    $user1 = Get-AzureADUser -Filter "UserPrincipalName eq '$upn1'"
    $user2 = Get-AzureADUser -Filter "UserPrincipalName eq '$upn2'"

    if ($user1 -eq $null) {
        Write-Log "User '$upn1' not found." "error"
    } elseif ($user2 -eq $null) {
        Write-Log "User '$upn2' not found." "error"
    } else {
        $user1ObjectId = $user1.ObjectId
        $user2ObjectId = $user2.ObjectId

        $user1Groups = Get-AzureADUserMembership -ObjectId $user1ObjectId | Where-Object { $_.ObjectType -eq "Group" -and $_.SecurityEnabled -eq $true -and $_.MailEnabled -ne $true }
        $user2Groups = Get-AzureADUserMembership -ObjectId $user2ObjectId | Where-Object { $_.ObjectType -eq "Group" -and $_.SecurityEnabled -eq $true -and $_.MailEnabled -ne $true }

        Process-GroupMembership -upn1 $upn1 -upn2 $upn2 -user1ObjectId $user1ObjectId -user2ObjectId $user2ObjectId -user1Groups $user1Groups -user2Groups $user2Groups
        Process-DistributionGroupMembership -upn1 $upn1 -upn2 $upn2
    }

    Write-Log "Script execution completed." "info"
}

# Execute the main script
Main
