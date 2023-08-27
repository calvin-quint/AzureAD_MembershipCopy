############################################################################
#    Email   = "github@myqnet.io"                                          #
#    GitHub  = "https://github.com/1yv0s"                                  #
#    Version = "1.0"                                                       #
#    Prerequisite   : AzureAD and Exchange Online PowerShell modules       #
#    License: GNU General Public License                                   #
############################################################################

# Define log file path
$logFilePath = "C:\Scripts\Powershell\Logs\AzureAD_MembershipCopy_Log.txt"

# Create log directory if it doesn't exist
$logDirectory = [System.IO.Path]::GetDirectoryName($logFilePath)
if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory
}

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

# Function to get user input
function Get-UserInput {
    param(
        [string]$prompt
    )

    Read-Host $prompt
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

# Main script logic

Write-Log "Starting script execution." "info"

# Prompt for user input
$upn1 = Get-UserInput "Enter the username to copy from"
$upn2 = Get-UserInput "Enter the username to copy to"

# Import the AzureAD module if not already imported
if (-not (Get-Module -Name AzureAD -ListAvailable)) {
    # Check if running with admin rights
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Log "This script requires administrator rights to install the AzureAD module. Please run the script as an administrator." "error"
        exit
    }

    Write-Log "Installing AzureAD module..." "info"
    Install-Module -Name AzureAD -Force
}
Import-Module AzureAD -ErrorAction Stop

# Import the Exchange Online module if not already imported
if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    # Check if running with admin rights
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Log "This script requires administrator rights to install the Exchange Online module. Please run the script as an administrator." "error"
        exit
    }

    Write-Log "Installing Exchange Online module..." "info"
    Install-Module -Name ExchangeOnlineManagement -Force
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

# Connect to Azure AD
Connect-AzureAD

# Get both users' ObjectIds
$user1 = Get-AzureADUser -Filter "UserPrincipalName eq '$upn1'"
$user2 = Get-AzureADUser -Filter "UserPrincipalName eq '$upn2'"

# Check if both users were found
if ($user1 -eq $null) {
    Write-Log "User '$upn1' not found." "error"
} elseif ($user2 -eq $null) {
    Write-Log "User '$upn2' not found." "error"
} else {
    $user1ObjectId = $user1.ObjectId
    $user2ObjectId = $user2.ObjectId

    # Get all groups that both users are members of (filtering out distribution groups)
    $user1Groups = Get-AzureADUserMembership -ObjectId $user1ObjectId | Where-Object { $_.ObjectType -eq "Group" -and $_.SecurityEnabled -eq $true }
    $user2Groups = Get-AzureADUserMembership -ObjectId $user2ObjectId | Where-Object { $_.ObjectType -eq "Group" -and $_.SecurityEnabled -eq $true }

    foreach ($group1 in $user1Groups) {
        $group1Details = Get-AzureADGroup -ObjectId $group1.ObjectId
        $groupId = $group1Details.ObjectId

        # Check if $upn2 is already a member of the Azure AD group $upn1 is a member of
        if ($user2Groups.ObjectId -contains $groupId) {
            Write-Log "$upn2 is already a member of Azure AD group $($group1Details.DisplayName) (ObjectId: $groupId)." "info"
        } else {
            Add-UserToGroup -userObjectId $user2ObjectId -groupObjectId $groupId -userUpn $upn2 -groupName $group1Details.DisplayName
        }
    }

    Write-Log "$upn2 has been added to Azure AD groups that $upn1 is a member of." "info"

    # Connect to Exchange Online
    Connect-ExchangeOnline 

    # Get the distribution groups that $upn1 is a member of
    $groups = Get-DistributionGroup -ResultSize Unlimited | Where-Object { Get-DistributionGroupMember $_ | Where-Object { $_.PrimarySmtpAddress -eq $upn1 } }

    foreach ($group in $groups) {
        $groupDisplayName = $group.DisplayName

        # Check if $upn2 is already a member of the distribution group
        $isMember = Get-DistributionGroupMember -Identity $groupDisplayName | Where-Object { $_.PrimarySmtpAddress -eq $upn2 }

        if ($isMember) {
            Write-Log "User $upn2 is already a member of $groupDisplayName" "info"
        } else {
            Add-DistributionGroupMember -Identity $groupDisplayName -Member $upn2 -BypassSecurityGroupManagerCheck
            Write-Log "Added $upn2 to $groupDisplayName" "info"
        }
    }

    # Disconnect from Exchange Online
    Disconnect-ExchangeOnline -Confirm:$false
}

Write-Log "Script execution completed." "info"
