<#   
.NOTES
    File Name      : AzureAD_MembershipCopy.ps1
    Description    : This PowerShell script is designed to automate the copying of user group memberships between two users in Azure Active Directory (Azure AD) and Exchange Online. 
                     The script transfers group memberships from a source user to a destination user, ensuring consistent group access for both users.
    Prerequisite   : AzureAD module and Exchange Online Management module
    Parameters     : Get-UniqueEmailInputs function validationMethod = 0 or 1 depending what validation you want to be used
    License        : GNU GPL
    Github         : https://github.com/calvin-quint/AzureAD_MembershipCopy
    Email          : github@myqnet.io
#>


# Function to check if OneDrive exists
function Test-OneDrive {
    if ($env:OneDrive -ne $null -and $env:OneDrive -ne "") {
        return $true
    } else {
        return $false
    }
}

# Function to get the log directory path
function Get-LogDirectory {
    if (Test-OneDrive) {
        return "$env:OneDrive\Documents\Scripts\Powershell\Logs"
    } else {
        return "$env:USERPROFILE\Documents\Scripts\Powershell\Logs"
    }
}

function Ensure-DirectoryAndLogFile {
    param (
        [string]$directoryPath,
        [string]$logFilePath
    )

    if (-not (Test-Path -Path $directoryPath -PathType Container)) {
        try {
            New-Item -Path $directoryPath -ItemType Directory -Force
            Write-Log "Directory created: $($directoryPath)" "INFO"
        } catch {
            Write-Host "Failed to create directory: $($directoryPath)"
            Write-Host "Error: $_"
            exit 1
        }
    }

    if (-not (Test-Path -Path $logFilePath)) {
        try {
            $null | Out-File -FilePath $logFilePath -Force
            Write-Log "Log file created: $logFilePath" "INFO"
        } catch {
            Write-Host "Failed to create log file: $logFilePath"
            Write-Host "Error: $_"
            exit 1
        }
    }
}


function Write-Log {
    param(
        [string]$message,
        [string]$level
    )

    $logDirectory = Get-LogDirectory
    $logFilePath = "$logDirectory\AzureAD_MembershipCopy_Log.txt"

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$level] $message"

    # Define colors for INFO and ERROR log levels
    $infoColor = "Yellow"
    $errorColor = "Red"

    # Display the log message in the console with the appropriate color
    if ($level -eq "INFO") {
        Write-Host $logMessage -ForegroundColor $infoColor
    } elseif ($level -eq "ERROR") {
        Write-Host $logMessage -ForegroundColor $errorColor
    } else {
        Write-Host $logMessage
    }

    # Ensure the log directory and log file exist using the combined function
    Ensure-DirectoryAndLogFile -directoryPath $logDirectory -logFilePath $logFilePath

    # Append the log message to the log file
    $logMessage | Out-File -FilePath $logFilePath -Append

    # Get the current log file size
    $currentFileSize = (Get-Item $logFilePath).Length

    # Define the maximum log file size (100MB)
    $maxLogSize = 100MB

    # If the current log file size exceeds the maximum, perform log rotation
    if ($currentFileSize -gt $maxLogSize) {
        $linesToKeep = 500  # Define the maximum number of log lines to keep
        $logContent = Get-Content -Path $logFilePath -TotalCount $linesToKeep
        $logContent | Out-File -FilePath $logFilePath -Force
    }
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
            Write-log "Invalid email address format. Please enter a valid email address." "ERROR"
        }
    }
    return $email
}

function IsValidDomain($email, $allowedDomains) {
    $domain = $email.Split('@')[1]
    return $domain -in $allowedDomains
}

function Get-ValidEmailInputWithDomainCheck($message, $allowedDomains) {
    $email = $null

    while ($email -eq $null -or -not (IsValidDomain $email $allowedDomains)) {
        $email = Get-ValidEmailInput $message

        if ($email -eq $null) {
            Write-Log "Email cannot be empty. Please enter a valid email address." "ERROR"
            continue
        }

        if (-not (IsValidDomain $email $allowedDomains)) {
            Write-Log "Invalid domain in email address. Allowed domains are: $($allowedDomains -join ', ')." "ERROR"
        }
    }

    return $email
}

function Get-UniqueEmailInputs {
    param (
        [int]$validationMethod = 1
    )

    if ($validationMethod -eq 0) {
        $upn1 = $null
        $upn2 = $null

        $upn1 = Get-ValidEmailInput "Enter the source username (e.g., user@example.com)"

        while ($upn1 -eq $null) {
            Write-Log "Source username cannot be empty. Please enter a valid username." "ERROR"
            $upn1 = Get-ValidEmailInput "Enter the source username (e.g., user@example.com)"
        }

        $upn2 = Get-ValidEmailInput "Enter the destination username (e.g., user@example.com)"

        while ($upn2 -eq $null) {
            Write-Log "Destination username cannot be empty. Please enter a valid username." "ERROR"
            $upn2 = Get-ValidEmailInput "Enter the destination username (e.g., user@example.com)"
        }

        while ($upn1 -eq $upn2) {
            Write-Log "Source and destination usernames cannot be the same. Please enter different usernames." "ERROR"
            $upn2 = Get-ValidEmailInput "Enter the destination username (e.g., user@example.com)"
        }
    }
    else {
        $allowedDomains = @("op.test.com", "test.com")

        $upn1 = Get-ValidEmailInputWithDomainCheck "Enter the source username (e.g., user@$($allowedDomains[0]) or user@$($allowedDomains[1]))" $allowedDomains
        $upn2 = Get-ValidEmailInputWithDomainCheck "Enter the destination username (e.g., user@$($allowedDomains[0]) or user@$($allowedDomains[1]))" $allowedDomains

        while ($upn1 -eq $upn2) {
            Write-Log "Source and destination usernames cannot be the same. Please enter different usernames." "ERROR"
            $upn2 = Get-ValidEmailInputWithDomainCheck "Enter the destination username (e.g., user@$($allowedDomains[0]) or user@$($allowedDomains[1]))" $allowedDomains
        }
    }

    return $upn1, $upn2
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
            Write-Log "This script requires administrator rights to install the $moduleName module. Please run the script as an administrator." "ERROR"
            exit
        }

        Write-Log "Installing $moduleName module..." "INFO"
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
        Write-Log "Added $userUpn to Azure AD group $groupName" "INFO"
    } catch {
        Write-Log "Failed to add $userUpn to Azure AD group $groupName" "ERROR"
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
            Write-Log "$upn2 is already a member of Azure AD group $($group1Details.DisplayName)" "INFO"
        } else {
            Add-UserToGroup -userObjectId $user2ObjectId -groupObjectId $groupId -userUpn $upn2 -groupName $group1Details.DisplayName
        }
    }

    Write-Log "$upn2 has been added to Azure AD groups that $upn1 is a member of." "INFO"
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
            Write-Log "User $upn2 is already a member of Distribution Group $groupDisplayName" "INFO"
        } else {
            Add-DistributionGroupMember -Identity $groupDisplayName -Member $upn2 -BypassSecurityGroupManagerCheck
            Write-Log "Added $upn2 to Distribution Group $groupDisplayName" "INFO"
        }
    }

   
}

function Process-MailEnableSecurityGroup {
    param(
        [string]$upn1,
        [string]$upn2
    )

   

    $mailenablegroups = Get-DistributionGroup -ResultSize Unlimited | Where-Object { $_.RecipientTypeDetails -eq "MailUniversalSecurityGroup" -and (Get-DistributionGroupMember $_ | Where-Object { $_.PrimarySmtpAddress -eq $upn1 }) }

    foreach ($group in $mailenablegroups) {
        $groupDisplayName = $group.DisplayName
        $isMember = Get-DistributionGroupMember -Identity $groupDisplayName | Where-Object { $_.PrimarySmtpAddress -eq $upn2 }

        if ($isMember) {
            Write-Log "User $upn2 is already a member of Mail Enabled Security Group $groupDisplayName" "INFO"
        } else {
            Add-DistributionGroupMember -Identity $groupDisplayName -Member $upn2 -BypassSecurityGroupManagerCheck
            Write-Log "Added $upn2 to Mail Enabled Security Group $groupDisplayName" "INFO"
        }
    }

   
}

function Process-M365GroupMembership {
    param(
        [string]$upn1,
        [string]$upn2
    )

    $unifiedGroups = Get-UnifiedGroup -ResultSize Unlimited | Where-Object { Get-UnifiedGroupLinks -Identity $_.Id -LinkType Members | Where-Object { $_.PrimarySmtpAddress -eq $upn1 } }

    foreach ($group in $unifiedGroups) {
        $groupId = $group.Id
        $groupDisplayName = $group.DisplayName
        $isMember = Get-UnifiedGroupLinks -Identity $groupId -LinkType Members | Where-Object { $_.PrimarySmtpAddress -eq $upn2 }

        if ($isMember) {
            Write-Log "User $upn2 is already a member of Microsoft 365 Group $groupDisplayName" "INFO"
        } else {
            Add-UnifiedGroupLinks -Identity $groupId -LinkType Members -Links $upn2 -ErrorAction SilentlyContinue
            Write-Log "Added $upn2 to Microsoft 365 Group $groupDisplayName" "INFO"
        }
    }

    Disconnect-ExchangeOnline -Confirm:$false
}



# Main script logic
function Main {
    Write-Log "Starting script execution." "INFO"

    # Prompt for valid user email input
    $upn1, $upn2 = Get-UniqueEmailInputs

    Install-AndImportModule -moduleName "AzureAD" -moduleCheckCommand "Get-Module -Name AzureAD -ListAvailable"
    Install-AndImportModule -moduleName "ExchangeOnlineManagement" -moduleCheckCommand "Get-Module -Name ExchangeOnlineManagement -ListAvailable"

    Connect-ToAzureAD

    # Get both users' ObjectIds
    $user1 = Get-AzureADUser -Filter "UserPrincipalName eq '$upn1'"
    $user2 = Get-AzureADUser -Filter "UserPrincipalName eq '$upn2'"

    if ($user1 -eq $null) {
        Write-Log "User '$upn1' not found." "ERROR"
    } elseif ($user2 -eq $null) {
        Write-Log "User '$upn2' not found." "ERROR"
    } else {
        $user1ObjectId = $user1.ObjectId
        $user2ObjectId = $user2.ObjectId

        $user1Groups = Get-AzureADUserMembership -ObjectId $user1ObjectId | Where-Object { $_.ObjectType -eq "Group" -and $_.SecurityEnabled -eq $true -and $_.MailEnabled -ne $true }
        $user2Groups = Get-AzureADUserMembership -ObjectId $user2ObjectId | Where-Object { $_.ObjectType -eq "Group" -and $_.SecurityEnabled -eq $true -and $_.MailEnabled -ne $true }

        Process-GroupMembership -upn1 $upn1 -upn2 $upn2 -user1ObjectId $user1ObjectId -user2ObjectId $user2ObjectId -user1Groups $user1Groups -user2Groups $user2Groups
        Process-DistributionGroupMembership -upn1 $upn1 -upn2 $upn2
        Process-MailEnableSecurityGroup -upn1 $upn1 -upn2 $upn2 
        Process-M365GroupMembership -upn1 $upn1 -upn2 $upn2 
    }

    Write-Log "Script execution completed." "INFO"
}

# Execute the main script
Main | Out-Null
