# Azure AD User Group Membership Copy Script

This PowerShell script is designed to automate the copying of user group memberships between two users in Azure Active Directory (Azure AD) and Exchange Online. The script transfers group memberships from a source user to a destination user, ensuring consistent group access for both users.

## Prerequisites

Before using the script, ensure you have the following:

- Windows PowerShell installed on your system.
- Administrative rights to install PowerShell modules if necessary.
- AzureAD module and Exchange Online Management module installed.
- Configuration of your Azure AD and Exchange Online environments.
- User credentials with appropriate permissions to manage users and groups.

## Usage

1. Download the `AzureAD_MembershipCopy.ps1` script from this repository.
2. Open PowerShell and navigate to the directory where the script is located.
3. Run the script using the command: `.\AzureAD_MembershipCopy.ps1`

## How to Use

1. Run PowerShell as an administrator, if the required modules are not installed.
2. Navigate to the directory where the script is located.
3. Run the script using the command: `.\AzureAD_MembershipCopy.ps1`

## Instructions

1. The script will prompt you to enter the UPNs (User Principal Names) of the source and destination users.
2. If the required modules (AzureAD and ExchangeOnlineManagement) are not installed, the script will prompt for admin rights to install them.
3. The script will copy Azure AD group memberships from the source user to the destination user.
4. Additionally, the destination user will be added to the same distribution groups in Exchange Online as the source user.
5. Log messages will be displayed in the console and saved to a log file.

## Logging

The script logs its activities to a log file located at `C:\Scripts\Powershell\Logs\AzureAD_MembershipCopy_Log.txt`.

## Important Notes

- Ensure that you have the necessary permissions to manage users and groups in Azure AD and Exchange Online.
- Test the script in a controlled environment before using it in production.
- Review the script and adapt it to your environment's requirements.
- Keep your sensitive information secure and follow best practices.

## License

This project is licensed under the terms of the GNU General Public License v3.0. For more details, please see the [LICENSE](LICENSE) file.

## Disclaimer

This script is provided as-is and may require modifications to fit your specific use case. Use it responsibly and ensure compliance with Azure AD and Exchange Online policies. The creators of this script are not responsible for any misuse or unintended consequences of its usage.
