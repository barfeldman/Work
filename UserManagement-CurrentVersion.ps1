function Get-UserInput {
    param ()
    
    # Prompt the user for input and validate it
    $username = Read-Host "Enter username"
    while ([string]::IsNullOrEmpty($username)) {
        Write-Host "Username cannot be empty. Please try again."
        $username = Read-Host "Enter username"
    }
    
    $password = Read-Host "Enter password" -AsSecureString
    while ([string]::IsNullOrEmpty($password)) {
        Write-Host "Password cannot be empty. Please try again."
        $password = Read-Host "Enter password" -AsSecureString
    }
    
    $group = Read-Host "Enter group"
    while ([string]::IsNullOrEmpty($group)) {
        Write-Host "Group cannot be empty. Please try again."
        $group = Read-Host "Enter group"
    }
    
    # Store the input in variables
    $usernameVariable = $username
    $passwordVariable = $password
    $groupVariable = $group
    
    # Output the values for verification
    Write-Host "Username: $usernameVariable"
    Write-Host "Password: $passwordVariable"
    Write-Host "Group: $groupVariable"
    
    # Call the function to create the user and set the policy
    $createdUser = Create-LocalUser -Username $usernameVariable -Password $passwordVariable
    if ($createdUser) {
        $sid = Get-UserSID -Username $createdUser.Name
        Write-Host "Username: $($createdUser.Name)"
        Write-Host "SID: $sid"
        Add-ToGroup -GroupName $groupVariable -Username $createdUser.Name
        Set-LocalUserPolicy -Username $createdUser.Name
        Set-UserSettings -Username $createdUser.Name
        
    }
}

function Create-LocalUser {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Username,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Password
    )
    
    $existingUser = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
    
    if ($existingUser) {
        Write-Host "User '$Username' already exists."
        return $null
    }
    
    # Create a new user
    $user = New-LocalUser -Name $Username -Password (ConvertTo-SecureString -String $Password -AsPlainText -Force)
    
    if ($user) {
        Write-Host "User '$Username' created successfully."
        return $user
    } else {
        Write-Host "Failed to create user '$Username'."
        return $null
    }
}

function Add-ToGroup {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupName,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Username
    )
    
    # Check if the group already exists
    $existingGroup = Get-LocalGroup -Name $GroupName -ErrorAction SilentlyContinue
    
    if ($existingGroup) {
        # Add user to existing group
        Add-LocalGroupMember -Group $GroupName -Member $Username
        Write-Host "User '$Username' added to group '$GroupName'."
    } else {
        # Create new group and add user to it
        $group = New-LocalGroup -Name $GroupName
        if ($group) {
            Add-LocalGroupMember -Group $GroupName -Member $Username
            Write-Host "User '$Username' added to new group '$GroupName'."
        } else {
            Write-Host "Failed to create group '$GroupName'. User '$Username' was not added to any group."
        }
    }
}
function Get-UserSID {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Username
    )
    
    $user = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
    if ($user) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($user.SID)
        return $sid
    }
    
    Write-Host "User '$Username' not found."
    return $null
}
function Set-LocalUserPolicy {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Username
    )
    
    $sid = Get-UserSID -Username $Username
    
    if ($sid) {
        $policyFolderPath = Join-Path -Path "C:\Windows\System32\GroupPolicyUsers" -ChildPath $sid.Value
        
        if (-not (Test-Path $policyFolderPath)) {
            New-Item -ItemType Directory -Path $policyFolderPath -ErrorAction SilentlyContinue | Out-Null
            Write-Host "Policy folder created: $policyFolderPath"
            
            $sourceFolderPath = Join-Path -Path "C:\Windows\System32\GroupPolicyUsers" -ChildPath "S-1-5-21-266747492-49634458-2244263459-1015"
            
            if (Test-Path $sourceFolderPath) {
                Get-ChildItem -Path $sourceFolderPath | ForEach-Object {
                    $destinationPath = Join-Path -Path $policyFolderPath -ChildPath $_.Name
                    Copy-Item -Path $_.FullName -Destination $destinationPath -Recurse -Force
                }
                
                Write-Host "Contents copied from '$sourceFolderPath' to '$policyFolderPath'."
            } else {
                Write-Host "Source folder '$sourceFolderPath' does not exist."
            }
        } else {
            Write-Host "Policy folder already exists: $policyFolderPath"
        }
    }
}

function Set-UserSettings {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Username
    )
    
    # Set the "PasswordNeverExpires" property for the user
    Set-LocalUser -Name $Username -PasswordNeverExpires $true
    
    # Add the user to the Remote Desktop Users group
    $group = "Remote Desktop Users"
    Add-ToGroup -GroupName $group -Username $Username
    
    Write-Host "User '$Username' set to never expire and added to the '$group' group."
}


function Main {
    # Call the input function that calls all other functions
    Get-UserInput
}

# Call the main function
Main
