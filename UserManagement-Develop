
function Run-GUI {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Create the form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "My GUI"
    $form.Size = New-Object System.Drawing.Size(300, 200)
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog

    # Create labels and text boxes for input
    $usernameLabel = New-Object System.Windows.Forms.Label
    $usernameLabel.Location = New-Object System.Drawing.Point(10, 30)
    $usernameLabel.Size = New-Object System.Drawing.Size(80, 20)
    $usernameLabel.Text = "Username:"
    $form.Controls.Add($usernameLabel)

    $usernameTextBox = New-Object System.Windows.Forms.TextBox
    $usernameTextBox.Location = New-Object System.Drawing.Point(100, 30)
    $usernameTextBox.Size = New-Object System.Drawing.Size(180, 20)
    $form.Controls.Add($usernameTextBox)

    $passwordLabel = New-Object System.Windows.Forms.Label
    $passwordLabel.Location = New-Object System.Drawing.Point(10, 60)
    $passwordLabel.Size = New-Object System.Drawing.Size(80, 20)
    $passwordLabel.Text = "Password:"
    $form.Controls.Add($passwordLabel)

    $passwordTextBox = New-Object System.Windows.Forms.TextBox
    $passwordTextBox.Location = New-Object System.Drawing.Point(100, 60)
    $passwordTextBox.Size = New-Object System.Drawing.Size(180, 20)
    $passwordTextBox.UseSystemPasswordChar = $true
    $form.Controls.Add($passwordTextBox)

    $groupLabel = New-Object System.Windows.Forms.Label
    $groupLabel.Location = New-Object System.Drawing.Point(10, 90)
    $groupLabel.Size = New-Object System.Drawing.Size(80, 20)
    $groupLabel.Text = "Group:"
    $form.Controls.Add($groupLabel)

    $groupTextBox = New-Object System.Windows.Forms.TextBox
    $groupTextBox.Location = New-Object System.Drawing.Point(100, 90)
    $groupTextBox.Size = New-Object System.Drawing.Size(180, 20)
    $form.Controls.Add($groupTextBox)

    # Create a button for submission
    $submitButton = New-Object System.Windows.Forms.Button
    $submitButton.Location = New-Object System.Drawing.Point(100, 130)
    $submitButton.Size = New-Object System.Drawing.Size(100, 30)
    $submitButton.Text = "Submit"
    $submitButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($submitButton)

    # Add event handler for the submit button
    $submitButton.Add_Click({
        $global:usernameInput = $usernameTextBox.Text
        $global:passwordInput = $passwordTextBox.Text
        $global:groupInput = $groupTextBox.Text

        # Validate the input
        if ([string]::IsNullOrEmpty($usernameInput) -or
            [string]::IsNullOrEmpty($passwordInput) -or
            [string]::IsNullOrEmpty($groupInput)) {
            [System.Windows.Forms.MessageBox]::Show("Please fill in all fields.", "Input Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
        else {
            $form.Close()
        }
    })

    # Show the form
    $form.AcceptButton = $submitButton
    [void]$form.ShowDialog()
}

function Get-UserInput {
    $validInput = $false

    while (-not $validInput) {
        # Call the GUI function to get user input
        Run-GUI

        # Use the global variables from the GUI for input
        $usernameVariable = $global:usernameInput
        $passwordVariable = $global:passwordInput
        $groupVariable = $global:groupInput

        # Validate the input
        if ([string]::IsNullOrEmpty($usernameVariable) -or
            [string]::IsNullOrEmpty($passwordVariable) -or
            [string]::IsNullOrEmpty($groupVariable)) {
            [System.Windows.Forms.MessageBox]::Show("Please fill in all fields.", "Input Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
        else {
            $validInput = $true
        }
    }

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
            
            $sourceFolderPath = Join-Path -Path "C:\Windows\System32\GroupPolicyUsers" -ChildPath "S-1-5-21-3648033753-2748498847-2875352419-1008"
            
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

    # Add the user to the Administrators group
    $administratorsGroup = "Administrators"
    Add-ToGroup -GroupName $administratorsGroup -Username $Username
    
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



# if group not exist run the gui again and dont create the group
# complexity to password
# add window of are you sure to confirm the data?

