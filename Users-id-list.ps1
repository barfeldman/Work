$users = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"

foreach ($user in $users) {
    $sid = New-Object System.Security.Principal.SecurityIdentifier($user.SID)
    $folderName = "$($sid.Value)"
    
    Write-Output "Username: $($user.Name), Folder Name: $folderName"
}
