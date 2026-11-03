# CurrentUser DPAPI only. Payloads travel over private stdin/stdout, never argv.
# No file, certificate-store, ACL, policy or network operation.
$ErrorActionPreference='Stop'
try {
    Add-Type -AssemblyName System.Security
    $data=[Console]::In.ReadToEnd() | ConvertFrom-Json
    $bytes=[Convert]::FromBase64String([string]$data.payload)
    $entropy=[Text.Encoding]::UTF8.GetBytes('UniversalControl/private-state/v1')
    if($data.action -eq 'protect') {
        $result=[Security.Cryptography.ProtectedData]::Protect($bytes,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    } elseif($data.action -eq 'unprotect') {
        $result=[Security.Cryptography.ProtectedData]::Unprotect($bytes,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    } else { throw 'Unsupported protected-data action' }
    [Convert]::ToBase64String($result)
} catch { [Console]::Error.WriteLine('CurrentUser protected-data operation failed'); exit 1 }
