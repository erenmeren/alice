# The Windows settings the WinRS real tests (R71 F24-F31) may change, one name=value line each. The fixture
# reads them before its first change and TestRealRunnerIsClean (cmd/alice-winhelper) after every real test,
# with this one script, so both compare the same text.
Import-Module Microsoft.WSMan.Management
function Get-Value($path, $name) {
    $v = (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue).$name
    if ($null -eq $v) { 'absent' } else { "$v" }
}
"LocalAccountTokenFilterPolicy=$(Get-Value 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy')"
"LmCompatibilityLevel=$(Get-Value 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel')"
"ProcessCreationIncludeCmdLine_Enabled=$(Get-Value 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled')"
# The Process Creation subcategory by its GUID (its name is localized).
$audit = @(& "$env:WINDIR\System32\auditpol.exe" /get '/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}' /r | Where-Object { $_ } | ConvertFrom-Csv)
"ProcessCreationAudit=$($audit[0].'Inclusion Setting')"
foreach ($n in 'Basic', 'Kerberos', 'Negotiate', 'Certificate', 'CredSSP', 'CbtHardeningLevel') {
    "Service.Auth.$n=$((Get-Item -LiteralPath "WSMan:\localhost\Service\Auth\$n").Value)"
}
"Service.AllowUnencrypted=$((Get-Item -LiteralPath 'WSMan:\localhost\Service\AllowUnencrypted').Value)"
$inf = Join-Path $env:TEMP ('alice-w7-rights-' + [guid]::NewGuid().ToString('N') + '.inf')
try {
    & "$env:WINDIR\System32\secedit.exe" /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "secedit /export exited $LASTEXITCODE" }
    $deny = @(Get-Content -LiteralPath $inf -Encoding Unicode | Where-Object { $_ -match '^\s*SeDenyNetworkLogonRight\s*=' })
    "SeDenyNetworkLogonRight.S-1-5-114=$(@($deny | Where-Object { $_ -match '\*S-1-5-114\b' }).Count -gt 0)"
} finally {
    Remove-Item -LiteralPath $inf -Force -ErrorAction SilentlyContinue
}
# powershell.exe -Command exits 1 when the last statement left $? false; every line above was read.
exit 0
