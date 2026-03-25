param(
    [string]$PfxPath = "C:\bitlocker-bitlocker-oid.pfx",
    [string]$Password = "DeinPasswort",
    [string]$Subject = "CN=BitLocker",
    [int]$YearsValid = 10
)

$ErrorActionPreference = "Stop"

$securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
$notAfter = (Get-Date).AddYears($YearsValid)

$cert = New-SelfSignedCertificate `
    -Type Custom `
    -Subject $Subject `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy Exportable `
    -KeySpec KeyExchange `
    -KeyUsage KeyEncipherment `
    -TextExtension @(
        "2.5.29.37={text}1.3.6.1.4.1.311.67.1.1"
    ) `
    -NotAfter $notAfter

Export-PfxCertificate `
    -Cert "Cert:\CurrentUser\My\$($cert.Thumbprint)" `
    -FilePath $PfxPath `
    -Password $securePassword | Out-Null

Write-Host "PFX erzeugt:" $PfxPath
Write-Host "Thumbprint:" $cert.Thumbprint
Write-Host "Subject:" $cert.Subject
Write-Host "NotAfter:" $cert.NotAfter.ToString("u")
Write-Host "EKU OID: 1.3.6.1.4.1.311.67.1.1"
Write-Host "KeySpec: KeyExchange"
Write-Host "KeyUsage: KeyEncipherment"
