# Windows PIV and BitLocker Workflow

This document describes the Windows workflow that was validated on the `LilyGO T-Dongle S3` build of this fork.

## Goal

Get the device recognized by Windows as a usable PIV smartcard with:

- stable `CCID` transport
- working `PIV SELECT`
- working slot metadata and certificate reads
- working Microsoft smartcard container mapping
- working BitLocker-compatible certificate profile

## Build Variant

Use the `tdongle-s3` board profile with the `Yubikey5` USB identity:

```powershell
python "$env:IDF_PATH\tools\idf.py" -B build-tdongle-yk5 -DPICO_FIDO_ESP_BOARD=tdongle-s3 -DVIDPID=Yubikey5 build
```

## Flashing

Always start from a full erase:

```cmd
tools\flash_clean_yk5.cmd COM5
```

If the board becomes unresponsive, use:

```cmd
tools\flash_clean_recovery.cmd COM5
```

## PIV Import Script

The repository contains a helper importer:

```cmd
python tools\import_piv_pkcs12.py -i C:\bitlocker.pfx -p DeinPasswort -s 9a --auth-mode off --reader "Yubico"
```

What it writes:

- private key into the chosen slot
- certificate object
- `CHUID` object `0x5FC102`
- `CCC` object `0x5FC107`
- Microsoft container map `0x5FFF10`
- Microsoft roots object `0x5FFF11`

## Useful Test Commands

### Basic transport

```cmd
python tools\import_piv_pkcs12.py --reader "Yubico" --connect-only
python tools\import_piv_pkcs12.py --reader "Yubico" --select-only
```

### Read PIV data

```cmd
python tools\import_piv_pkcs12.py --reader "Yubico" -s 9a --read-metadata
python tools\import_piv_pkcs12.py --reader "Yubico" -s 9a --read-cert
python tools\import_piv_pkcs12.py --reader "Yubico" --read-object 0x5fc102
python tools\import_piv_pkcs12.py --reader "Yubico" --read-object 0x5fc107
python tools\import_piv_pkcs12.py --reader "Yubico" --read-object 0x5fff10
python tools\import_piv_pkcs12.py --reader "Yubico" --read-object 0x5fff11
```

### Windows verification

```cmd
certutil -scinfo
```

Expected signs of success:

- `Kette gueltig`
- `Schluesselcontainer = PIV 9A`
- `Privater Schluessel verifiziert`
- `Verifizierte Anwendungsrichtlinien` shows the intended EKU

## Generate a BitLocker-Compatible Test Certificate

To generate a self-signed test PFX with the BitLocker EKU:

```cmd
powershell -ExecutionPolicy Bypass -File tools\new_bitlocker_pfx.ps1 -PfxPath C:\bitlocker-bitlocker-oid.pfx -Password DeinPasswort
```

Then import it:

```cmd
python tools\import_piv_pkcs12.py -i C:\bitlocker-bitlocker-oid.pfx -p DeinPasswort -s 9a --auth-mode off --reader "Yubico"
```

## Trust the Self-Signed Certificate in Windows

If Windows reports `CERT_E_UNTRUSTEDROOT`, export and trust the generated certificate locally:

```cmd
powershell -NoProfile -Command "Export-Certificate -Cert 'Cert:\CurrentUser\My\THUMBPRINT' -FilePath C:\bitlocker-bitlocker-oid.cer | Out-Null"
certutil -addstore -f Root C:\bitlocker-bitlocker-oid.cer
certutil -addstore -f TrustedPeople C:\bitlocker-bitlocker-oid.cer
certutil -user -addstore -f Root C:\bitlocker-bitlocker-oid.cer
certutil -user -addstore -f TrustedPeople C:\bitlocker-bitlocker-oid.cer
reg add HKLM\SOFTWARE\Policies\Microsoft\FVE /v SelfSignedCertificates /t REG_DWORD /d 1 /f
gpupdate /force
```

## Important Limitations

### BitLocker

- Works for `fixed data drives` and `removable data drives`
- Not a replacement for OS-drive pre-boot smartcard authentication

### Windows login

- Native Windows smartcard login for a `local standalone account` is not provided by this project
- Domain or Entra-based smartcard login is a separate setup problem

## Troubleshooting

### White display after power-up

The T-Dongle S3 display must be actively put into sleep mode. This fork does that in `src/fido2/board_tdongle.c`.

### `SELECT PIV` crashes

Use the `build-tdongle-yk5` firmware from this fork. The current PIV patches fix the Windows `SELECT`, metadata and read paths.

### `certutil -scinfo` shows `(null)` container

This usually means one or more of the following objects are missing:

- `CHUID`
- `CCC`
- `MSCMAP`
- `MSROOTS`

The import helper in this fork writes them automatically.
