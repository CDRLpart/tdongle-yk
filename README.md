# tdongle-yk

`tdongle-yk` is a LilyGO T-Dongle S3 focused fork of `pico-fido2` / `pico-openpgp`.

The goal of this fork is simple:

- run `FIDO2`, `OTP`, `OATH`, `OpenPGP` and `PIV` on the `LilyGO T-Dongle S3`
- expose a `YubiKey 5` compatible USB identity for better Windows / Yubico tool compatibility
- make the board usable as a compact USB security token with native support for its button, RGB LED and display power behavior
- provide working helper scripts for build, flash and Windows PIV / BitLocker import workflows

This is not an official Yubico product.

## What This Fork Adds

- Native `LilyGO T-Dongle S3` board support
- `ESP32-S3` board selection via `PICO_FIDO_ESP_BOARD=tdongle-s3`
- Native button mapping for FIDO user presence on `GPIO 0`
- `APA102` RGB LED support using the T-Dongle S3 pins
- Safe ST7735 display sleep handling so the display does not stay white and powered
- A stable `Yubikey5` build profile for Windows smartcard tooling
- Windows-focused PIV fixes for:
  - `SELECT PIV`
  - `GET METADATA`
  - certificate reads
  - Microsoft smartcard container mapping
  - `CHUID` and `CCC` object population
- Helper scripts for:
  - full erase + flash
  - PKCS#12 import into PIV
  - generating a BitLocker-compatible self-signed PFX

## Hardware Target

Board: `LilyGO T-Dongle S3`

### Pinout

| Function | Pin |
| --- | --- |
| User button | `GPIO 0` |
| APA102 data | `GPIO 40` |
| APA102 clock | `GPIO 39` |
| ST7735 MOSI | `GPIO 3` |
| ST7735 SCK | `GPIO 5` |
| ST7735 CS | `GPIO 4` |
| ST7735 DC | `GPIO 2` |
| ST7735 backlight | `GPIO 38` |

### Board-specific behavior

- The boot button is used as the `FIDO user presence` button.
- The RGB LED is configured as an `APA102` device.
- The ST7735 display is put into `Sleep In (0x10)` and its backlight is driven low during init to avoid a permanently lit white screen.

Implementation file: `src/fido2/board_tdongle.c`

## Repository Layout

- `src/fido2/board_tdongle.c`
  - LilyGO T-Dongle S3 hardware support
- `tools/flash_clean_yk5.cmd`
  - full chip erase + flash of the YubiKey-compatible build
- `tools/flash_clean_recovery.cmd`
  - full chip erase + flash of the known-good recovery build
- `tools/import_piv_pkcs12.py`
  - direct PKCS#12 import into the PIV applet
  - writes certificate, `CHUID`, `CCC`, `MSCMAP`, and `MSROOTS`
- `tools/new_bitlocker_pfx.ps1`
  - generates a self-signed PFX with the BitLocker EKU

## Build

This fork is primarily documented for `Windows + ESP-IDF + ESP32-S3`.

### Prerequisites

- `ESP-IDF 5.5.x`
- Python available for `idf.py` and `esptool`
- Git submodules initialized

### Example build on Windows

```powershell
$env:PATH='C:\Users\rapha\AppData\Local\Programs\Python\Python311;' + $env:PATH
. 'C:\Espressif\frameworks\esp-idf-v5.5.3\export.ps1'
python "$env:IDF_PATH\tools\idf.py" -B build-tdongle-yk5 -DPICO_FIDO_ESP_BOARD=tdongle-s3 -DVIDPID=Yubikey5 build
```

Important build options:

- `-DPICO_FIDO_ESP_BOARD=tdongle-s3`
- `-DVIDPID=Yubikey5`

Current supported ESP board values:

- `generic`
- `tdongle-s3`

Current supported `VIDPID` presets include:

- `Yubikey5`
- `YubikeyNeo`
- `NitroFIDO2`
- `Gnuk`
- `GnuPG`

## Flashing

Both flash helper scripts always do a `full erase` first.

### Flash the YubiKey-compatible build

```cmd
tools\flash_clean_yk5.cmd COM5
```

### Flash the recovery build

```cmd
tools\flash_clean_recovery.cmd COM5
```

If the board is not detected:

1. Hold the `BOOT` button while plugging in the dongle.
2. Run the flash script again.
3. Unplug / replug after flashing.

## Windows PIV Workflow

This fork includes a direct PIV import workflow for Windows.

### Import a PKCS#12 bundle into slot `9A`

```cmd
python tools\import_piv_pkcs12.py -i C:\bitlocker.pfx -p DeinPasswort -s 9a --auth-mode off --reader "Yubico"
```

The import script writes:

- private key into the PIV slot
- X.509 certificate object
- `CHUID` (`0x5FC102`)
- `CCC` / capability container (`0x5FC107`)
- Microsoft smartcard mapping object (`0x5FFF10`)
- Microsoft roots object (`0x5FFF11`)

### Verify the PIV smartcard stack

```cmd
python tools\import_piv_pkcs12.py --reader "Yubico" --connect-only
python tools\import_piv_pkcs12.py --reader "Yubico" --select-only
python tools\import_piv_pkcs12.py --reader "Yubico" -s 9a --read-metadata
python tools\import_piv_pkcs12.py --reader "Yubico" -s 9a --read-cert
certutil -scinfo
```

For a full Windows and BitLocker walkthrough, see:

- [docs/WINDOWS-PIV-BITLOCKER.md](docs/WINDOWS-PIV-BITLOCKER.md)

## BitLocker Notes

This repository now supports a working Windows smartcard / PIV path for BitLocker certificate handling.

Important caveats:

- Smartcard certificate protectors are for `fixed data drives` and `removable data drives`.
- Native Windows `smartcard login` for a `local standalone account` is not supported by this repository alone.
- For `BitLocker`, you need a certificate profile that matches the BitLocker EKU requirements.

Helper for generating a compatible test certificate:

```cmd
powershell -ExecutionPolicy Bypass -File tools\new_bitlocker_pfx.ps1 -PfxPath C:\bitlocker-bitlocker-oid.pfx -Password DeinPasswort
```

## Known Scope

This fork is focused on:

- `LilyGO T-Dongle S3`
- `ESP32-S3`
- `Windows` smartcard compatibility
- `PIV` stability and helper tooling

It is not intended to be a polished generic multi-board distribution.

## Upstream Attribution

This repository is based on:

- `pico-fido2`
- `pico-openpgp`
- `pico-keys-sdk`

Please keep upstream attribution intact when redistributing the fork.

## Submodules

This repository currently keeps the upstream components as submodules:

- `pico-fido`
- `pico-openpgp`
- `pico-keys-sdk`

The `.gitmodules` file is configured with relative URLs:

- `../pico-fido.git`
- `../pico-openpgp.git`
- `../pico-keys-sdk.git`

That means the cleanest GitHub layout is:

- top-level repo: `tdongle-yk`
- sibling repos in the same GitHub account or organization:
  - `pico-fido`
  - `pico-openpgp`
  - `pico-keys-sdk`

If you want to publish this fork as a working project, push the modified submodule repositories first, then push the top-level repository.

Publishing notes:

- [docs/PUBLISHING.md](docs/PUBLISHING.md)

## License

This fork inherits the licensing model of the upstream project and its subcomponents.

Review the upstream license files before redistributing binaries, modified firmware, or downstream forks.
