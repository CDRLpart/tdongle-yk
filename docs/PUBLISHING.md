# Publishing This Fork with Submodules

This repository is not a single self-contained tree yet.

It contains modified submodules:

- `pico-fido`
- `pico-openpgp`
- `pico-keys-sdk`

## Recommended GitHub Layout

Use one GitHub account or organization and create these repositories:

- `tdongle-yk`
- `pico-fido`
- `pico-openpgp`
- `pico-keys-sdk`

The current `.gitmodules` file already points to sibling repositories with relative URLs:

```ini
../pico-fido.git
../pico-openpgp.git
../pico-keys-sdk.git
```

That layout works well if all four repositories live under the same owner.

## Recommended Publish Order

1. Push `pico-fido`
2. Push `pico-openpgp`
3. Push `pico-keys-sdk`
4. Update the top-level repository so its submodule pointers reference the pushed commits
5. Push `tdongle-yk`

## Clone Command for Users

```bash
git clone --recurse-submodules https://github.com/<your-user-or-org>/tdongle-yk.git
```

If the repository was already cloned without submodules:

```bash
git submodule update --init --recursive
```

## Important Note

If you only push the top-level repository but not the modified submodule commits, other users will not get the working T-Dongle / PIV changes.

## Alternative

If you want a single self-contained repository without submodules, you need a separate flattening or vendoring step. That is a different cleanup task from this document.
