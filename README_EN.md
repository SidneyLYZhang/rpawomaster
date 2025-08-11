# RPaWoMaster

English | [中文](README.md)

I previously wrote a password manager in Python, but not every colleague had Python installed, so I always planned to create a new version with better universality.
And after all these years, the password management situation among company colleagues is still concerning, with various mysterious operations.

Security shouldn't just be a slogan, so this password manager, after several years since I wrote the Python version, finally has a prototype.

This is the origin of this password manager built with Rust.

There's also another important issue: why insist on writing a password manager myself? Because if it's not written by me, it can't be used at work.
Another additional reason is that I also want to practice my Rust coding skills. I haven't been writing Haskell, lean4, or racket for a while...
So there are many places where I'm not quite sure how to write...

## Overview

A password manager written in Rust. Currently available features include:

1. Password vault initialization (including vault import)
2. Password generation
3. Password strength testing
4. Adding passwords
5. Searching passwords
6. Exporting password vault
7. Listing passwords/vaults
8. Simple encryption/decryption features

## Is the Password Secure?

I've heard many people say that storing passwords in one place, even together with 2FA, is a hidden danger because if one is compromised, all are compromised. This sounds quite reasonable.
However, no matter how you separate the storage, encryption methods eventually have limits, and security is always relative.

Security, usability, and convenience are always contradictory from a controllable perspective. All these issues are within an uncontrollable range.
No matter who it is, everyone thinks they're an insignificant nobody who won't be specifically targeted, thus obtaining relative password security.

Absolute security, of course, still depends on absolute physical isolation, which eliminates usability and convenience.
Usability also means security is only temporary. Separating password and 2FA storage is just for an additional layer of isolation.
But it's not necessarily secure either.

This is why many current encryptions use nested layers to enhance confidentiality and security, or use algorithms with higher mathematical difficulty/complexity
to achieve encryption security. It's all a compromise.

Separating passwords and 2FA, but using the same (similar) password management, is still high-risk behavior. Ensuring the password itself is difficult to crack
and not leaked might be what relative security truly needs.

So my password manager will enforce core password checks and set an unchangeable core password update cycle.
It can also manage 2FA (one-time passwords), but requires the 2FA verification password to be different from the core password, and the verification password must also meet password level requirements.
Meanwhile, a stricter offline storage mode with troublesome and multiple verification import and export processes, suitable for situations with higher confidentiality requirements.
Of course, if completely physically isolated, this is also another acceptable choice.

But these settings of mine are passive and cannot prevent password cracking. The key points are still the complexity and storage methods of the core password and 2FA verification password,
these two critical passwords. At least the difficulty of memorizing passwords has decreased somewhat, hasn't it?

## Installation Guide

Can be installed from source or using `Cargo`.

Source installation method:

```bash
# Clone repository
git clone https://github.com/SidneyLYZhang/rpawomaster.git
cd rpawomaster

# Build project
cargo build --release
```

Cargo installation:

```bash
cargo install rpawomaster
```

## Usage

Since only core features are currently completed, the following usage examples are for the current version.

```bash
# View help
$ rpawomaster --help

A secure password manager written in Rust

Usage: rpawomaster.exe <COMMAND>

Commands:
  init      Initialize a new password vault
  gen       Generate a new password
  add       Add a password to the vault
  update    Update an existing password
  delete    Delete an existing password
  list      list all existing passwords
  search    Search passwords in the vault
  testpass  Test password strength and properties
  vaults    List all password vaults
  crypt     Encrypt or decrypt files/directories
  export    Export password vault
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

(1) First step of usage: Initialize password vault.

```bash
# The first step in using the password vault is to initialize it
rpawomaster init
```

This feature mainly addresses which user needs to set up the password vault, what name to give the vault, and needs to confirm the vault's save location.

Why specify which user? Because in some company device security areas, such as secure computers, multiple users might share the device,
each needing different passwords. So to better handle multi-user sharing situations, determining the user and password vault is necessary.

(2) Now you can add passwords.

```bash
# Add password
rpawomaster add [password-name] -u yourname
```

Unlike traditional direct plaintext addition, here you need to fill in step by step, but it better handles the password generation process and password rule storage,
providing a foundation for subsequent automatic password updates.

(3) After adding passwords, you can search for them.

```bash
# Search password
rpawomaster search [password-name] -u yourname
```

This supports fuzzy and exact search, with fuzzy search as the default. So even if you can't remember the exact password name, it's fine,
or even if the password record contains this field, it can help find it.

For exact search, you need to add the exact search parameter: `--exact`.

(4) Updating passwords is not complicated.

```bash
# Update password
rpawomaster update -p password-name -u yourname
```

Or if you want to update all expired passwords:

```bash
rpawomaster update -a -u yourname
```

Password updates mainly select based on the validity period of passwords in the current user's vault. If password generation strategy was confirmed when saving passwords,
it will directly use the existing strategy to generate new passwords when updating. Otherwise, users need to manually input passwords again.

(5) Of course, you can also simply use `rpawomaster` as a password generator:

```bash
# Generate random password
rpawomaster gen random -l 22
```

## Progress

| Feature/Task | Status | Completion Date |
|----------|------|------------|
| Command line argument parsing | :heavy_check_mark: Completed | 2025-06-30 |
| Password creation | :heavy_check_mark: Completed | 2025-06-30 |
| Password strength testing | :heavy_check_mark: Completed | 2025-06-30 |
| Password vault initialization | :heavy_check_mark: Completed | 2025-07-29 |
| Adding passwords | :heavy_check_mark: Completed | 2025-07-29 |
| Updating passwords | :heavy_check_mark: Completed | 2025-07-30 |
| Searching passwords | :heavy_check_mark: Completed | 2025-07-29 |
| Deleting passwords | :heavy_check_mark: Completed | 2025-07-30 |
| Exporting password vault | :heavy_check_mark: Completed | 2025-07-30 |
| File/directory encryption/decryption | :heavy_check_mark: Completed | 2025-07-30 |
| Support for storing [dynamic tokens (TOTP/HOTP)](https://2fasolution.com/index.html) | 🚧 In Progress | 2025-07-31 |
| Clipboard functionality (auto-clear) | :heavy_check_mark: Partially Completed, Not Implemented | 2025-07-31 |
| Memorable password generation | :heavy_check_mark: Completed | 2025-07-31 |
| Unit testing | :heavy_check_mark: Completed | 2025-07-29 |
| Documentation improvement | In progress ... | 2025-07-31 |
| Release v0.1.8 | :heavy_check_mark: Completed | 2025-07-31 |
| Release v1.0 | 🔖 Planned |  |

Currently, the core password vault features are essentially complete, with v0.1.8 already released. TOTP/HOTP functionality is under development and expected to be completed in a subsequent version.

## Contribution Guidelines
1. Fork this repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add some amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Create Pull Request

## Additional Notes

The [`wordlist.txt`](data/wordlist.txt) used for memorable passwords comes from [EFF](https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt).

## LICENSE

Copyright (c) 2025 Sidney Zhang <zly@lyzhang.me>

rpawomaster is licensed under [Mulan PSL v2](LICENSE) .