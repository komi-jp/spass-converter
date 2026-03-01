# spass-converter

Convert Samsung Pass `.spass` export files into CSV formats compatible with popular password managers. Runs entirely offline on your local machine.

## Purpose

Enable data portability for users who have exported their own data from Samsung Pass via the official export feature, allowing migration to another password manager.

> **Note:** Currently only **IDs & Passwords** (login credentials) are converted. Other data types included in `.spass` exports (cards, addresses, notes) are detected and reported but skipped during conversion.

## Supported Formats

| Password Manager | `--format` value |
|---|---|
| Google Password Manager | `google` (default) |
| Bitwarden | `bitwarden` |
| 1Password | `1password` |
| LastPass | `lastpass` |
| KeePass | `keepass` |
| Dashlane | `dashlane` |

## How to Export from Samsung Pass

1. Open **Settings** > **Security and privacy** > **More security settings** > **Samsung Pass**
2. Tap **⋮ (More options)** > **Settings**
3. Tap **Export data to phone**
4. Select the data to export (IDs & Passwords, Cards, Addresses, Notes)
5. Set a password for the exported file — **remember this password**, you will need it for conversion
6. The `.spass` file will be saved to your device

Transfer the `.spass` file to your computer, then use this tool to convert it.

For more details, see the official Samsung support page: [Set up and use Samsung Pass](https://www.samsung.com/us/support/answer/ANS10002529/)

## Installation

```bash
pip install -r requirements.txt
```

The only dependency is `cryptography`.

## Usage

### Basic (Google Password Manager format)

```bash
python spass_converter.py export_data.spass
```

You will be prompted to enter the decryption password interactively (not stored in shell history).

### Specify format

```bash
python spass_converter.py export_data.spass --format bitwarden
python spass_converter.py export_data.spass -f keepass
```

### Other options

```bash
# Provide password on command line (not recommended — may appear in shell history)
python spass_converter.py export_data.spass --password YOUR_PASSWORD

# Specify output file path
python spass_converter.py export_data.spass --output ~/Desktop/passwords.csv

# Also save the full decrypted text to a file (for debugging)
python spass_converter.py export_data.spass --dump
```

### CLI Reference

| Option | Description |
|---|---|
| `<file.spass>` | Input file (required) |
| `--format`, `-f` | Output format (default: `google`) |
| `--password`, `-p` | Decryption password (interactive prompt if omitted) |
| `--output`, `-o` | Output file path (auto-generated if omitted) |
| `--dump` | Also save the full decrypted text to a file |

## Security

- **Fully offline**: No network calls or telemetry of any kind
- **In-memory processing**: Plaintext passwords are never written to intermediate files (`io.StringIO` is used for CSV generation)
- **Password protection**: Interactive `getpass` prompt by default (not visible in shell history or `ps` output)
- **Bring Your Own Key**: The decryption password is provided by the user at runtime; no proprietary keys are hardcoded

## Disclaimer

- This is an unofficial open-source tool intended solely for personal data migration
- It is not affiliated with Samsung, Google, Bitwarden, 1Password, LastPass, KeePass, Dashlane, or any other company
- The developer assumes no responsibility for data loss or leakage
- Please securely delete the generated CSV files after importing into your password manager
- This tool only processes data that users have exported themselves through the official Samsung Pass export feature

## Contributing

Bug reports, feature requests, and pull requests are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

MIT License
