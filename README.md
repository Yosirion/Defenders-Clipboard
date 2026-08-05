# Defenders Clipboard

A lightweight Windows clipboard manager built for SOC analysts and threat hunters. It watches the system clipboard, keeps a short in-memory history, and lets you run one-click decoding, defanging, and OSINT lookups on whatever you just copied — without leaving your keyboard.

Written in Rust, using `eframe`/`egui` for the UI and native Win32 APIs for clipboard monitoring, global hotkeys, and the system tray icon.

## Highlights

- **Event-driven clipboard monitoring** — hooks `WM_CLIPBOARDUPDATE`, no polling.
- **In-memory history only** — clipboard content is never written to disk; closing the app clears it.
- **Global hotkey** (default `Ctrl+Alt+V`) to summon the UI from anywhere, plus a system tray icon.
- **Skips reputation lookups for private/internal IPs** (RFC 1918, loopback, link-local, IPv4 and IPv6) — there's no reputation data for an address that was never publicly routable.
- **Encrypted API keys at rest** — VirusTotal/AbuseIPDB keys are encrypted with Windows DPAPI, tied to your Windows user profile.
- **On-the-fly file hashing** — copy a file in Explorer and its SHA-256 is computed and added to history (files > 100 MB are skipped).
- **Pin up to 3 items**, fuzzy search, full keyboard navigation, and deterministic auto-paste into the window you were working in.

## Tools

Each item in your history gets contextual one-click actions, shown only when relevant to that indicator type:

| Tool | What it does |
|---|---|
| **Smart Fang** | Toggles an IOC between defanged (`hxxp[:]//evil[.]com`) and refanged form. |
| **URL Decode** | Reverses percent-encoding. |
| **Base64 Decode** | Decodes standard Base64; auto-detects UTF-16LE (common in obfuscated PowerShell). |
| **Hex Decode** | Strips `0x`/`\x`/commas/spaces and decodes raw hex bytes. |
| **Extract IOCs** | Pulls every IPv4/IPv6 address, URL, domain, and hash out of a raw log/paste and adds each as its own history entry. |
| **QR Decode** | Scans a pasted screenshot for a QR code and extracts its text. |
| **API VirusTotal / API AbuseIPDB** | Queries the VT v3 / AbuseIPDB API and color-codes the entry (clean / suspicious / malicious). Results are cached per session. |
| **🌐 VirusTotal / 🌐 AbuseIPDB / 🌐 Whois / 🌐 UrlScan** | One-click pivot to the corresponding website for the copied indicator. |

## Requirements

- Windows 10/11
- Rust (stable) with the MSVC toolchain — the `windows` and `eframe` crates need `link.exe` from the Visual Studio Build Tools.

## Building

```bash
cargo build --release
```

The binary is produced at `target/release/defenders_clipboard.exe` and embeds its own icon.

## Configuration

On first run, a `config.yml` is created next to the executable (see [`config.example.yml`](config.example.yml) for the shape). It stores:

- your VirusTotal / AbuseIPDB API keys (DPAPI-encrypted on save)
- the global hotkey
- which tools are enabled
- window size and history capacity

`config.yml` is git-ignored — never commit your own copy, since the encrypted keys are tied to your Windows profile and useless (but still sensitive-looking) elsewhere.

## Testing

```bash
cargo test
```

Runs unit tests co-located with each module (`src/<module>/tests.rs`) plus integration tests in `tests/` that exercise the public API end-to-end.

## Architecture

- [`src/main.rs`](src/main.rs) — thin binary entry point.
- [`src/lib.rs`](src/lib.rs) — module declarations, so `tests/` can exercise the crate's public API.
- [`src/clipboard_listener.rs`](src/clipboard_listener.rs) — all `unsafe` Win32 code (clipboard hook, hotkey, tray icon, auto-paste), isolated behind a safe interface.
- [`src/app.rs`](src/app.rs) — application state, `egui` UI, config load/save, DPAPI encryption.
- [`src/transformers.rs`](src/transformers.rs) — the `Transformer` trait and all decoding/OSINT plugins (strategy pattern; adding a new tool doesn't require touching the UI).
- [`src/api.rs`](src/api.rs) — indicator classification and the VirusTotal/AbuseIPDB HTTP clients, with an in-memory result cache.
- [`src/events.rs`](src/events.rs) — message types passed between the GUI thread and background workers.

## Extending: adding a new transformer

The tool system uses a Strategy pattern specifically so that new tools never require touching the UI, the config system, or the Win32 layer — everything is driven by the `Transformer` trait in [`src/transformers.rs`](src/transformers.rs).

1. **Define a struct** for your tool (usually a zero-sized unit struct):

    ```rust
    pub struct Rot13Transformer;
    ```

2. **Implement `Transformer`.** At minimum you need `name`, `short_name`, and `transform_text`:

    ```rust
    impl Transformer for Rot13Transformer {
        fn name(&self) -> &str { "ROT13" }
        fn short_name(&self) -> &str { "ROT13" }

        fn transform_text(&self, input: &str, _vt_key: Option<&str>, _abuse_key: Option<&str>) -> Option<TransformerResult> {
            let rotated: String = input.chars().map(|c| match c {
                'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
                'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
                other => other,
            }).collect();

            Some(TransformerResult::Text(rotated))
        }
    }
    ```

    `transform_text` returns `None` to hide the result (e.g. nothing to do) or `Some(TransformerResult::...)` — see the `TransformerResult` enum for the other outcomes: `OpenBrowser(url)` for web pivots, `ApiVtResult`/`ApiAbuseResult`/`ApiError` for OSINT lookups. The `_vt_key`/`_abuse_key` parameters are only needed if your tool calls VirusTotal/AbuseIPDB.

3. **Override the optional hooks** if they apply to your tool:

    | Method | Default | Override when... |
    |---|---|---|
    | `supports_image` / `supports_text` | text-only | your tool works on pasted images instead (see `QrDecodeTransformer`) |
    | `button_width` | `60.0` | your `short_name` needs more room |
    | `is_supported_indicator` | always shown | your tool only makes sense for certain indicator types (e.g. `WhoisTransformer` only shows for `Ip`/`Domain`) |
    | `requires_external_lookup` | `false` | **your tool queries a public data source** — this is what hides it automatically for private/internal IPs, since there's no reputation data to fetch for those |

4. **Register it** in `TransformationManager::new()`:

    ```rust
    Box::new(Rot13Transformer),
    ```

That's it — the Settings screen, the enable/disable toggle, the button, and its width are all generated automatically from the trait. Add a test alongside the others in [`src/transformers/tests.rs`](src/transformers/tests.rs).

## Security notes

- Clipboard history lives in RAM only.
- API keys are encrypted at rest via `CryptProtectData`/`CryptUnprotectData` (Windows DPAPI).
- Tools that call out to a public data source (VirusTotal, AbuseIPDB, Whois, UrlScan) are automatically hidden for private/internal IP indicators, since there's no reputation data available for an address that isn't publicly routable.
