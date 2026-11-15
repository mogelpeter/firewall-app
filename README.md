# Firewall Manager

Small native Windows app (Rust, egui) for blocking programs in Windows Firewall.

- Block every `.exe` in a folder (recursive) with inbound + outbound block rules (`PSFirewallBlock_*`), or block single/multiple `.exe` files
- Drag and drop a folder or `.exe` files onto the window
- See all blocked programs in one searchable list, remove selected / missing / all
- The blocked list is remembered in `%ProgramData%\FirewallManager\blocked.txt`; rules that went missing show as "Not in firewall" and are restored with one button
- Talks to the firewall directly through the `INetFwPolicy2` COM API (no PowerShell), so listing takes milliseconds
- Single portable `.exe`; asks for administrator rights on start (UAC)

The original PowerShell version is kept as `firewall_manager.ps1`.

## Development

```
cargo run --release
cargo test                      # unit tests
cargo test -- --ignored         # firewall round-trip test (needs an elevated shell)
```

## License

[MIT](LICENSE)
