# Firewall Manager

Small Windows GUI (Electron) for blocking programs in Windows Firewall.

- Block every `.exe` in a folder with inbound + outbound block rules (`PSFirewallBlock_*`)
- List and remove the rules this app created
- Runs elevated (admin) via PowerShell `New-NetFirewallRule`; packaged builds request elevation through the manifest

The original PowerShell version is kept as `firewall_manager.ps1`.

## Development

```
npm install
npm start        # run the app
npm test         # jest
npm run dist     # portable Windows build in dist/
```

## License

[MIT](LICENSE)
