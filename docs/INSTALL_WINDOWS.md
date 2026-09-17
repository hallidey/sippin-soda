# Windows installer

Sippin Soda can be packaged as an NSIS installer for the current Windows user. The installer does not require administrator privileges and does not change the system proxy or certificate trust store.

## Build locally

Install the development prerequisites from the root README, then run:

```powershell
npm ci
npm run package:windows
```

The resulting installer is written to `target/release/bundle/nsis/`. The exact file name includes the application version and CPU architecture.

## Build in GitHub Actions

Open **Actions → Windows installer → Run workflow**. After the workflow succeeds, download the `sippin-soda-windows-installer` artifact from that run. The artifact contains the NSIS setup executable.

## Install and remove

Run the setup executable and launch **Sippin Soda** from the Start menu. The installer selects Italian or English from the Windows language and installs WebView2 from Microsoft only if the runtime is missing. Remove the app from **Settings → Apps → Installed apps**.

## Development-build warning

The current installer and executable are not digitally signed. Windows SmartScreen may therefore show an unknown-publisher warning. Only run an installer that you built yourself or downloaded from a trusted repository workflow, and verify the workflow run and commit before opening it. Code signing and release provenance remain required before a public release.

Installing Sippin Soda does not enable HTTPS inspection. CA generation, public-certificate export, client trust and each HTTPS inspection run remain explicit actions inside the app.
