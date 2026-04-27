# Crucible Security Scanner (VS Code Extension Stub)

This is an early Alpha/Stub VS Code extension for the [Crucible](https://github.com/crucible-security/crucible) security framework.

It allows developers to trigger Crucible agent scans directly from their editor by simply providing a target URL. The extension will automatically open a terminal and execute the `crucible scan` command for you, letting you track the results and your final grade directly within VS Code.

## Features

- **Crucible: Scan Agent**: A command available in the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`).
- **Target URL Prompt**: Prompts for a target URL if you haven't set a default in your settings.
- **Visual Feedback**: Automatically opens an integrated terminal and runs the scan with the rich UI.

## Extension Settings

This extension contributes the following settings:

* `crucible.defaultTargetUrl`: The default target URL for your agent scans. Set this to avoid being prompted on every scan.

## Install from Source

Currently, this extension is a stub and is **not** published to the VS Code Marketplace. You must run it locally.

### Prerequisites
1. Ensure you have [Node.js](https://nodejs.org/) installed.
2. Ensure you have the `crucible` CLI installed in your Python environment and available in your VS Code terminal's PATH.

### Building & Running
1. Open this `extensions/vscode` folder in VS Code.
2. Open a terminal and run `npm install` to install the dependencies.
3. Press `F5` to open a new VS Code window with the extension loaded in "Extension Development Host" mode.
4. In the new window, open the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P`) and run **"Crucible: Scan Agent"**.
5. Enter your URL and watch the scan execute in the terminal!

## Building the `.vsix` Package

If you want to install it permanently in your regular VS Code without `F5`:
1. Run `npx @vscode/vsce package` inside this directory.
2. It will generate a `crucible-vscode-0.1.0.vsix` file.
3. Install it via the Command Palette: **"Extensions: Install from VSIX..."**.
