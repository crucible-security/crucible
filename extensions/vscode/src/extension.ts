import * as vscode from 'vscode';

export function activate(context: vscode.ExtensionContext) {
    let disposable = vscode.commands.registerCommand('crucible.scan', async () => {
        // Read the target URL from configuration
        const config = vscode.workspace.getConfiguration('crucible');
        let targetUrl = config.get<string>('defaultTargetUrl');

        // If no default target URL is set, prompt the user
        if (!targetUrl) {
            targetUrl = await vscode.window.showInputBox({
                prompt: 'Enter the target agent URL to scan',
                placeHolder: 'https://example.com/api/chat',
                ignoreFocusOut: true
            });
        }

        // Exit if no URL is provided
        if (!targetUrl) {
            vscode.window.showWarningMessage('Crucible scan cancelled: No target URL provided.');
            return;
        }

        // Find existing terminal or create a new one
        const terminalName = 'Crucible Scan';
        let terminal = vscode.window.terminals.find(t => t.name === terminalName);
        if (!terminal) {
            terminal = vscode.window.createTerminal(terminalName);
        }

        // Show the terminal and send the scan command
        terminal.show();
        terminal.sendText(`crucible scan --target "${targetUrl}"`);

        // Show a notification
        vscode.window.showInformationMessage(`Crucible scan started for ${targetUrl}. Check the terminal for your grade!`);
    });

    context.subscriptions.push(disposable);
}

export function deactivate() {}
