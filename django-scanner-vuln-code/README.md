# Django Security Scanner

A Visual Studio Code extension that scans Django projects for security vulnerabilities and provides recommendations for improving code security.

## Features

This extension helps identify common security vulnerabilities in Django applications by scanning:

- **Python Files**: Detects insecure coding patterns, SQL injection vulnerabilities, XSS risks, and other security issues
- **Settings Files**: Analyzes Django settings for insecure configurations
- **Templates**: Scans Django templates for potential security issues
- **APIs**: Reviews API endpoints for common vulnerabilities
- **Configuration Best Practices**: Checks for security best practices in project configuration

### Key Capabilities

- 🔍 Comprehensive security scanning
- 📊 Detailed vulnerability reports with severity levels
- 💡 Actionable recommendations for fixing issues
- 🚀 Quick access through VS Code command palette

## Requirements

- Visual Studio Code 1.107.0 or higher
- A Django project open in the workspace

## How to Use

1. Open your Django project in VS Code
2. Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
3. Run the command: `Django Security Scanner: Scan Project`
4. Review the security report in the output panel

## Extension Settings

This extension currently does not add any VS Code settings.

## Known Issues

- Scanning large projects may take some time
- Some false positives may occur in complex code patterns

## Release Notes

### 0.0.1

Initial release with basic Django security scanning capabilities:
- Python file vulnerability detection
- Settings configuration analysis
- Template security scanning
- API endpoint review
- Configuration best practices checking

---

**Enjoy secure Django development!** 🛡️

## Following extension guidelines

Ensure that you've read through the extensions guidelines and follow the best practices for creating your extension.

* [Extension Guidelines](https://code.visualstudio.com/api/references/extension-guidelines)

## Working with Markdown

You can author your README using Visual Studio Code. Here are some useful editor keyboard shortcuts:

* Split the editor (`Cmd+\` on macOS or `Ctrl+\` on Windows and Linux).
* Toggle preview (`Shift+Cmd+V` on macOS or `Shift+Ctrl+V` on Windows and Linux).
* Press `Ctrl+Space` (Windows, Linux, macOS) to see a list of Markdown snippets.

## For more information

* [Visual Studio Code's Markdown Support](http://code.visualstudio.com/docs/languages/markdown)
* [Markdown Syntax Reference](https://help.github.com/articles/markdown-basics/)

**Enjoy!**
