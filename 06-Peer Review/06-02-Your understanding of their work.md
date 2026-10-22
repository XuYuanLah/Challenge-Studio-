Stated problem : WESA designed to address the issue by providing a lightweight audit tool for individual devices. It focuses on a limited set of win sec features. checks whether in expected secure state. to identify potential sec issues. 

WESA is a desktop tool that checks four Windows security settings against a fixed baseline and tells a non expert user which ones are misconfigured and how to fix them. It reports only and never changes settings.

The problem stated is that security tools can be installed but disabled or misconfigured, and personal users and small businesses lack staff or enterprise tooling to notice. WESA aims to be local, lightweight and easy to read.

Four controls are checked: Windows Firewall, Microsoft Defender Antivirus, Defender Real-Time Protection and the Guest Account. Each returns PASS or FAIL, plus severity, risk and remediation advice. A timestamped plain text report can be exported.

The architecture is WPF/XAML GUI → C# front end → Python audit service → PowerShell checks → comparison with baseline.json → JSON results → GUI or report. Python loads the expected values, PowerShell reads the live state, and Python compares the two.

For testing, they used a fresh Windows 11 VM and deliberately changed settings.The demostration show that the guest account was activated and it was reported as a FAIL after running the WESA software. 

The value they give is a simple configuration assessment and not a replacement for antivirus or enterprise security software.