- Kernel security and driver signature enforcement

# Possible false Fails and Passes
With a third-party antivirus installed, Defender normally goes passive, so "Defender not enabled" may be a false FAIL. Enabled does not mean effective with stuff like stale signatures, exclusions, Tamper Protection or Group Policy overrides. This could lead to alarming users who are protected, or reassuring users who are not. Suggesting to add signature age and Tamper Protection as extra checks. 

# Python usage and three layer pipeline
Python must be installed on a non-technical user's PC, which is against "lightweight". More layers means more failure points and attack surface. Could move comparision into C# and make one executable. If python kept, document the dependencies and execution policy requirements.

# Baseline.json and Report Integrity
Both are plain local files which means that anyone or any malware that edits the baseline can make the tool report PASS. A compromised host can also fake its own audit output. Consider signing or hashing the baseline and the report.
