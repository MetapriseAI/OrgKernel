# Security Policy
## Supported Versions
| Version | Supported |
|---|---|
| latest (main) | Yes |
| older releases | No |
## Reporting a Vulnerability
OrgKernel handles cryptographic identity and audit infrastructure for enterprise AI agents. We take security vulnerabilities extremely seriously.
**Please do not report security vulnerabilities through public GitHub issues.**
Instead, disclose responsibly by emailing:
**developer@metaprise.ai**
Please include the following in your report:
- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Any proof-of-concept code or screenshots
- Your suggested fix (if any)
## Response Timeline
- **Acknowledgement**: within 48 hours of receiving your report
- **Initial assessment**: within 5 business days
- **Remediation timeline**: communicated after initial assessment
- **Public disclosure**: coordinated with the reporter after a fix is released
## Scope
The following are in scope for security reports:
- Cryptographic identity (Ed25519 keypair generation, certificate issuance, challenge-response)
- Execution token signing and validation
- Token grafting attack vectors in the Tool Gateway
- Audit chain integrity and hash-chaining logic
- SSO/SAML integration vulnerabilities
- SCIM provisioning logic
## Out of Scope
- Vulnerabilities in third-party dependencies (report to the respective maintainers)
- Issues requiring physical access to infrastructure
- Social engineering attacks
## Recognition
We are grateful to security researchers who responsibly disclose vulnerabilities. Confirmed reporters will be acknowledged in our release notes (with permission).