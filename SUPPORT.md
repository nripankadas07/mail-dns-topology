# Support, contribution and security

Use [issues](https://github.com/nripankadas07/mail-dns-topology/issues) for reproducible bugs with Python version, command, expected/actual exit status and a minimal **synthetic** fixture. Do not upload private captions, customer XML, mail records, real webhook keys/IDs or sensitive release metadata. No response-time guarantee.

Contributions: open an issue for scope changes, use a descriptive branch, include a regression demonstrating the user-facing contract and run `python verify.py`. Keep runtime dependency-free; preserve documented unsupported cases and fail-closed inputs.

Security: do not disclose exploit details or secrets publicly. Use GitHub private vulnerability reporting if available; otherwise request a private contact through a minimal issue without sensitive details. Treat input data as untrusted and use resource controls appropriate to your environment. This MVP is not a certification or substitute for deployment-specific threat modelling.

Original implementation/prose under MIT. No competitor code or prose copied. Shared packaging/verification scaffolding comes from the author's existing portfolio under MIT; product capabilities and fixtures are distinct. Python's standard library and build-time setuptools are separately licensed upstream.
