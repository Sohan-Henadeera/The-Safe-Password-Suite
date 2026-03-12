# The-Safe-Password-Suite
To publicly access via streamlit: [http://192.168.1.117:8501](https://the-safe-password-suite-jxmwqpbthbrpdibmne2dmp.streamlit.app/)

A full-stack cybersecurity web application built with Python and Streamlit that teaches users how to create, audit, and understand secure passwords.

What It Does:
The app has four core modules:
Auditor — paste in any password and instantly get a full security report: entropy score, complexity analysis, improvement tips, and a live check against the Have I Been Pwned database to see if it has appeared in real-world data breaches.
Generator — create cryptographically secure passwords using Python's secrets module (a true CSPRNG), with controls for length, character sets, and an optional personal keyword that gets safely embedded in the output.
Cryptographic Simulator — a visual, step-by-step walkthrough of how servers actually store passwords. Demonstrates the Caesar Cipher to show why reversible encryption is dangerous, then contrasts it with SHA-256 hashing + salt to show the industry-standard approach.
Credits — full breakdown of the tech stack and security concepts powering the app.

🛠 Tools & Technologies

Python 3 — core language
Streamlit — web app framework, UI, and deployment
hashlib — SHA-1 (k-anonymity hashing) and SHA-256 (password storage simulation)
secrets — cryptographically secure random password generation
requests — HTTP calls to the HIBP API
re / math — regex-based complexity scoring and entropy calculations
Have I Been Pwned API — breach database lookup using the k-anonymity model (your password never leaves your machine in full)
Custom CSS — Apple-inspired UI styling injected into Streamlit

🔧 Use Cases

- Security awareness training for students or new developers
- A personal tool to audit passwords before using them
- A teaching demo for cybersecurity concepts like hashing, salting, and breach databases
- A portfolio piece demonstrating applied cryptography knowledge in Python
