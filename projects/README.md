# Projects

Security tools and platforms I've built. Each lives in its own repository — linked below — with its own README, CI, and release process.

| Project | Description | Stack |
|---|---|---|
| [**Aysal-Scan**](https://github.com/Rolex-1905/aysal-scan) | Secrets and leak detection for git repos — goes beyond regex/entropy matching by calling the provider's API to confirm whether a leaked key is still active and what it can access (AWS blast-radius analysis across direct, inline, and group-attached IAM policies). 17+ secret types, SARIF output, GitHub Action, pre-commit hook. Published on PyPI (`pip install aysal-scan`), 96 tests. | Python, Typer, boto3 |
| [**Aysal-Shield**](https://github.com/Rolex-1905/aysal-shield) | CI-native DAST automation platform for web applications on Apache Tomcat. Orchestrates the full dynamic testing lifecycle — authenticated/unauthenticated crawling, OWASP Top 10 coverage via ZAP, Tomcat CIS hardening checks, result normalization/deduplication, multi-format reporting (JSON/HTML/CSV/SARIF), and CI fail-gates on High/Critical findings. | Python, OWASP ZAP, Docker |
| [**Aysal-IDS**](https://github.com/Rolex-1905/aysal-IDS) | ML-based network intrusion detection system trained on CICIDS2017 and cross-validated against the independent CICIDS2018 dataset, to measure real generalization rather than same-dataset accuracy. Detects DDoS, port scans, brute force, and web attacks using Random Forest and Logistic Regression. | Python, scikit-learn, Jupyter |

Each name links directly to its repo — clone, install, and usage instructions live there.
