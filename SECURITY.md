# Security and trust boundaries

This package is a Windows client for a separately managed compatible controller. It is not a public controller deployment recipe. There is no embedded owner controller URL, certificate pin, code, OAuth credential or signing key.

Treat any pairing code as a short-lived bearer secret delivered privately by its actual owner. The code's included verification key is not independently trusted against whole-code substitution. A malicious controller can supply its own runtime after approval. Public distribution and runtime signing are separate trust decisions.

Do not attach real keys, codes, certificates with private keys, profiles, account tokens, cookies or unredacted logs to public issues. A private disclosure channel must be agreed with the maintainer; do not assume one is automatically configured by this source publication. GitHub repository settings are managed separately.

The client is designed to fail closed on identity, grant, signature, hash, TLS or protected-storage errors. It must not bypass Windows permission/session restrictions, weaken TLS, silently replace an identity or replay uncertain mutations. Interactive desktop access is not provided by this repository alone.

The optional owner display sends code text through the helper's stdin, not argv/URLs/tool output. It is masked by default and uses manual reveal/copy. Clipboard history, malware and screen capture remain possible exposures. Native visibility flags cannot establish human observation.

No production service, startup entry, firewall rule, elevation or global execution-policy modification is installed by this client. Closing its foreground lifetime disconnects its owned runtime.
