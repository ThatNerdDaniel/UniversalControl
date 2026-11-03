# UniversalControl client — Windows preview

A generic Windows agent and installer for an **existing compatible UniversalControl controller**. This repository currently publishes the client and reusable client/owner utility libraries. It does not include a standalone controller installation, controller runtime, hosted control service or complete desktop engine. Do not treat this preview as a complete self-hosted-controller distribution.

## Start

Windows and Node.js 22.13+ with npm are required. Use normal, non-admin PowerShell:

```powershell
npx --yes --package=@thatnerddaniel/universalcontrol@0.10.2 universalcontrol
```

This command is intended for the reviewed public release. Before publication, use only an independently reviewed local artifact; do not substitute an unverified publisher or package.

On first run, the client asks for a hidden pairing code. Obtain it privately from the intended controller owner. No code means no enrollment contact with a controller. npm still contacts the npm registry to fetch this package. The client contains no owner-specific controller address or pin.

A valid code supplies connection/trust details. The client creates/reuses a Windows-account-protected device key, requests pairing, and waits for the owner to approve that device and fingerprint. Only then does it verify and install the owner-signed runtime. Runtime code executes as the local Windows user, subject to Windows permissions. Closing the foreground console disconnects; saved pairing is retained until revoked. This client adds no service or autostart.

Existing generic profiles reconnect without another code. If existing legacy state, unsupported Node or an ownership/integrity mismatch is reported, stop and inspect rather than deleting keys or retrying a mutation blindly. No new signing authority, controller installation or security-policy change is performed by normal client startup.

## Trust and privacy

- Verify the npm publisher and pinned version. A compromised distributor/controller can deliver code that runs with your account's access.
- The pairing code must come through a trusted owner channel. Its embedded key proves integrity under that key, not that an attacker-substituted invitation belongs to the intended owner.
- The compatible controller protocol uses high-entropy one-use/key-bound invitations, a maximum 15-minute admission window, explicit whole-machine owner approval and revocation. This package alone is not the controller.
- Codes belong in the hidden local prompt, never command arguments, URLs, chat, screenshots or public issues. Revealed/copied text can be retained by clipboard history or local software.
- Transport certificates are finite. Saved-key renewal depends on the compatible controller remaining available and honoring revocation. Do not interpret saved pairing as permission to ignore TLS expiry or Windows ACLs.

The optional `universalcontrol-owner` bin is only a private-code utility for an already configured compatible owner installation. It cannot install a controller or authorize an arbitrary remote machine by itself. Its display uses masked text/manual reveal and native visibility checks; those checks are not proof that a human saw a window. It does not approve device pairing.

## Current limits

This is an initial Windows client preview. The private reference controller is not generalized/published here. Owner provisioning, OAuth ingress, native desktop engine and runtime publishing are outside this repository's standalone setup. Full new-device enrollment still needs real second-machine acceptance; fixture tests do not establish that every Windows/session/application combination works. Node versions beyond the tested environment may need validation. The client's Node minimum does not imply compatibility of separate controller dependencies.

## Development

From a source checkout, no third-party npm packages are required:

```powershell
node --test test/*.test.mjs
```

Tests use mocked transports/helpers and disposable fixture state; they do not read production credentials or open Windows dialogs. Native DPAPI/UI/mTLS acceptance must be recorded separately. See SECURITY.md and PROVENANCE.md.

## License

MIT. See LICENSE. Preserve applicable copyright and permission notices when redistributing covered code.

Before approving on MAIN, compare its displayed device key SHA-256 fingerprint with the fingerprint printed on the actual enrolling PC. A matching hostname alone is insufficient. Reject any mismatch.
