# Provenance inventory

The packaged JavaScript/PowerShell derives from the reviewed local UniversalControl generic client 0.10.1. Version 0.10.2 adds local device-fingerprint display before enrollment contact and corresponding owner-console comparison guidance, plus its version banner. Private controller HTTP rate limits are staged separately and are not part of this client-only distribution. Source deltas are recorded against the prior reviewed baseline. No private reference-controller artifact, actual owner configuration, runtime archive, credential, key or old development history is included.

No third-party npm dependency or bundled Node/Windows binary is included. Runtime imports use local files or Node built-ins. PowerShell/.NET/Windows APIs are operating-system requirements, not redistributed assemblies. Optional owner utility libraries are generic source; no configured owner authority accompanies them.

The public subset contains client installation/archive verification, protected storage, console/runtime lifecycle, generic invitation/proof handling and optional owner display utilities. Some shared source exports owner setup/signing functions, but they are not a configured controller or grant and require explicit local owner setup; no private signing identity is published.

No DesktopCommanderMCP implementation was imported into this release bundle. Internal project source history is not published here. A scan found no third-party copyright/license notices in the selected executable source; that is not proof of authorship for every historical line. The maintainer must confirm redistribution rights and any additional notices before approving this release. Do not remove third-party notices if later evidence identifies them.

This staged release proposes MIT with copyright attribution to ThatNerdDaniel (2026), subject to the owner's explicit approval. MIT permits commercial reuse and modification; it does not require downstream changes to be published. Its notice-preservation condition remains. A different license or copyright attribution requires resealing the package metadata/notice files. This proposal does not license the private controller or promise it will use the same terms later.

Canonical license reference: https://opensource.org/license/mit
