# Attribution

droidmitm is licensed under AGPL-3.0 (see LICENSE).

This project's design is derived from study of HTTP Toolkit
(https://github.com/httptoolkit), copyright Tim Perry / httptoolkit,
itself licensed AGPL-3.0. Components adapted with license notices preserved:

- httptoolkit/httptoolkit-server — Android ADB interception pipeline
  (`src/interceptors/android/`) and Frida interception pipeline
  (`src/interceptors/frida/`), adapted in Phase 2/3.
- httptoolkit/frida-interception-and-unpinning — Android unpinning/proxy
  Frida scripts, adapted in Phase 3.
- httptoolkit/httptoolkit-android — VpnService companion-app approach,
  studied for Phase 4.

Built on mockttp (https://github.com/httptoolkit/mockttp), Apache-2.0.
