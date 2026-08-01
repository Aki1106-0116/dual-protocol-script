# Third-party notices

This project contains adapted portions of:

- `byJoey/fanout`, copyright 2026 Joey (byJoey), licensed under the MIT
  License. The original license text is preserved in this repository's
  `LICENSE`.

At installation time, the project downloads a pinned revision of:

- `Aki1106-0116/Three-Protocol-Script`,
  `jb-combo-installer.sh` at commit
  `68d15b2397bb8df8f058c004c29ac6872fded09d`.

The pinned script is transformed by `scripts/harden_node_installer.py`.
The transformer is intentionally narrow and fails closed when expected
function boundaries no longer match.
