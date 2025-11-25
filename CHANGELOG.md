# Changelog
All notable changes to this project will be documented in this file.

---

## [0.5] - 2025-11-25
### Added
- Recursive malware neutralization across entire malicious plugin directories.
- Wordfence-informed file targets for `either-interoperable-blob` and `some-validated-workflow`.
- Improved neutralization logic for non-PHP assets (JSON, misc files).
- Forced plugin visibility via late `all_plugins` hook.
- Full documentation and README.md.

### Changed
- Strengthened signature matching rules.
- Cleaned structure for malware profiles and plugin directory resolution.

### Fixed
- Issue where malware hid itself from the plugin list.
- Edge case where some malicious files were not stubbed.

---

## [0.4] - 2025-11-24
### Added
- Initial neutralizer plugin with signature-based file stubbing.
- Core logic for per-file neutralization.
- Deactivation of malicious plugins when detected.

---

## [0.1–0.3] - 2025-11-24
### Added
- Early prototypes of the malware mitigator.
- Testing builds and local verification.
