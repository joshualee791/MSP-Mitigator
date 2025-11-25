# MSP Malware Mitigator  
**A defensive WordPress fleet-wide malware neutralization plugin for WebOps environments**

The **MSP Malware Mitigator** is a purpose-built WordPress plugin designed to safely neutralize specific families of malicious plugins discovered across large multisite portfolios. It works by:

- Detecting known malicious plugins using signature-based matching  
- Overwriting infected files with inert stubs  
- Recursively neutralizing entire malicious plugin directories  
- Silently deactivating the infected plugins  
- Forcing them visible in the WordPress Plugins admin screen  
- Allowing centralized deletion via MainWP or other remote management tools  

This plugin was built for WebOps teams managing many independent WordPress installations where rapid containment is essential.

---

## 🚨 What This Plugin Does

Once deployed and activated, the plugin:

1. Runs on the next WordPress admin request (`admin_init`)  
2. Scans for known malware families defined in the `$malware_profiles` array  
3. When a file matches **two or more malware signatures**, it:
   - Overwrites that file with a neutral “stub”  
   - Recursively neutralizes *every file* inside that plugin folder  
4. Deactivates the malicious plugin  
5. Ensures the malicious plugin **appears** in the Plugins screen even if it previously hid itself  
6. Logs actions to `debug.log` when `WP_DEBUG_LOG` is enabled  

This tool acts like a targeted antivirus layer for WordPress — meant for *reaction and control*, not generic threat hunting.

---

## 🛑 What This Plugin Does NOT Do

- It does **not** scan arbitrary files or the rest of `wp-content`  
- It does **not** remove plugin folders automatically (you should delete them manually)  
- It does **not** clean database injections  
- It does **not** detect unknown malware beyond the signatures you define  
- It does **not** attempt to fix compromised themes or uploads  

It is intentionally conservative and defensive by design.

---

## 🎯 Use Case

This plugin is ideal for:

- Agencies and WebOps teams managing 50–500+ WordPress sites  
- Situations where a malware outbreak appears across multiple customer sites  
- Environments where manual cleaning is too slow or too risky  
- MainWP, ManageWP, or similar remote management ecosystems  
- Incidents where speed, safety, and stability matter more than forensic perfection  

If you're handling a distributed infection across many small WordPress installs, this plugin buys you time.

---

## ⚙️ How to Deploy

1. Download or clone this repo  
2. Zip the `msp-malware-mitigator/` directory  
3. Deploy via:
   - MainWP  
   - WordPress plugin uploader  
   - WP-CLI  
4. Activate the plugin  
5. Trigger an admin request by either:
   - Visiting `/wp-admin/` on each site  
   - Or letting MainWP’s sync/health checks trigger it automatically  

On first run, the plugin will neutralize matching malware families portfolio-wide.

---

## 🔍 Profiles & Signatures

Malware detection is driven by the `$malware_profiles` array, where each profile contains something like:

```php
[
    'plugin_file'  => 'slug/main-file.php',
    'file_targets' => [
        // Absolute paths from ABSPATH to inspect/neutralize
    ],
    'signatures'   => [
        // Malware-specific strings to match
    ],
]
```

You can add new malware families by extending this array with additional profiles.

---

## 🪓 Neutralization Process

For every infected file that matches at least **two** signatures:

### PHP files  
are replaced with a safe stub:

```php
<?php
/**
 * Neutralized malicious file...
 */
return;
```

### Non-PHP files (JSON, assets, misc)  
are replaced with empty content.

### After the first confirmed match for a profile

Once one file is confirmed as malware for a given profile, the plugin:

- Recursively walks the entire plugin directory for that profile.  
- Replaces **all** `.php` files with neutral stubs.  
- Blanks out all non-PHP files.  

The plugin folder is left in place so you can review it and then delete it safely via the WordPress admin or MainWP.

---

## 🧪 Logging (Optional)

To enable logging, add the following to `wp-config.php`:

```php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
```

Neutralization logs will then appear in:

```text
wp-content/debug.log
```

Example log entries:

```text
[MSP Malware Mitigator] Neutralized file (either-interoperable-blob): includes/actual-resource.php
[MSP Malware Mitigator] Recursively neutralized file (some-validated-workflow): vendor/.../likely.php
[MSP Malware Mitigator] Deactivated plugin (either-interoperable-blob): either-interoperable-blob/either-interoperable-blob.php
```

---

## 🧼 After Neutralization

After the plugin has run across your portfolio:

1. Review a few representative sites to confirm neutralization.  
2. Delete the neutralized malware plugin folders entirely.  
3. Rotate any potentially compromised credentials (WP admin, SFTP/SSH, etc.).  
4. Run Wordfence or a similar scanner to verify no active payload remains.  
5. Remove the MSP Malware Mitigator plugin once cleanup is complete.  

This plugin is an incident-response tool, not a permanent fixture.

---

## 🛡️ Disclaimer

This plugin is intended strictly for **defensive use** in environments you administer.  
It does not exploit vulnerabilities or modify unrelated files.  
Use responsibly.

---

## 📄 License

MIT License.
