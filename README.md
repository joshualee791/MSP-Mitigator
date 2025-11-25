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
- MainWP or similar remote management ecosystems  
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

---

## 🔍 Profiles & Signatures

Each malware profile in `$malware_profiles` contains:

```
plugin_file   → the plugin’s main file
file_targets  → specific absolute paths to inspect
signatures    → malware-specific strings to match
```

You can add new malware families by extending this array.

---

## 🪓 Neutralization Process

For every infected file:

**PHP files** are replaced with a stub:

<?php  
// Neutralized malicious file…  
return;

**JSON and other files** are replaced with empty content.

After the **first confirmed match**, the plugin recursively neutralizes *the entire plugin directory*, replacing:

- all `.php` files with stubs  
- all other files with empty files  

The malicious plugin folder remains visible so it can be deleted safely.

---

## 🧪 Logging (Optional)

Enable debug logging by adding to `wp-config.php`:

define('WP_DEBUG_LOG', true);  
define('WP_DEBUG', true);

Neutralization logs will appear at:

`wp-content/debug.log`

Example:

[MSP Malware Mitigator] Neutralized file (either-interoperable-blob): includes/actual-resource.php  
[MSP Malware Mitigator] Recursively neutralized file (some-validated-workflow): vendor/.../likely.php  
[MSP Malware Mitigator] Deactivated plugin (either-interoperable-blob)

---

## 🧼 After Neutralization

After the plugin runs across your portfolio:

1. Review a few sites for confirmation  
2. Delete the neutralized malware plugin folders  
3. Rotate any potentially compromised credentials  
4. Run Wordfence or similar to verify no active payload remains  
5. Remove this mitigator plugin once cleanup is complete  

---

## 🛡️ Disclaimer

This plugin is intended strictly for defensive use in environments you administer.  
It does not exploit vulnerabilities or modify unrelated files.  
Use responsibly.

---

## 📄 License

MIT License.
