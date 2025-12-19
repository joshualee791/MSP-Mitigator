<?php
/*
Plugin Name: MSP Malware Mitigator
Description: Neutralizes known malicious plugins across MSP sites by stubbing or wiping their files, deactivating them, and forcing them visible in the Plugins list.
Version: 0.6
Author: Joshua Garza, MSP WebOps
*/

if (!defined('ABSPATH')) {
    exit;
}

class MSP_Malware_Mitigator {

    /**
     * Option key to store last run timestamp.
     */
    private $option_key = 'msp_malware_mitigator_last_run';

    /**
     * Option key to store last family sweep timestamp.
     */
    private $family_sweep_option = 'msp_malware_mitigator_last_family_sweep';

    /**
     * Option key to store last detection breadcrumb.
     */
    private $last_detection_option = 'msp_malware_mitigator_last_detection';

    /**
     * Malware profiles:
     * - plugin_file: the plugin main file (relative to plugins dir), for deactivation.
     * - file_targets: relative paths from ABSPATH to check and neutralize.
     * - signatures: string signatures to match. We require >= 2 hits per file to trigger.
     */
    private $malware_profiles = [

        // 1) either-interoperable-blob (known malware plugin family)
        'either-interoperable-blob' => [
            'plugin_file'  => 'either-interoperable-blob/either-interoperable-blob.php',
            'file_targets' => [
                'wp-content/plugins/either-interoperable-blob/either-interoperable-blob.php',
                'wp-content/plugins/either-interoperable-blob/loader.php',
                'wp-content/plugins/either-interoperable-blob/assets/zigzag.php',
                'wp-content/plugins/either-interoperable-blob/includes/core.php',
            ],
            'signatures' => [
                'either_interoperable_blob',
                'interoperable_blob_loader',
                'wp_remote_post(',
                'base64_decode(',
                'eval(',
                'gzinflate(',
            ],
        ],

        // 2) either-propagation-interchange (known malware plugin family)
        'either-propagation-interchange' => [
            'plugin_file'  => 'either-propagation-interchange/either-propagation-interchange.php',
            'file_targets' => [
                'wp-content/plugins/either-propagation-interchange/either-propagation-interchange.php',
                'wp-content/plugins/either-propagation-interchange/loader.php',
                'wp-content/plugins/either-propagation-interchange/assets/zigzag.php',
                'wp-content/plugins/either-propagation-interchange/includes/core.php',
            ],
            'signatures' => [
                'either_propagation_interchange',
                'propagation_interchange_loader',
                'wp_remote_post(',
                'base64_decode(',
                'eval(',
                'gzinflate(',
            ],
        ],

        // 3) plug-sync-middleware (known malware plugin family)
        'plug-sync-middleware' => [
            'plugin_file'  => 'plug-sync-middleware/plug-sync-middleware.php',
            'file_targets' => [
                'wp-content/plugins/plug-sync-middleware/plug-sync-middleware.php',
                'wp-content/plugins/plug-sync-middleware/loader.php',
                'wp-content/plugins/plug-sync-middleware/assets/zigzag.php',
                'wp-content/plugins/plug-sync-middleware/includes/core.php',
            ],
            'signatures' => [
                'plug_sync_middleware',
                'sync_middleware_loader',
                'wp_remote_post(',
                'base64_decode(',
                'eval(',
                'gzinflate(',
            ],
        ],

        // 4) plug-notes-middleware (known malware plugin family)
        'plug-notes-middleware' => [
            'plugin_file'  => 'plug-notes-middleware/plug-notes-middleware.php',
            'file_targets' => [
                'wp-content/plugins/plug-notes-middleware/plug-notes-middleware.php',
                'wp-content/plugins/plug-notes-middleware/loader.php',
                'wp-content/plugins/plug-notes-middleware/assets/zigzag.php',
                'wp-content/plugins/plug-notes-middleware/includes/core.php',
            ],
            'signatures' => [
                'plug_notes_middleware',
                'notes_middleware_loader',
                'wp_remote_post(',
                'base64_decode(',
                'eval(',
                'gzinflate(',
            ],
        ],

        // 5) either-integration-middleware (known malware plugin family)
        'either-integration-middleware' => [
            'plugin_file'  => 'either-integration-middleware/either-integration-middleware.php',
            'file_targets' => [
                'wp-content/plugins/either-integration-middleware/either-integration-middleware.php',
                'wp-content/plugins/either-integration-middleware/loader.php',
                'wp-content/plugins/either-integration-middleware/assets/zigzag.php',
                'wp-content/plugins/either-integration-middleware/includes/core.php',
            ],
            'signatures' => [
                'either_integration_middleware',
                'integration_middleware_loader',
                'wp_remote_post(',
                'base64_decode(',
                'eval(',
                'gzinflate(',
            ],
        ],

        // 6) either-interop-middleware (known malware plugin family)
        'either-interop-middleware' => [
            'plugin_file'  => 'either-interop-middleware/either-interop-middleware.php',
            'file_targets' => [
                'wp-content/plugins/either-interop-middleware/either-interop-middleware.php',
                'wp-content/plugins/either-interop-middleware/loader.php',
                'wp-content/plugins/either-interop-middleware/assets/zigzag.php',
                'wp-content/plugins/either-interop-middleware/includes/core.php',
            ],
            'signatures' => [
                'either_interop_middleware',
                'interop_middleware_loader',
                'wp_remote_post(',
                'base64_decode(',
                'eval(',
                'gzinflate(',
            ],
        ],

        // 7) plug-bridge-middleware (known malware plugin family)
        'plug-bridge-middleware' => [
            'plugin_file'  => 'plug-bridge-middleware/plug-bridge-middleware.php',
            'file_targets' => [
                'wp-content/plugins/plug-bridge-middleware/plug-bridge-middleware.php',
                'wp-content/plugins/plug-bridge-middleware/loader.php',
                'wp-content/plugins/plug-bridge-middleware/assets/zigzag.php',
                'wp-content/plugins/plug-bridge-middleware/includes/core.php',
            ],
            'signatures' => [
                'plug_bridge_middleware',
                'bridge_middleware_loader',
                'wp_remote_post(',
                'base64_decode(',
                'eval(',
                'gzinflate(',
            ],
        ],

        // 8) plug-interchange-middleware (known malware plugin family)
        'plug-interchange-middleware' => [
            'plugin_file'  => 'plug-interchange-middleware/plug-interchange-middleware.php',
            'file_targets' => [
                'wp-content/plugins/plug-interchange-middleware/plug-interchange-middleware.php',
                'wp-content/plugins/plug-interchange-middleware/loader.php',
                'wp-content/plugins/plug-interchange-middleware/assets/zigzag.php',
                'wp-content/plugins/plug-interchange-middleware/includes/core.php',
            ],
            'signatures' => [
                'plug_interchange_middleware',
                'interchange_middleware_loader',
                'wp_remote_post(',
                'base64_decode(',
                'eval(',
                'gzinflate(',
            ],
        ],

        // 9) plug-matrix-middleware (known malware plugin family)
        'plug-matrix-middleware' => [
            'plugin_file'  => 'plug-matrix-middleware/plug-matrix-middleware.php',
            'file_targets' => [
                'wp-content/plugins/plug-matrix-middleware/plug-matrix-middleware.php',
                'wp-content/plugins/plug-matrix-middleware/loader.php',
                'wp-content/plugins/plug-matrix-middleware/assets/zigzag.php',
                'wp-content/plugins/plug-matrix-middleware/includes/core.php',
            ],
            'signatures' => [
                'plug_matrix_middleware',
                'matrix_middleware_loader',
                'wp_remote_post(',
                'base64_decode(',
                'eval(',
                'gzinflate(',
            ],
        ],

        // 10) plug-interface-middleware (known malware plugin family)
        'plug-interface-middleware' => [
            'plugin_file'  => 'plug-interface-middleware/plug-interface-middleware.php',
            'file_targets' => [
                'wp-content/plugins/plug-interface-middleware/plug-interface-middleware.php',
                'wp-content/plugins/plug-interface-middleware/loader.php',
                'wp-content/plugins/plug-interface-middleware/assets/zigzag.php',
                'wp-content/plugins/plug-interface-middleware/includes/core.php',
            ],
            'signatures' => [
                'plug_interface_middleware',
                'interface_middleware_loader',
                'wp_remote_post(',
                'base64_decode(',
                'eval(',
                'gzinflate(',
            ],
        ],

        // 11) plug-relay-middleware (known malware plugin family)
        'plug-relay-middleware' => [
            'plugin_file'  => 'plug-relay-middleware/plug-relay-middleware.php',
            'file_targets' => [
                'wp-content/plugins/plug-relay-middleware/plug-relay-middleware.php',
                'wp-content/plugins/plug-relay-middleware/loader.php',
                'wp-content/plugins/plug-relay-middleware/assets/zigzag.php',
                'wp-content/plugins/plug-relay-middleware/includes/core.php',
            ],
            'signatures' => [
                'plug_relay_middleware',
                'relay_middleware_loader',
                'wp_remote_post(',
                'base64_decode(',
                'eval(',
                'gzinflate(',
            ],
        ],

        // X) these-middleware (fake plugin malware family)
        'these-middleware' => [
            'plugin_file'  => 'these-middleware/these-middleware.php',
            'file_targets' => [
                // Core plugin files
                'wp-content/plugins/these-middleware/these-middleware.php',
                'wp-content/plugins/these-middleware/reorient.php',
                'wp-content/plugins/these-middleware/includes/always.php',
                'wp-content/plugins/these-middleware/class/duster.php',

                // Wordfence-flagged artifacts (JS/JSON)
                'wp-content/plugins/these-middleware/data/json/bug-noted-populist.json',
                'wp-content/plugins/these-middleware/sources/vibration-opera-ecstatic.json',
                'wp-content/plugins/these-middleware/includes/js/elegantly-spring.js',
                'wp-content/plugins/these-middleware/assets/js/ill-vibraphone-untried.js',
                'wp-content/plugins/these-middleware/frontend/js/fake-hunger-nun.js',
                'wp-content/plugins/these-middleware/assets/js/diligently-coagulate.js',
                'wp-content/plugins/these-middleware/assets/js/deceivingly.js',
                'wp-content/plugins/these-middleware/assets/js/passport.js',
                'wp-content/plugins/these-middleware/includes/js/nucleotidase.js',
                'wp-content/plugins/these-middleware/includes/js/thread-violently.js',
                'wp-content/plugins/these-middleware/frontend/js/tempting-wee-gum.js',
                'wp-content/plugins/these-middleware/includes/js/worst.js',
            ],
            'signatures' => [
                // Strong header anchors
                'Text Domain: these-middleware',
                'Plugin Name: Certain monolithic automation concurrently debugs',

                // Weird identifiers (low false positives)
                'cinderreceptornun',
                'dusk_stark_fidget_messy',
                '4b91d',

                // Asset/content anchors (very low false positives)
                '// sample_6_storage.js',
                'kjasdn7u3i1_setLocalStorage',
                'smoggy_knuckle_rectangular',
            ],
        ],
    ];

    public function __construct() {
        // Run on admin_init so current_user_can is meaningful and we avoid front-end disk churn.
        add_action('admin_init', [$this, 'scan_and_clean_once'], 1);

        // Make sure these plugins show up in the plugin list (so you can see them)
        add_filter('all_plugins', [$this, 'force_expose_malware_plugins'], 1000);
    }

    /**
     * Scan and clean once per hour.
     */
    public function scan_and_clean_once() {
        if (!current_user_can('manage_options')) {
            return;
        }

        $last_run = get_option($this->option_key);

        // Only run once per hour to avoid unnecessary disk churn.
        if ($last_run && (time() - (int) $last_run) < 3600) {
            return;
        }

        // Needed for is_plugin_active() / deactivate_plugins()
        include_once ABSPATH . 'wp-admin/includes/plugin.php';

        $anything_cleaned = false;

        foreach ($this->malware_profiles as $slug => $profile) {
            $profile_cleaned = $this->handle_profile($slug, $profile);
            if ($profile_cleaned) {
                $anything_cleaned = true;
            }
        }

        if ($anything_cleaned) {
            $this->log_event('MSP Malware Mitigator ran and took action.');
        }

        update_option($this->option_key, time());
    }

    /**
     * Handle one malware profile: stub/wipe files, deactivate plugin,
     * and recursively neutralize the whole plugin directory once a match is found.
     *
     * @param string $slug
     * @param array  $profile
     * @return bool true if this profile caused any changes
     */
    private function handle_profile($slug, $profile) {
        $cleaned = false;

        $file_targets = isset($profile['file_targets']) ? (array) $profile['file_targets'] : [];
        $signatures   = isset($profile['signatures'])   ? (array) $profile['signatures']   : [];
        $plugin_file  = isset($profile['plugin_file'])  ? $profile['plugin_file']          : null;

        $plugin_dir = null;
        if (!empty($plugin_file)) {
            $plugin_dir = $this->get_plugin_dir_from_file($plugin_file);
        }

        // 1) Neutralize files by overwriting with a harmless stub / blank.
        foreach ($file_targets as $rel_path) {
            $full_path = ABSPATH . $rel_path;

            if (!file_exists($full_path) || !is_readable($full_path)) {
                continue;
            }

            $contents = @file_get_contents($full_path);
            if ($contents === false) {
                continue;
            }

            if ($this->looks_like_malware($contents, $signatures)) {
                // Neutralize the file we matched on
                $this->neutralize_single_file($full_path, $slug);
                $cleaned = true;
                $this->log_event("Neutralized file ({$slug}): {$rel_path}");

                // Once we've confirmed malware in one file, nuke the entire plugin dir.
                if ($plugin_dir) {
                    $this->neutralize_entire_plugin_dir($plugin_dir, $slug);
                }

                // Break to avoid redundant work.
                break;
            }
        }

        // 2) Deactivate the plugin if present and active
        if ($plugin_file && function_exists('is_plugin_active') && is_plugin_active($plugin_file)) {
            deactivate_plugins($plugin_file, true); // silent deactivation
            $cleaned = true;
            $this->log_event("Deactivated plugin ({$slug}): {$plugin_file}");
        }

        if ($cleaned) {
            $this->run_post_detection_actions($slug, $profile);
        }

        return $cleaned;
    }

    /**
     * Very simple signature check: require at least 2 signature hits
     * before we call it malware and touch the file.
     *
     * @param string $contents
     * @param array  $signatures
     * @return bool
     */
    private function looks_like_malware($contents, $signatures) {
        $hits = 0;

        foreach ($signatures as $sig) {
            if ($sig === '' || $sig === null) {
                continue;
            }
            if (strpos($contents, $sig) !== false) {
                $hits++;
                if ($hits >= 2) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Overwrite a suspicious file with a harmless stub.
     *
     * @param string $full_path
     * @param string $slug
     * @return void
     */
    private function neutralize_single_file($full_path, $slug) {
        if (!file_exists($full_path) || !is_writable($full_path)) {
            $this->log_event("Cannot write to file ({$slug}): {$full_path}");
            return;
        }

        $ext = strtolower(pathinfo($full_path, PATHINFO_EXTENSION));

        if ($ext === 'php') {
            $stub = "<?php\n"
                . "/**\n"
                . " * Neutralized malicious file for profile: {$slug}\n"
                . " * This file previously contained a known malware payload.\n"
                . " */\n"
                . "return;\n";
            @file_put_contents($full_path, $stub);
        } else {
            // Non-PHP: blank it out.
            @file_put_contents($full_path, '');
        }
    }

    /**
     * Recursively neutralize all files within a plugin directory.
     *
     * @param string $plugin_dir
     * @param string $slug
     * @return void
     */
    private function neutralize_entire_plugin_dir($plugin_dir, $slug) {
        if (!is_dir($plugin_dir)) {
            return;
        }

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($plugin_dir, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
        } catch (Exception $e) {
            $this->log_event("Failed to iterate plugin dir ({$slug}): {$plugin_dir}");
            return;
        }

        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }

            $full_path = $file->getPathname();
            $this->neutralize_single_file($full_path, $slug);
            $this->log_event("Recursively neutralized file ({$slug}): {$full_path}");
        }
    }

    /**
     * Get the full plugin directory path from a plugin_file string
     * e.g. "bad-plugin/bad.php" => WP_PLUGIN_DIR . "/bad-plugin"
     *
     * @param string $plugin_file
     * @return string|null
     */
    private function get_plugin_dir_from_file($plugin_file) {
        if (!defined('WP_PLUGIN_DIR')) {
            return null;
        }

        $parts = explode('/', $plugin_file);
        if (empty($parts[0])) {
            return null;
        }

        return rtrim(WP_PLUGIN_DIR, '/') . '/' . $parts[0];
    }

    /**
     * Post-detection actions that only run AFTER a known profile has fired.
     * Keeps heuristics from ever running "standalone" and reduces false positives.
     *
     * @param string $trigger_slug
     * @param array  $trigger_profile
     * @return void
     */
    private function run_post_detection_actions($trigger_slug, $trigger_profile) {
        $payload = [
            'time'        => time(),
            'slug'        => (string) $trigger_slug,
            'plugin_file' => isset($trigger_profile['plugin_file']) ? (string) $trigger_profile['plugin_file'] : '',
        ];
        update_option($this->last_detection_option, $payload, false);

        // Secondary sweep: look for "same family" artifacts elsewhere.
        $this->secondary_plugin_family_sweep($trigger_slug);
    }

    /**
     * Secondary heuristic sweep for malware "family" variants.
     * Runs ONLY after a confirmed profile match.
     *
     * Strategy: score each plugin directory on multiple weak signals.
     * If a directory crosses a threshold, neutralize the entire directory.
     *
     * @param string $trigger_slug
     * @return void
     */
    private function secondary_plugin_family_sweep($trigger_slug) {
        if (!defined('WP_PLUGIN_DIR') || !is_dir(WP_PLUGIN_DIR)) {
            return;
        }

        // Avoid re-running too frequently (per-site).
        $last = (int) get_option($this->family_sweep_option, 0);
        if ($last && (time() - $last) < 3600) {
            return;
        }
        update_option($this->family_sweep_option, time(), false);

        $self_dir = basename(dirname(__FILE__));
        $base     = rtrim(WP_PLUGIN_DIR, '/');

        $dirs = @scandir($base);
        if (!is_array($dirs)) {
            return;
        }

        foreach ($dirs as $d) {
            if ($d === '.' || $d === '..') {
                continue;
            }
            if ($d === $self_dir) {
                continue;
            }

            $plugin_dir = $base . '/' . $d;
            if (!is_dir($plugin_dir) || !is_readable($plugin_dir)) {
                continue;
            }

            $score = $this->score_suspicious_plugin_dir($plugin_dir);
            if ($score >= 3) {
                $slug = 'family-sweep:' . $trigger_slug;
                $this->log_event("Family sweep flagged dir (score={$score}) triggered by {$trigger_slug}: {$plugin_dir}");

                // Best-effort: deactivate any plugins in this directory.
                $this->deactivate_plugins_in_dir($plugin_dir);

                // Neutralize the whole directory to prevent re-execution.
                $this->neutralize_entire_plugin_dir($plugin_dir, $slug);
            }
        }
    }

    /**
     * Score a plugin directory for suspicious "family" artifacts.
     * Conservative: requires multiple independent signals.
     *
     * @param string $plugin_dir
     * @return int
     */
    private function score_suspicious_plugin_dir($plugin_dir) {
        $score = 0;

        $word_salad_hits = 0;
        $content_hits    = 0;

        // Limit work to avoid timeouts.
        $max_files = 250;
        $max_bytes = 300000; // 300 KB
        $seen      = 0;

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($plugin_dir, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
        } catch (Exception $e) {
            return 0;
        }

        foreach ($iterator as $file) {
            if ($seen >= $max_files) {
                break;
            }
            if (!$file->isFile()) {
                continue;
            }

            $seen++;
            $path = $file->getPathname();
            $ext  = strtolower(pathinfo($path, PATHINFO_EXTENSION));

            if (!in_array($ext, ['js', 'json', 'php'], true)) {
                continue;
            }

            $base = basename($path);

            // "word-salad" filenames common in this family
            if (preg_match('/^[a-z]+(?:-[a-z]+){1,4}\.(js|json|php)$/i', $base)) {
                $word_salad_hits++;
            }

            $size = (int) $file->getSize();
            if ($size > 0 && $size <= $max_bytes && is_readable($path)) {
                $chunk = @file_get_contents($path, false, null, 0, 60000); // 60KB
                if (is_string($chunk) && $chunk !== '') {
                    // Content anchors observed in these-middleware family
                    $anchors = [
                        'kjasdn7u3i1_setLocalStorage',
                        'smoggy_knuckle_rectangular',
                        'sample_6_storage.js',
                        'localStorage.setItem(',
                        'sessionStorage.setItem(',
                    ];
                    foreach ($anchors as $a) {
                        if (strpos($chunk, $a) !== false) {
                            $content_hits++;
                            break;
                        }
                    }

                    // Strong signal: exact Text Domain for known family.
                    if (strpos($chunk, 'Text Domain: these-middleware') !== false) {
                        $score += 3;
                    }
                }
            }
        }

        // Convert hit counts into conservative score increments.
        if ($word_salad_hits >= 6) {
            $score += 1;
        }
        if ($word_salad_hits >= 12) {
            $score += 1;
        }

        if ($content_hits >= 2) {
            $score += 2;
        } elseif ($content_hits >= 1) {
            $score += 1;
        }

        // Folder-structure hints
        if (is_dir($plugin_dir . '/data/json') || is_dir($plugin_dir . '/sources')) {
            $score += 1;
        }

        return (int) $score;
    }

    /**
     * Best-effort attempt to deactivate any active plugins whose files live in a given directory.
     *
     * @param string $plugin_dir
     * @return void
     */
    private function deactivate_plugins_in_dir($plugin_dir) {
        if (!function_exists('get_plugins')) {
            include_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        if (!function_exists('get_plugins')) {
            return;
        }

        $all = get_plugins();
        if (!is_array($all)) {
            return;
        }

        foreach ($all as $plugin_file => $data) {
            $full = WP_PLUGIN_DIR . '/' . $plugin_file;
            if (strpos($full, rtrim($plugin_dir, '/') . '/') === 0) {
                if (function_exists('is_plugin_active') && is_plugin_active($plugin_file)) {
                    deactivate_plugins($plugin_file, true);
                    $this->log_event("Family sweep deactivated plugin: {$plugin_file}");
                }
            }
        }
    }

    /**
     * Ensure these plugins show up in the plugin list, even if a malware author tries to hide them.
     */
    function force_expose_malware_plugins($plugins) {
        // Defensive: ensure the plugin headers for known malware plugin files are discoverable.
        // This does NOT activate them; it only helps admins see them in the UI.
        foreach ($this->malware_profiles as $slug => $profile) {
            if (empty($profile['plugin_file'])) {
                continue;
            }

            $plugin_file = $profile['plugin_file'];
            $full_path = WP_PLUGIN_DIR . '/' . $plugin_file;

            if (!file_exists($full_path) || !is_readable($full_path)) {
                continue;
            }

            // If already visible, skip
            if (isset($plugins[$plugin_file])) {
                continue;
            }

            // Attempt to read plugin data
            $data = get_plugin_data($full_path, false, false);
            if (!empty($data) && !empty($data['Name'])) {
                $plugins[$plugin_file] = $data;
            }
        }

        return $plugins;
    }

    /**
     * Log to WP debug log (if enabled).
     *
     * @param string $message
     * @return void
     */
    private function log_event($message) {
        if (!defined('WP_DEBUG_LOG') || !WP_DEBUG_LOG) {
            return;
        }
        error_log('[MSP Malware Mitigator] ' . $message);
    }
}

new MSP_Malware_Mitigator();