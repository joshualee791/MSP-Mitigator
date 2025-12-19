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
     * Option key to store last run timestamp (per-site).
     *
     * @var string
     */
    private $option_key = 'msp_malware_mitigator_last_run';

    /**
     * Profiles for known malware families.
     *
     * Each profile:
     * - plugin_file: the plugin's main file (relative to WP_PLUGIN_DIR) used for deactivation.
     * - file_targets: list of absolute-relative paths (from ABSPATH) to scan.
     * - signatures: list of string signatures; requires >=2 hits to trigger.
     *
     * @var array
     */
    private $malware_profiles = [

        // 1) either-interoperable-blob family
        'either-interoperable-blob' => [
            'plugin_file'  => 'either-interoperable-blob/either-interoperable-blob.php',
            'file_targets' => [
                // Core files we saw in the original sample
                'wp-content/plugins/either-interoperable-blob/either-interoperable-blob.php',
                'wp-content/plugins/either-interoperable-blob/class/intensely-complication-tenant.php',
                'wp-content/plugins/either-interoperable-blob/vendor/travel/alert.php',
                'wp-content/plugins/either-interoperable-blob/class/excited.php',
                'wp-content/plugins/either-interoperable-blob/vendor/rusty/really.php',
                'wp-content/plugins/either-interoperable-blob/vendor/rusty/conceptualize-narrowcast.php',
                'wp-content/plugins/either-interoperable-blob/class/excited.php',

                // Additional files flagged by Wordfence
                'wp-content/plugins/either-interoperable-blob/includes/actual-resource.php',
                'wp-content/plugins/either-interoperable-blob/vendor/travel/table-patiently.php'
            ],
            'signatures' => [
                // Strong anchors + common obfuscation indicators
                'Text Domain: either-interoperable-blob',
                'either_interoperable_blob',
                'base64_decode(',
                'gzinflate(',
                'eval(',
            ],
        ],

        // 2) some-validated-workflow family
        'some-validated-workflow' => [
            'plugin_file'  => 'some-validated-workflow/some-validated-workflow.php',
            'file_targets' => [
                'wp-content/plugins/some-validated-workflow/some-validated-workflow.php',
                'wp-content/plugins/some-validated-workflow/public/class-notice.php',
                'wp-content/plugins/some-validated-workflow/assets/hidden.php',
                'wp-content/plugins/some-validated-workflow/includes/legacy.php',
            ],
            'signatures' => [
                'Text Domain: some-validated-workflow',
                'some_validated_workflow',
                'base64_decode(',
                'gzinflate(',
                'eval(',
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
        add_action('admin_init', [$this, 'scan_and_clean_once']);
        add_filter('all_plugins', [$this, 'force_expose_malware_plugins'], 1000);
    }

    /**
     * Scan and clean once per hour.
     */
    function scan_and_clean_once() {
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
     */
    function handle_profile($slug, $profile) {
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
     */
    function looks_like_malware($contents, $signatures) {
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
     */
    function neutralize_single_file($full_path, $slug) {
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
            @file_put_contents($full_path, '');
        }
    }

    /**
     * Recursively neutralize all files within a plugin directory.
     */
    function neutralize_entire_plugin_dir($plugin_dir, $slug) {
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
     * Get the full plugin directory path from a plugin_file string.
     */
    function get_plugin_dir_from_file($plugin_file) {
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
     * Ensure these plugins show up in the plugin list, even if a malware author tries to hide them.
     */
    function force_expose_malware_plugins($plugins) {
        foreach ($this->malware_profiles as $slug => $profile) {
            if (empty($profile['plugin_file'])) {
                continue;
            }

            $plugin_file = $profile['plugin_file'];
            $full_path = WP_PLUGIN_DIR . '/' . $plugin_file;

            if (!file_exists($full_path) || !is_readable($full_path)) {
                continue;
            }

            if (isset($plugins[$plugin_file])) {
                continue;
            }

            $data = get_plugin_data($full_path, false, false);
            if (!empty($data) && !empty($data['Name'])) {
                $plugins[$plugin_file] = $data;
            }
        }

        return $plugins;
    }

    /**
     * Post-detection actions that only run AFTER a known profile has fired.
     * Keeps heuristics from ever running "standalone" and reduces false positives.
     */
    private function run_post_detection_actions($trigger_slug, $trigger_profile) {
        $payload = [
            'time'        => time(),
            'slug'        => (string) $trigger_slug,
            'plugin_file' => isset($trigger_profile['plugin_file']) ? (string) $trigger_profile['plugin_file'] : '',
        ];
        @update_option('msp_malware_mitigator_last_detection', $payload, false);

        $this->secondary_plugin_family_sweep($trigger_slug);
    }

    /**
     * Secondary heuristic sweep for malware "family" variants.
     * Runs ONLY after a confirmed profile match.
     */
    private function secondary_plugin_family_sweep($trigger_slug) {
        if (!defined('WP_PLUGIN_DIR') || !is_dir(WP_PLUGIN_DIR)) {
            return;
        }

        $last = (int) get_option('msp_malware_mitigator_last_family_sweep', 0);
        if ($last && (time() - $last) < 3600) {
            return;
        }
        @update_option('msp_malware_mitigator_last_family_sweep', time(), false);

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

                $this->deactivate_plugins_in_dir($plugin_dir);
                $this->neutralize_entire_plugin_dir($plugin_dir, $slug);
            }
        }
    }

    /**
     * Score a plugin directory for suspicious "family" artifacts.
     * Conservative: requires multiple independent signals.
     */
    private function score_suspicious_plugin_dir($plugin_dir) {
        $score = 0;

        $word_salad_hits = 0;
        $content_hits    = 0;

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

            if (preg_match('/^[a-z]+(?:-[a-z]+){1,4}\.(js|json|php)$/i', $base)) {
                $word_salad_hits++;
            }

            $size = (int) $file->getSize();
            if ($size > 0 && $size <= $max_bytes && is_readable($path)) {
                $chunk = @file_get_contents($path, false, null, 0, 60000);
                if (is_string($chunk) && $chunk !== '') {
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

                    if (strpos($chunk, 'Text Domain: these-middleware') !== false) {
                        $score += 3;
                    }
                }
            }
        }

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

        if (is_dir($plugin_dir . '/data/json') || is_dir($plugin_dir . '/sources')) {
            $score += 1;
        }

        return (int) $score;
    }

    /**
     * Best-effort attempt to deactivate any active plugins whose files live in a given directory.
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
     * Log to WP debug log (if enabled).
     */
    function log_event($message) {
        if (!defined('WP_DEBUG_LOG') || !WP_DEBUG_LOG) {
            return;
        }

        error_log('[MSP Malware Mitigator] ' . $message);
    }
}

new MSP_Malware_Mitigator();
