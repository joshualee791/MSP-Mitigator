<?php
/*
Plugin Name: MSP Malware Mitigator
Description: Neutralizes known malicious plugins across MSP sites by stubbing or wiping their files, deactivating them, and forcing them visible in the Plugins list.
Version: 0.3
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
     * - plugin_file: main plugin file as seen in the WP plugins list
     * - file_targets: relative paths from ABSPATH to inspect/neutralize
     * - signatures: unique strings used to confirm it's the right malware
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
                'wp-content/plugins/either-interoperable-blob/vendor/travel/table-patiently.php',
                'wp-content/plugins/either-interoperable-blob/includes/fully-violent.php',
                'wp-content/plugins/either-interoperable-blob/data/json/other.json',
                'wp-content/plugins/either-interoperable-blob/db/json/new-formal-self-reliant.json',
                'wp-content/plugins/either-interoperable-blob/vendor/rusty/heavy-bossy.php',
                'wp-content/plugins/either-interoperable-blob/class/plastic.php',
                'wp-content/plugins/either-interoperable-blob/vendor/owlishly/boastfully.php',
                'wp-content/plugins/either-interoperable-blob/vendor/rusty/rarely.php',
                'wp-content/plugins/either-interoperable-blob/includes/coordinated-lanky.php',
                'wp-content/plugins/either-interoperable-blob/irk-neatly-thongs.php',
            ],
            'signatures'   => [
                'Plugin Name: My strongly-consistent compiler',
                'Text Domain: either-interoperable-blob',
                'refine_cheerfully',
                'sadlysplitdirect',
                'coincidemajesticallywing',
            ],
        ],

        // 2) some-validated-workflow family
        'some-validated-workflow' => [
            'plugin_file'  => 'some-validated-workflow/some-validated-workflow.php',
            'file_targets' => [
                'wp-content/plugins/some-validated-workflow/some-validated-workflow.php',
                'wp-content/plugins/some-validated-workflow/includes/icy.php',
                'wp-content/plugins/some-validated-workflow/class/switchboard-lone.php',
                'wp-content/plugins/some-validated-workflow/class/fondly.php',
                'wp-content/plugins/some-validated-workflow/includes/syringe-microchip.php',
                'wp-content/plugins/some-validated-workflow/thoughtfully-responsible-successfully.php',
                'wp-content/plugins/some-validated-workflow/vendor/innocent_sheepishly/likely.php',

                // Additional file flagged by Wordfence
                'wp-content/plugins/some-validated-workflow/sources/sad.json',
            ],
            'signatures'   => [
                'Plugin Name: Both recovery meanwhile buffer',
                'Text Domain: some-validated-workflow',
                'cleverlypracticaldemob',
                'bookendpreregisterspiritdampen',
                'wellserve',
                'powerlessruingladlyeyeglasses',
                'rejiggerroyalpart',
            ],
        ],

        // Add more profiles here as you discover additional malware plugins.
    ];

    public function __construct() {
        // Main scanner / neutralizer – runs on admin requests with cooldown.
        add_action('admin_init', [$this, 'scan_and_clean_once']);

        // Force known malicious plugins to show up in the list
        // even if they try to hide via all_plugins filters.
        add_filter('all_plugins', [$this, 'force_expose_malware_plugins'], 999);
    }

    /**
     * Run the scanner at most once per hour per site on admin hits.
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
                $this->neutralize_single_file($full_path, $slug);
                $cleaned = true;
                $this->log_event("Neutralized file ({$slug}): {$rel_path}");

                // Once we've confirmed malware in one file, nuke the entire plugin dir.
                if ($plugin_dir) {
                    $this->neutralize_entire_plugin_dir($plugin_dir, $slug);
                }

                // No need to keep checking other targets for this profile to trigger recursion;
                // but continuing is harmless, so we just break here to avoid redundant work.
                break;
            }
        }

        // 2) Deactivate the plugin if present and active
        if ($plugin_file && function_exists('is_plugin_active') && is_plugin_active($plugin_file)) {
            deactivate_plugins($plugin_file, true); // silent deactivation
            $cleaned = true;
            $this->log_event("Deactivated plugin ({$slug}): {$plugin_file}");
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
        if (empty($signatures)) {
            return false;
        }

        $hits = 0;
        foreach ($signatures as $sig) {
            if ($sig !== '' && strpos($contents, $sig) !== false) {
                $hits++;
            }
        }

        // Require at least two matches to reduce false positives.
        return $hits >= 2;
    }

    /**
     * Neutralize a single file:
     * - If it's PHP, write a PHP stub.
     * - Otherwise, write an empty string.
     *
     * @param string $full_path
     * @param string $slug
     */
    private function neutralize_single_file($full_path, $slug) {
        if (!is_writable($full_path)) {
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
            // For JSON or other assets, blank them out.
            @file_put_contents($full_path, '');
        }
    }

    /**
     * Recursively neutralize all files in the plugin directory.
     *
     * For PHP files: write stub.
     * For non-PHP: blank them out.
     *
     * @param string $plugin_dir
     * @param string $slug
     */
    private function neutralize_entire_plugin_dir($plugin_dir, $slug) {
        if (!is_dir($plugin_dir)) {
            return;
        }

        // Use SPL iterators to walk the directory tree.
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
     * like 'slug/slug.php'.
     *
     * @param string $plugin_file
     * @return string
     */
    private function get_plugin_dir_from_file($plugin_file) {
        $rel_dir = dirname($plugin_file);
        return WP_PLUGIN_DIR . '/' . $rel_dir;
    }

    /**
     * Force malicious plugins to appear in the Plugins list,
     * even if they hook all_plugins and try to hide.
     *
     * Runs very late (priority 999) so it can override their tricks.
     *
     * @param array $plugins
     * @return array
     */
    public function force_expose_malware_plugins($plugins) {
        $slugs = [];

        foreach ($this->malware_profiles as $profile) {
            if (!empty($profile['plugin_file'])) {
                $slugs[] = $profile['plugin_file'];
            }
        }

        foreach ($slugs as $slug) {
            // If it's already visible, nothing to do.
            if (isset($plugins[$slug])) {
                continue;
            }

            // If the plugin main file doesn't exist, nothing to show.
            $plugin_path = WP_PLUGIN_DIR . '/' . $slug;
            if (!file_exists($plugin_path)) {
                continue;
            }

            // Inject a minimal placeholder entry so it shows up as a plugin.
            $plugins[$slug] = [
                'Name'        => 'Neutralized Malware (' . $slug . ')',
                'PluginURI'   => '',
                'Version'     => '0.0',
                'Description' => 'Previously malicious plugin neutralized by MSP Malware Mitigator.',
                'Author'      => 'MSP Ops',
                'AuthorURI'   => '',
                'TextDomain'  => '',
                'DomainPath'  => '',
                'Network'     => false,
                'Title'       => 'Neutralized Malware (' . $slug . ')',
                'AuthorName'  => 'MSP Ops',
            ];
        }

        return $plugins;
    }

    /**
     * Log to debug.log when WP_DEBUG_LOG is enabled.
     *
     * @param string $message
     */
    private function log_event($message) {
        if (!defined('WP_DEBUG_LOG') || !WP_DEBUG_LOG) {
            return;
        }

        error_log('[MSP Malware Mitigator] ' . $message);
    }
}

new MSP_Malware_Mitigator();
