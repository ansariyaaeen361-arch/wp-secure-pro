<?php
if ( ! defined('ABSPATH') ) exit;

class SWPS_Core_Repair {

    const CHECKSUMS_API = 'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s';

    public static function init() {
        $settings = get_option('swps_settings', array());
        if (empty($settings['core_repair_enabled'])) return;

        add_action('swps_daily_cron',          array(__CLASS__, 'scheduled_check'));
        add_action('wp_ajax_swps_core_verify', array(__CLASS__, 'ajax_verify'));
        add_action('wp_ajax_swps_core_repair', array(__CLASS__, 'ajax_repair'));
    }

    /* ── Fetch official checksums from WordPress.org ── */
    public static function get_checksums() {
        $version = get_bloginfo('version');
        $locale  = get_locale();
        $url     = sprintf(self::CHECKSUMS_API, $version, $locale);

        $cached = get_transient('swps_core_checksums');
        if ($cached) return $cached;

        $resp = wp_remote_get($url, array('timeout' => 20));
        if (is_wp_error($resp)) return false;

        $body = json_decode(wp_remote_retrieve_body($resp), true);
        if (empty($body['checksums'])) return false;

        set_transient('swps_core_checksums', $body['checksums'], 12 * HOUR_IN_SECONDS);
        return $body['checksums'];
    }

    /* ── Verify core files against checksums ── */
    public static function verify() {
        $checksums = self::get_checksums();
        if (!$checksums) {
            return array('error' => 'Could not fetch checksums from WordPress.org');
        }

        $abspath   = rtrim(ABSPATH, '/\\') . '/';
        $modified  = array();
        $missing   = array();

        foreach ($checksums as $file => $hash) {
            // Skip wp-content — user data
            if (strpos($file, 'wp-content/') === 0) continue;

            $full_path = $abspath . $file;

            if (!file_exists($full_path)) {
                $missing[] = $file;
                continue;
            }

            $actual = md5_file($full_path);
            if ($actual !== $hash) {
                $modified[] = array(
                    'file'     => $file,
                    'expected' => $hash,
                    'actual'   => $actual,
                );
            }
        }

        $result = array(
            'total'     => count($checksums),
            'ok'        => count($checksums) - count($modified) - count($missing),
            'modified'  => $modified,
            'missing'   => $missing,
            'checked_at'=> time(),
        );

        update_option('swps_core_verify_result', $result, false);

        if (!empty($modified) || !empty($missing)) {
            $notify = SWPS_Notifications::get_instance();
            $notify->send(
                'core_modified',
                'WordPress Core Files Modified',
                count($modified) . ' modified, ' . count($missing) . ' missing core files detected.',
                'critical'
            );
            SWPS_Audit_Trail::log('core_files_modified', 'core', '', 'WordPress Core',
                count($modified) . ' modified + ' . count($missing) . ' missing');
        }

        return $result;
    }

    /* ── Re-download and restore a single core file ── */
    public static function repair_file($rel_path) {
        $rel_path  = ltrim(str_replace('..', '', $rel_path), '/\\');
        $checksums = self::get_checksums();
        if (!isset($checksums[$rel_path])) {
            return array('success' => false, 'message' => 'File not in checksums list.');
        }

        $version  = get_bloginfo('version');
        $dl_url   = "https://core.svn.wordpress.org/tags/{$version}/{$rel_path}";
        $response = wp_remote_get($dl_url, array('timeout' => 30));

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return array('success' => false, 'message' => 'Could not download file from WordPress.org.');
        }

        $content   = wp_remote_retrieve_body($response);
        $full_path = rtrim(ABSPATH, '/\\') . '/' . $rel_path;
        $dir       = dirname($full_path);

        if (!file_exists($dir)) wp_mkdir_p($dir);

        // Backup original before overwrite
        if (file_exists($full_path)) {
            copy($full_path, $full_path . '.swps_bak_' . date('Ymd_His'));
        }

        if (!file_put_contents($full_path, $content)) {
            return array('success' => false, 'message' => 'Could not write file — check permissions.');
        }

        // Verify after repair
        $new_hash = md5_file($full_path);
        if ($new_hash !== $checksums[$rel_path]) {
            return array('success' => false, 'message' => 'File written but hash still wrong.');
        }

        SWPS_Audit_Trail::log('core_file_repaired', 'core', '', $rel_path, 'Restored from WordPress.org SVN');
        return array('success' => true, 'message' => "Repaired: $rel_path");
    }

    /* ── Repair all modified/missing files at once ── */
    public static function repair_all() {
        $result = get_option('swps_core_verify_result', array());
        if (empty($result)) {
            $result = self::verify();
        }

        $repaired = 0; $failed = 0; $errors = array();

        foreach (array_merge($result['modified'] ?? array(), array_map(fn($f) => array('file'=>$f), $result['missing'] ?? array())) as $item) {
            $file = is_array($item) ? $item['file'] : $item;
            $r    = self::repair_file($file);
            if ($r['success']) $repaired++; else { $failed++; $errors[] = $file; }
        }

        return array('repaired' => $repaired, 'failed' => $failed, 'errors' => $errors);
    }

    public static function scheduled_check() {
        $settings = get_option('swps_settings', array());
        if (!empty($settings['core_repair_enabled'])) {
            self::verify();
        }
    }

    public static function ajax_verify() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        wp_send_json_success(self::verify());
    }

    public static function ajax_repair() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $file = sanitize_text_field($_POST['file'] ?? '');
        if ($file === '__all__') {
            wp_send_json_success(self::repair_all());
        } else {
            wp_send_json_success(self::repair_file($file));
        }
    }
}
