<?php
if ( ! defined('ABSPATH') ) exit;

class SWPS_Settings_Export {

    public static function init() {
        add_action('wp_ajax_swps_export_settings', array(__CLASS__, 'ajax_export'));
        add_action('wp_ajax_swps_import_settings', array(__CLASS__, 'ajax_import'));
        add_action('wp_ajax_swps_reset_settings',  array(__CLASS__, 'ajax_reset'));
    }

    public static function export() {
        $keys = array(
            'swps_settings',
            'swps_blocked_ips',
            'swps_blocked_countries',
            'swps_whitelist_ips',
            'swps_away_mode',
            'swps_custom_login_url',
            'swps_waf_rules',
            'swps_file_baseline_meta',
            'swps_cf_zone_id',
        );

        $data = array(
            'version'    => '3.0.0',
            'exported'   => current_time('c'),
            'site_url'   => get_site_url(),
            'settings'   => array(),
        );

        foreach ($keys as $key) {
            $val = get_option($key);
            if ($val !== false) {
                $data['settings'][$key] = $val;
            }
        }

        // Exclude sensitive keys from export
        $sensitive = array('abuseipdb_api_key','cf_api_key','cf_email','hibp_api_key','wpscan_api_key','slack_webhook','telegram_bot_token','discord_webhook');
        if (isset($data['settings']['swps_settings'])) {
            foreach ($sensitive as $s) {
                unset($data['settings']['swps_settings'][$s]);
            }
        }

        return $data;
    }

    public static function ajax_export() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');

        $data     = self::export();
        $json     = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        $filename = 'swps-settings-' . date('Y-m-d') . '.json';

        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . strlen($json));
        echo $json;
        exit;
    }

    public static function ajax_import() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');

        if (empty($_FILES['import_file']['tmp_name'])) {
            wp_send_json_error('No file uploaded.');
        }

        $content = file_get_contents($_FILES['import_file']['tmp_name']);
        if (!$content) wp_send_json_error('Could not read file.');

        $data = json_decode($content, true);
        if (!$data || empty($data['settings']) || empty($data['version'])) {
            wp_send_json_error('Invalid settings file format.');
        }

        $imported = 0;
        $allowed_keys = array(
            'swps_settings',
            'swps_blocked_countries',
            'swps_whitelist_ips',
            'swps_away_mode',
            'swps_custom_login_url',
            'swps_waf_rules',
        );

        foreach ($data['settings'] as $key => $value) {
            if (in_array($key, $allowed_keys)) {
                update_option($key, $value);
                $imported++;
            }
        }

        SWPS_Audit_Trail::log('settings_imported', 'plugin', '', 'WP Secure Pro', "Imported $imported settings from file (v{$data['version']})");
        wp_send_json_success("Successfully imported $imported settings.");
    }

    public static function ajax_reset() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');

        $reset_keys = array(
            'swps_settings',
            'swps_blocked_ips',
            'swps_blocked_countries',
            'swps_whitelist_ips',
            'swps_away_mode',
            'swps_custom_login_url',
            'swps_waf_rules',
        );

        foreach ($reset_keys as $key) {
            delete_option($key);
        }

        SWPS_Audit_Trail::log('settings_reset', 'plugin', '', 'WP Secure Pro', 'All plugin settings have been reset to defaults.');
        wp_send_json_success('All settings have been reset.');
    }
}
