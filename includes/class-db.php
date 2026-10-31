<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_DB {

    public static function install() {
        global $wpdb;
        $charset = $wpdb->get_charset_collate();

        $sql1 = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}swps_activity_log (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            event_type varchar(50) NOT NULL,
            severity varchar(20) NOT NULL DEFAULT 'info',
            user_id bigint(20) DEFAULT 0,
            username varchar(100) DEFAULT '',
            ip_address varchar(45) DEFAULT '',
            description text NOT NULL,
            extra_data longtext DEFAULT '',
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY event_type (event_type),
            KEY severity (severity),
            KEY created_at (created_at)
        ) $charset;";

        $sql2 = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}swps_blocked_ips (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            reason varchar(255) DEFAULT '',
            blocked_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at datetime DEFAULT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY ip_address (ip_address)
        ) $charset;";

        $sql3 = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}swps_login_attempts (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            username varchar(100) DEFAULT '',
            attempted_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY attempted_at (attempted_at)
        ) $charset;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql1 );
        dbDelta( $sql2 );
        dbDelta( $sql3 );

        self::apply_default_options();
    }

    /**
     * Applies safe default options, filling only missing keys so the owner's
     * explicit choices are never overridden. Called on activation and, once
     * per version, on load (so existing sites get new defaults without a
     * manual reactivation).
     */
    public static function apply_default_options() {
        // Default settings. Only zero-config, safe-to-run protections are ON
        // by default. Anything needing API keys, credentials, per-user setup,
        // a slug/country list, or that could lock the owner out stays OFF.
        $defaults = array(
            // Core login protection
            'max_login_attempts'   => 5,
            'lockout_duration'     => 30,

            // Email alerts (goes to admin_email — no owner action needed)
            'alert_email'          => get_option('admin_email'),
            'email_alerts'         => 1,
            'alert_new_admin'      => 1,
            'alert_login_fail'     => 1,
            'alert_file_change'    => 1,

            // File monitoring
            'file_monitor_enabled' => 1,
            'fim_enabled'          => 1,

            // Firewall (WAF) — works out of the box
            'waf_enabled'          => 1,
            'waf_mode'             => 'block',
            'waf_sqli'             => 1,
            'waf_xss'              => 1,
            'waf_lfi'              => 1,
            'waf_rfi'              => 1,
            'waf_bad_bot'          => 1,

            // Security response headers
            'security_headers_enabled' => 1,

            // Rate limiting & brute-force
            'rate_limiter_enabled'   => 1,
            'progressive_bf_enabled' => 1,

            // Deception / conditional (no config, only acts on suspicious IPs)
            'honeypot_enabled'       => 1,
            'challenge_page_enabled' => 1,

            // Keyless intelligence / monitoring
            'pwned_check_enabled'       => 1,
            'core_repair_enabled'       => 1,
            'ssl_monitor_enabled'       => 1,
            'blacklist_monitor_enabled' => 1,
            'anomaly_detection_enabled' => 1,
            'uptime_enabled'            => 1,
            'vuln_auto_scan'            => 1,

            // 2FA system ON — this only makes 2FA *available*; it never forces
            // anyone (2fa_require_for is empty) and cannot lock anyone out until
            // a user opts in from their own profile. So it is safe by default.
            'two_factor_enabled'        => 1,

            // Left OFF by default — these carry real risk or need owner input:
            //   geoip_enabled, away_mode_enabled, login_url  -> lockout risk
            //   captcha_enabled, threat_feed_enabled, cloudflare_enabled,
            //   siem_enabled, ms_hub_enabled                 -> need API keys
            //   fake_login_enabled, canary_enabled           -> need owner setup
            //   threat_feed_server_enabled                   -> exposes a public endpoint
            //   live_traffic_enabled                         -> per-request performance cost
            //   white_label, webhooks                        -> owner-specific config
            'login_url'            => '',
        );

        // Fill only missing keys — never override the owner's explicit choices.
        $existing = get_option( 'swps_settings', array() );
        if ( ! is_array( $existing ) ) $existing = array();
        update_option( 'swps_settings', array_merge( $defaults, $existing ) );

        // Hardening defaults (its own option) — safe baseline.
        if ( class_exists( 'SWPS_Hardening' ) ) {
            $h_existing = get_option( 'swps_hardening', array() );
            if ( ! is_array( $h_existing ) ) $h_existing = array();
            update_option( 'swps_hardening', array_merge( SWPS_Hardening::get_defaults(), $h_existing ) );
        }

        // Security header defaults (its own option).
        if ( class_exists( 'SWPS_Security_Headers' ) ) {
            $hd_existing = get_option( 'swps_headers', array() );
            if ( ! is_array( $hd_existing ) ) $hd_existing = array();
            update_option( 'swps_headers', array_merge( SWPS_Security_Headers::get_defaults(), $hd_existing ) );
        }
    }

    /**
     * Apply defaults once per version without requiring a reactivation.
     */
    public static function maybe_apply_defaults() {
        if ( get_option( 'swps_defaults_version' ) === SWPS_VERSION ) return;
        self::apply_default_options();
        // Purge caches that may hold results from an older scanner version
        // (e.g. a stale Spamhaus false positive) so the new logic re-runs clean.
        delete_transient( 'swps_blacklist_status' );
        delete_option( 'swps_blacklist_last_check' );
        update_option( 'swps_defaults_version', SWPS_VERSION );
    }

    public static function deactivate() {
        wp_clear_scheduled_hook( 'swps_daily_scan' );
    }
}
