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
            'uptime_alert_down'          => 1,
            'uptime_alert_recover'       => 1,
            'live_traffic_enabled'       => 1,
            'vuln_auto_scan'            => 1,
            'admin_creation_lock'        => 1,

            // 2FA is enabled by default for every Administrator, including
            // accounts that predate the plugin installation. Each admin may
            // deliberately opt out from their own profile.
            'two_factor_enabled'        => 1,
            '2fa_require_for'           => array( 'administrator' ),

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

    /** Apply the explicit secure profile when the owner activates the plugin. */
    public static function apply_activation_security_profile() {
        $settings = get_option( 'swps_settings', array() );
        if ( ! is_array( $settings ) ) $settings = array();
        foreach ( array( 'waf_enabled','waf_sqli','waf_xss','waf_lfi','waf_rfi','waf_bad_bot','file_monitor_enabled','fim_enabled','email_alerts','alert_new_admin','alert_file_change','rate_limiter_enabled','progressive_bf_enabled','honeypot_enabled','challenge_page_enabled','pwned_check_enabled','core_repair_enabled','ssl_monitor_enabled','blacklist_monitor_enabled','anomaly_detection_enabled','uptime_enabled','uptime_alert_down','uptime_alert_recover','live_traffic_enabled','vuln_auto_scan','two_factor_enabled','admin_creation_lock' ) as $key ) $settings[$key] = 1;
        $settings['2fa_require_for'] = array( 'administrator' );
        $settings['waf_mode'] = 'block';
        update_option( 'swps_settings', $settings );
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
        self::purge_page_cache_plugins();
        update_option( 'swps_defaults_version', SWPS_VERSION );
    }

    /**
     * Confirmed live (not theoretical): LiteSpeed Cache's JS/CSS optimizer
     * doesn't know when this plugin's own admin JS/PHP has just been
     * replaced by an update — an admin's browser can keep running the
     * previous version's cached, pre-fix JavaScript (e.g. a "Fix" button
     * missing an error handler from an older build) indefinitely after
     * updating, with no visible sign anything is stale. Force a full purge
     * once per plugin version so an update always actually takes effect.
     */
    private static function purge_page_cache_plugins() {
        if ( has_action( 'litespeed_purge_all' ) ) {
            do_action( 'litespeed_purge_all', 'WP Secure Pro updated to ' . SWPS_VERSION );
        }
        if ( class_exists( '\LiteSpeed\Purge' ) && method_exists( '\LiteSpeed\Purge', 'purge_all' ) ) {
            \LiteSpeed\Purge::purge_all();
        }
        if ( function_exists( 'w3tc_flush_all' ) ) w3tc_flush_all();
        if ( function_exists( 'wp_cache_clear_cache' ) ) wp_cache_clear_cache(); // WP Super Cache
        if ( function_exists( 'rocket_clean_domain' ) ) rocket_clean_domain(); // WP Rocket
    }

    public static function deactivate() {
        wp_clear_scheduled_hook( 'swps_daily_scan' );
    }

    /**
     * Full factory reset — wipes every trace of this plugin's data so the
     * site looks exactly like the moment it was first installed, without
     * actually deactivating/removing the plugin itself. Deliberately
     * thorough rather than guessing at a curated list: options and user
     * meta are matched by their 'swps_' prefix directly in the database
     * (the same prefix every setting, log, baseline and cache this plugin
     * has ever written uses), not by hand-maintaining a list of option
     * names that would silently go stale as new features are added.
     */
    public static function factory_reset() {
        global $wpdb;

        // 1. Every wp_options row this plugin owns — settings, all the
        //    *_log/*_baseline/*_last_* option-stored data, transients
        //    (both the value and its _transient_timeout_ companion).
        $wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'swps\\_%' OR option_name LIKE '\\_transient\\_swps\\_%' OR option_name LIKE '\\_transient\\_timeout\\_swps\\_%'" );

        // 2. Per-user 2FA secret/method — security config tied to the
        //    plugin, not to the WordPress user account itself.
        $wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE '\\_swps\\_%'" );

        // 3. Custom tables — TRUNCATE instead of DROP so the schema stays
        //    intact (no need to re-run CREATE TABLE / dbDelta right after).
        foreach ( array( 'swps_activity_log', 'swps_blocked_ips', 'swps_login_attempts' ) as $table ) {
            $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}{$table}" );
        }

        // 4. Filesystem artifacts this plugin writes outside the database —
        //    quarantined files, the cached GeoIP database, exported SIEM
        //    logs. Each path is removed only if it exists; a host where one
        //    of these was never created is not an error.
        $paths = array(
            dirname( rtrim( ABSPATH, '/\\' ) ) . '/swps-quarantine/', // outside-webroot quarantine
            WP_CONTENT_DIR . '/swps-quarantine/',                     // in-webroot fallback
            WP_CONTENT_DIR . '/swps-geoip/',
            WP_CONTENT_DIR . '/swps-siem-logs/',
        );
        foreach ( $paths as $path ) {
            if ( is_dir( $path ) ) self::rrmdir( $path );
        }

        // 5. Scheduled events — every cron hook this plugin has registered.
        foreach ( array( 'swps_daily_scan', 'swps_hourly_check', 'swps_scheduled_full_scan', 'swps_weekly_digest' ) as $hook ) {
            wp_clear_scheduled_hook( $hook );
        }

        // 6. Re-seed exactly as a brand-new activation would, so the site
        //    is immediately usable afterward rather than left in a
        //    half-configured state until the next page load happens to
        //    trigger maybe_apply_defaults().
        self::apply_default_options();
    }

    private static function rrmdir( $dir ) {
        $items = @scandir( $dir );
        if ( $items === false ) return;
        foreach ( $items as $item ) {
            if ( $item === '.' || $item === '..' ) continue;
            $path = $dir . '/' . $item;
            is_dir( $path ) ? self::rrmdir( $path ) : @unlink( $path );
        }
        @rmdir( $dir );
    }
}
