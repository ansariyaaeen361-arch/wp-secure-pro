<?php
/**
 * Plugin Name: SecureWP Shield
 * Plugin URI:  https://yoursite.com
 * Description: Enterprise WordPress Security Suite — WAF, 2FA, Full Site Scan, Core Repair, Honeypot, Rate Limiter, Challenge Page, DNA Scanner, Canary Tokens, IP Reputation, SIEM, Multi-Site Monitor, Threat Feed Server
 * Version:     5.0.0
 * Author:      Yaseen
 * Author URI:  https://yoursite.com
 * Text Domain: securewp-shield
 * Update URI:  https://github.com/ansariyaaeen361-arch/securewp-shield
 */

if ( ! defined( 'ABSPATH' ) ) exit;

define( 'SWPS_VERSION',     '5.0.0' );
define( 'SWPS_AUTHOR',      'Yaseen' );
define( 'SWPS_PLUGIN_DIR',  plugin_dir_path( __FILE__ ) );
define( 'SWPS_PLUGIN_URL',  plugin_dir_url( __FILE__ ) );
define( 'SWPS_TABLE_LOG',   'swps_activity_log' );
define( 'SWPS_TABLE_IPS',   'swps_blocked_ips' );
define( 'SWPS_TABLE_LOGINS','swps_login_attempts' );

// ─── Core classes (order matters — later classes depend on earlier) ────────────
require_once SWPS_PLUGIN_DIR . 'includes/class-db.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-email-alerts.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-activity-log.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-login-protection.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-ip-blocker.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-admin-monitor.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-scanner.php';

// ─── Phase 1: Advanced protection ─────────────────────────────────────────────
require_once SWPS_PLUGIN_DIR . 'includes/class-waf.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-two-factor.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-login-url.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-hardening.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-security-headers.php';

// ─── Phase 2: Intelligence & monitoring ───────────────────────────────────────
require_once SWPS_PLUGIN_DIR . 'includes/class-captcha.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-geoip.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-live-traffic.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-vuln-scanner.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-db-monitor.php';

// ─── Phase 3: Enterprise features ─────────────────────────────────────────────
require_once SWPS_PLUGIN_DIR . 'includes/class-away-mode.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-blacklist-monitor.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-white-label.php';

// ─── Tier 1: Extreme protection ────────────────────────────────────────────────
require_once SWPS_PLUGIN_DIR . 'includes/class-file-integrity.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-session-manager.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-pwned-check.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-progressive-brute-force.php';

// ─── Tier 2: Intelligence ──────────────────────────────────────────────────────
require_once SWPS_PLUGIN_DIR . 'includes/class-threat-feed.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-notifications.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-ssl-monitor.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-cloudflare.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-uptime-monitor.php';

// ─── Tier 3: Pro management ────────────────────────────────────────────────────
require_once SWPS_PLUGIN_DIR . 'includes/class-webhooks.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-audit-trail.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-anomaly-detection.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-report-digest.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-settings-export.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-cli.php';

// ─── Tier 4: Visual / UX ──────────────────────────────────────────────────────
require_once SWPS_PLUGIN_DIR . 'includes/class-dashboard-widget.php';

// ─── Full Site Scan ───────────────────────────────────────────────────────────
require_once SWPS_PLUGIN_DIR . 'includes/class-full-scan.php';

// ─── Tier 5: Self-Healing & Auto-Response ─────────────────────────────────────
require_once SWPS_PLUGIN_DIR . 'includes/class-core-repair.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-challenge-page.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-honeypot.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-rate-limiter.php';

// ─── Tier 6: Threat Intelligence & Deception ─────────────────────────────────
require_once SWPS_PLUGIN_DIR . 'includes/class-ip-reputation.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-canary-tokens.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-fake-login.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-malware-dna.php';

// ─── Tier 7: SIEM & Multi-Site ────────────────────────────────────────────────
require_once SWPS_PLUGIN_DIR . 'includes/class-siem-export.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-multisite-monitor.php';
require_once SWPS_PLUGIN_DIR . 'includes/class-threat-feed-server.php';

// ─── Self-hosted updates (private GitHub repo) ────────────────────────────────
require_once SWPS_PLUGIN_DIR . 'includes/class-github-updater.php';

// ─── Custom cron intervals ────────────────────────────────────────────────────
add_filter('cron_schedules', function($schedules) {
    if (!isset($schedules['swps_5min'])) {
        $schedules['swps_5min'] = array('interval' => 300, 'display' => 'Every 5 Minutes');
    }
    if (!isset($schedules['swps_weekly'])) {
        $schedules['swps_weekly'] = array('interval' => WEEK_IN_SECONDS, 'display' => 'Once Weekly');
    }
    return $schedules;
});

// ─── Activation / Deactivation ────────────────────────────────────────────────
register_activation_hook( __FILE__, 'swps_activate' );
register_deactivation_hook( __FILE__, 'swps_deactivate' );

function swps_activate() {
    SWPS_DB::install();
    SWPS_Audit_Trail::create_table();
    if ( ! wp_next_scheduled('swps_hourly_check') ) {
        wp_schedule_event( time(), 'hourly', 'swps_hourly_check' );
    }
    if ( ! wp_next_scheduled('swps_daily_cron') ) {
        wp_schedule_event( time(), 'daily', 'swps_daily_cron' );
    }
}

function swps_deactivate() {
    wp_clear_scheduled_hook('swps_hourly_check');
    wp_clear_scheduled_hook('swps_daily_cron');
}

// ─── Boot all classes ──────────────────────────────────────────────────────────
add_action( 'plugins_loaded', 'swps_init' );
function swps_init() {
    // Apply safe default settings once per version (no reactivation needed).
    SWPS_DB::maybe_apply_defaults();

    // Core
    SWPS_Activity_Log::init();
    SWPS_Login_Protection::init();
    SWPS_IP_Blocker::init();
    SWPS_Admin_Monitor::init();

    // Phase 1
    SWPS_WAF::init();
    SWPS_Two_Factor::init();
    SWPS_Login_URL::init();
    SWPS_Hardening::init();
    SWPS_Security_Headers::init();

    // Phase 2
    SWPS_Captcha::init();
    SWPS_GeoIP::init();
    SWPS_Live_Traffic::init();
    SWPS_Vuln_Scanner::init();
    SWPS_DB_Monitor::init();

    // Phase 3
    SWPS_Away_Mode::init();
    SWPS_Blacklist_Monitor::init();
    SWPS_White_Label::init();

    // Tier 1
    SWPS_File_Integrity::init();
    SWPS_Session_Manager::init();
    SWPS_Pwned_Check::init();
    SWPS_Progressive_Brute_Force::init();

    // Tier 2
    SWPS_Threat_Feed::init();
    SWPS_Notifications::init();
    SWPS_SSL_Monitor::init();
    SWPS_Cloudflare::init();
    SWPS_Uptime_Monitor::init();

    // Tier 3
    SWPS_Webhooks::init();
    SWPS_Audit_Trail::init();
    SWPS_Anomaly_Detection::init();
    SWPS_Report_Digest::init();
    SWPS_Settings_Export::init();

    // Tier 4
    SWPS_Dashboard_Widget::init();

    // Full Scan
    SWPS_Full_Scan::init();

    // Tier 5
    SWPS_Core_Repair::init();
    SWPS_Challenge_Page::init();
    SWPS_Honeypot::init();
    SWPS_Rate_Limiter::init();

    // Tier 6
    SWPS_IP_Reputation::init();
    SWPS_Canary_Tokens::init();
    SWPS_Fake_Login::init();

    // Tier 7
    SWPS_SIEM_Export::init();
    SWPS_Multisite_Monitor::init();
    SWPS_Threat_Feed_Server::init();

    // Self-hosted updates
    SWPS_GitHub_Updater::init();
}

// ─── Admin menu ───────────────────────────────────────────────────────────────
add_action( 'admin_menu', 'swps_admin_menu' );
function swps_admin_menu() {
    $wl       = get_option('swps_white_label', array());
    $menu_name = ( ! empty($wl['enabled']) && ! empty($wl['menu_name']) ) ? $wl['menu_name'] : 'SecureWP Shield';

    add_menu_page(
        $menu_name, $menu_name, 'manage_options',
        'swps-dashboard', 'swps_dashboard_page',
        'dashicons-shield', 2
    );

    // Primary pages
    add_submenu_page( 'swps-dashboard', 'Dashboard',        'Dashboard',        'manage_options', 'swps-dashboard',      'swps_dashboard_page' );
    add_submenu_page( 'swps-dashboard', 'Activity Log',     'Activity Log',     'manage_options', 'swps-activity-log',   'swps_activity_log_page' );
    add_submenu_page( 'swps-dashboard', 'IP Blocker',       'IP Blocker',       'manage_options', 'swps-ip-blocker',     'swps_ip_blocker_page' );
    add_submenu_page( 'swps-dashboard', 'Security Scanner', 'Security Scanner', 'manage_options', 'swps-scanner',        'swps_scanner_page' );
    add_submenu_page( 'swps-dashboard', '⚡ Full Site Scan', '⚡ Full Scan',    'manage_options', 'swps-full-scan',      'swps_full_scan_page' );

    // Phase 1
    add_submenu_page( 'swps-dashboard', 'Firewall (WAF)',   'Firewall (WAF)',   'manage_options', 'swps-waf',            'swps_waf_page' );
    add_submenu_page( 'swps-dashboard', '2FA',              'Two-Factor Auth',  'manage_options', 'swps-2fa',            'swps_2fa_page' );
    add_submenu_page( 'swps-dashboard', 'Hardening',        'Hardening',        'manage_options', 'swps-hardening',      'swps_hardening_page' );
    add_submenu_page( 'swps-dashboard', 'Sec Headers',      'Sec Headers',      'manage_options', 'swps-headers',        'swps_headers_page' );

    // Phase 2
    add_submenu_page( 'swps-dashboard', 'Live Traffic',     'Live Traffic',     'manage_options', 'swps-live-traffic',   'swps_live_traffic_page' );
    add_submenu_page( 'swps-dashboard', 'Vuln Scanner',     'Vuln Scanner',     'manage_options', 'swps-vuln-scanner',   'swps_vuln_scanner_page' );
    add_submenu_page( 'swps-dashboard', 'DB Monitor',       'DB Monitor',       'manage_options', 'swps-db-monitor',     'swps_db_monitor_page' );

    // Tier 1–4
    add_submenu_page( 'swps-dashboard', 'File Integrity',   'File Integrity',   'manage_options', 'swps-file-integrity', 'swps_file_integrity_page' );
    add_submenu_page( 'swps-dashboard', 'Sessions',         'Sessions',         'manage_options', 'swps-sessions',       'swps_sessions_page' );
    add_submenu_page( 'swps-dashboard', 'Uptime Monitor',   'Uptime Monitor',   'manage_options', 'swps-uptime',         'swps_uptime_page' );
    add_submenu_page( 'swps-dashboard', 'Attack Map',       'Attack Map',       'manage_options', 'swps-attack-map',     'swps_attack_map_page' );
    add_submenu_page( 'swps-dashboard', 'Timeline',         'Timeline',         'manage_options', 'swps-timeline',       'swps_timeline_page' );
    add_submenu_page( 'swps-dashboard', 'Audit Trail',      'Audit Trail',      'manage_options', 'swps-audit',          'swps_audit_page' );

    // Tier 5-7
    add_submenu_page( 'swps-dashboard', 'Core Repair',      'Core Repair',      'manage_options', 'swps-core-repair',    'swps_core_repair_page' );
    add_submenu_page( 'swps-dashboard', 'Threat Intel',     'Threat Intel',     'manage_options', 'swps-threat-intel',   'swps_threat_intel_page' );
    add_submenu_page( 'swps-dashboard', 'Multi-Site',       'Multi-Site',       'manage_options', 'swps-multisite',      'swps_multisite_page' );

    // Settings (last)
    add_submenu_page( 'swps-dashboard', 'Settings',         'Settings',         'manage_options', 'swps-settings',       'swps_settings_page' );
    add_submenu_page( 'swps-dashboard', 'Advanced',         'Advanced',         'manage_options', 'swps-advanced',       'swps_advanced_page' );
}

// ─── Enqueue admin assets ──────────────────────────────────────────────────────
add_action( 'admin_enqueue_scripts', 'swps_enqueue_assets' );
function swps_enqueue_assets( $hook ) {
    if ( strpos($hook, 'swps-') === false && $hook !== 'toplevel_page_swps-dashboard' ) return;

    wp_enqueue_style(  'swps-admin-style',  SWPS_PLUGIN_URL . 'admin/css/style.css',  array(), SWPS_VERSION );
    wp_enqueue_script( 'swps-admin-script', SWPS_PLUGIN_URL . 'admin/js/script.js', array('jquery'), SWPS_VERSION, true );
    wp_localize_script( 'swps-admin-script', 'swps_vars', array(
        'url'   => admin_url('admin-ajax.php'),
        'nonce' => wp_create_nonce('swps_nonce'),
    ) );
}

// ─── Settings API registration ────────────────────────────────────────────────
add_action( 'admin_init', 'swps_register_settings' );
function swps_register_settings() {
    register_setting( 'swps_settings_group', 'swps_settings', array(
        'sanitize_callback' => 'swps_sanitize_settings',
    ) );
}

function swps_sanitize_settings( $input ) {
    // Merge onto existing settings so saving one page does NOT wipe keys that
    // belong to other pages / default-on features (fim_enabled, rate_limiter,
    // honeypot, etc. that aren't in the lists below).
    $clean = get_option( 'swps_settings', array() );
    if ( ! is_array($clean) ) $clean = array();
    if ( ! is_array($input) ) return $clean;

    $text_fields = array(
        'max_login_attempts','lockout_duration','alert_email',
        'login_url','waf_mode','waf_auto_block_threshold','waf_whitelist_ips',
        '2fa_default_method','2fa_remember_days',
        'recaptcha_site_key','recaptcha_secret_key',
        'geoip_mode','geoip_countries','maxmind_license_key',
        'wpscan_api_key','gsb_api_key',
        'away_start','away_end','away_timezone',
        'login_allowed_ips',
    );
    foreach ( $text_fields as $f ) {
        if ( isset($input[$f]) ) $clean[$f] = sanitize_text_field($input[$f]);
    }

    $toggle_fields = array(
        'email_alerts','file_monitor_enabled','two_factor_enabled','waf_enabled',
        'waf_sqli','waf_xss','waf_lfi','waf_rfi','waf_bad_bot',
        'captcha_enabled','geoip_enabled','geoip_login_only','live_traffic_enabled',
        'vuln_auto_scan','away_mode_enabled','blacklist_monitor_enabled',
        'security_headers_enabled',
    );
    foreach ( $toggle_fields as $f ) {
        // Only change a toggle that was actually part of the submitted form,
        // so other pages' toggles are preserved.
        if ( array_key_exists($f, $input) ) {
            $clean[$f] = ! empty($input[$f]) ? 1 : 0;
        }
    }

    // Array fields
    if ( isset($input['captcha_on']) && is_array($input['captcha_on']) ) {
        $allowed_forms = array('login','register','lost_password','comments');
        foreach ( $allowed_forms as $form ) {
            $clean['captcha_on'][$form] = ! empty($input['captcha_on'][$form]) ? 1 : 0;
        }
    }
    if ( isset($input['2fa_require_for']) && is_array($input['2fa_require_for']) ) {
        $allowed_roles = array('administrator','editor','author','contributor','subscriber');
        $clean['2fa_require_for'] = array_intersect( (array)$input['2fa_require_for'], $allowed_roles );
    }

    return $clean;
}

// ─── AJAX handlers ────────────────────────────────────────────────────────────

// Core
add_action( 'wp_ajax_swps_run_scan',   'swps_ajax_run_scan' );
add_action( 'wp_ajax_swps_block_ip',   'swps_ajax_block_ip' );
add_action( 'wp_ajax_swps_unblock_ip', 'swps_ajax_unblock_ip' );
add_action( 'wp_ajax_swps_clear_log',  'swps_ajax_clear_log' );

function swps_ajax_run_scan() {
    check_ajax_referer( 'swps_nonce', 'nonce' );
    if ( ! current_user_can('manage_options') ) wp_die('Unauthorized');
    wp_send_json_success( SWPS_Scanner::run_scan() );
}

function swps_ajax_block_ip() {
    check_ajax_referer( 'swps_nonce', 'nonce' );
    if ( ! current_user_can('manage_options') ) wp_die('Unauthorized');
    $ip     = sanitize_text_field( $_POST['ip'] ?? '' );
    $reason = sanitize_text_field( $_POST['reason'] ?? 'Manual block from admin' );
    SWPS_IP_Blocker::block_ip( $ip, $reason );
    wp_send_json_success( array('message' => "IP $ip blocked.") );
}

function swps_ajax_unblock_ip() {
    check_ajax_referer( 'swps_nonce', 'nonce' );
    if ( ! current_user_can('manage_options') ) wp_die('Unauthorized');
    $ip = sanitize_text_field( $_POST['ip'] ?? '' );
    SWPS_IP_Blocker::unblock_ip( $ip );
    wp_send_json_success( array('message' => "IP $ip unblocked.") );
}

function swps_ajax_clear_log() {
    check_ajax_referer( 'swps_nonce', 'nonce' );
    if ( ! current_user_can('manage_options') ) wp_die('Unauthorized');
    global $wpdb;
    $wpdb->query( "TRUNCATE TABLE " . $wpdb->prefix . SWPS_TABLE_LOG ); // phpcs:ignore
    wp_send_json_success( array('message' => 'Log cleared.') );
}

add_action( 'wp_ajax_swps_fim_toggle', 'swps_ajax_fim_toggle' );
function swps_ajax_fim_toggle() {
    check_ajax_referer( 'swps_nonce', 'nonce' );
    if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');
    $enabled = ! empty($_POST['enabled']) ? 1 : 0;
    $s = get_option( 'swps_settings', array() );
    if ( ! is_array($s) ) $s = array();
    $s['fim_enabled'] = $enabled;
    update_option( 'swps_settings', $s );
    wp_send_json_success( array('enabled' => $enabled) );
}

add_action( 'wp_ajax_swps_reset_known_admins', 'swps_ajax_reset_known_admins' );
function swps_ajax_reset_known_admins() {
    check_ajax_referer( 'swps_nonce', 'nonce' );
    if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');
    delete_option( 'swps_known_admins' );
    wp_send_json_success( array('message' => 'Known admins list reset. Current admins will be re-learned on next check.') );
}

// Full Scan — scan settings + schedule
add_action('wp_ajax_swps_save_scan_settings',  'swps_ajax_save_scan_settings');
add_action('wp_ajax_swps_save_scan_schedule',  'swps_ajax_save_scan_schedule');

function swps_ajax_save_scan_settings() {
    check_ajax_referer('swps_nonce','nonce');
    if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
    $disabled = array_map('sanitize_key', (array)($_POST['disabled_steps']??array()));
    $s = get_option('swps_settings', array());
    $s['full_scan_disabled_steps'] = $disabled;
    update_option('swps_settings', $s);
    wp_send_json_success('Saved.');
}

function swps_ajax_save_scan_schedule() {
    check_ajax_referer('swps_nonce','nonce');
    if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
    $s = get_option('swps_settings', array());
    $s['full_scan_schedule']     = sanitize_key($_POST['full_scan_schedule']??'');
    $s['full_scan_auto_fix']     = !empty($_POST['full_scan_auto_fix']) ? 1 : 0;
    $s['full_scan_email_report'] = !empty($_POST['full_scan_email_report']) ? 1 : 0;
    update_option('swps_settings', $s);
    // Re-schedule
    wp_clear_scheduled_hook('swps_scheduled_full_scan');
    if ($s['full_scan_schedule']) {
        $interval = $s['full_scan_schedule'] === 'daily' ? 'daily' : 'swps_weekly';
        wp_schedule_event(time(), $interval, 'swps_scheduled_full_scan');
    }
    wp_send_json_success('Schedule saved.');
}

// Phase 2 AJAX (additional handlers registered in their classes)
add_action( 'wp_ajax_swps_test_headers',    'swps_ajax_test_headers' );
add_action( 'wp_ajax_swps_generate_report', 'swps_ajax_generate_report' );

function swps_ajax_test_headers() {
    check_ajax_referer( 'swps_nonce', 'nonce' );
    if ( ! current_user_can('manage_options') ) wp_die('Unauthorized');
    $results = SWPS_Security_Headers::test_headers();
    set_transient( 'swps_header_test', $results, HOUR_IN_SECONDS );
    wp_send_json_success( $results );
}

function swps_ajax_generate_report() {
    check_ajax_referer( 'swps_nonce', 'nonce' );
    if ( ! current_user_can('manage_options') ) wp_die('Unauthorized');
    echo SWPS_White_Label::generate_report();
    exit;
}

// ─── Page callbacks ────────────────────────────────────────────────────────────
function swps_dashboard_page()    { include SWPS_PLUGIN_DIR . 'admin/page-dashboard.php'; }
function swps_activity_log_page() { include SWPS_PLUGIN_DIR . 'admin/page-activity-log.php'; }
function swps_ip_blocker_page()   { include SWPS_PLUGIN_DIR . 'admin/page-ip-blocker.php'; }
function swps_scanner_page()      { include SWPS_PLUGIN_DIR . 'admin/page-scanner.php'; }
function swps_waf_page()          { include SWPS_PLUGIN_DIR . 'admin/page-waf.php'; }
function swps_2fa_page()          { include SWPS_PLUGIN_DIR . 'admin/page-two-factor.php'; }
function swps_hardening_page()    { include SWPS_PLUGIN_DIR . 'admin/page-hardening.php'; }
function swps_headers_page()      { include SWPS_PLUGIN_DIR . 'admin/page-headers.php'; }
function swps_live_traffic_page() { include SWPS_PLUGIN_DIR . 'admin/page-live-traffic.php'; }
function swps_vuln_scanner_page() { include SWPS_PLUGIN_DIR . 'admin/page-vuln-scanner.php'; }
function swps_db_monitor_page()   { include SWPS_PLUGIN_DIR . 'admin/page-db-monitor.php'; }
function swps_settings_page()       { include SWPS_PLUGIN_DIR . 'admin/page-settings.php'; }
function swps_advanced_page()       { include SWPS_PLUGIN_DIR . 'admin/page-advanced-settings.php'; }
function swps_file_integrity_page() { include SWPS_PLUGIN_DIR . 'admin/page-file-integrity.php'; }
function swps_sessions_page()       { include SWPS_PLUGIN_DIR . 'admin/page-sessions.php'; }
function swps_attack_map_page()     { include SWPS_PLUGIN_DIR . 'admin/page-attack-map.php'; }
function swps_timeline_page()       { include SWPS_PLUGIN_DIR . 'admin/page-security-timeline.php'; }
function swps_audit_page()          { include SWPS_PLUGIN_DIR . 'admin/page-audit-trail.php'; }
function swps_uptime_page()         { include SWPS_PLUGIN_DIR . 'admin/page-uptime-monitor.php'; }
function swps_full_scan_page()      { include SWPS_PLUGIN_DIR . 'admin/page-full-scan.php'; }
function swps_core_repair_page()    { include SWPS_PLUGIN_DIR . 'admin/page-core-repair.php'; }
function swps_threat_intel_page()   { include SWPS_PLUGIN_DIR . 'admin/page-threat-intelligence.php'; }
function swps_multisite_page()      { include SWPS_PLUGIN_DIR . 'admin/page-multisite.php'; }

// DNA scan AJAX
add_action('wp_ajax_swps_dna_scan', function() {
    check_ajax_referer('swps_nonce', 'nonce');
    if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
    wp_send_json_success(SWPS_Malware_DNA::run_scan());
});
