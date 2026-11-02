<?php
/**
 * Plugin Name: SecureWP Shield
 * Plugin URI:  https://yoursite.com
 * Description: Enterprise WordPress Security Suite — WAF, 2FA, Full Site Scan, Core Repair, Honeypot, Rate Limiter, Challenge Page, DNA Scanner, Canary Tokens, IP Reputation, SIEM, Multi-Site Monitor, Threat Feed Server
 * Version:     5.0.30
 * Author:      Yaseen
 * Author URI:  https://yoursite.com
 * Text Domain: securewp-shield
 * Update URI:  https://github.com/ansariyaaeen361-arch/securewp-shield
 */

if ( ! defined( 'ABSPATH' ) ) exit;

define( 'SWPS_VERSION',     '5.0.30' );
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
require_once SWPS_PLUGIN_DIR . 'includes/class-github-updater.php';
add_action( 'init', array( 'SWPS_GitHub_Updater', 'init' ) );

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
require_once SWPS_PLUGIN_DIR . 'includes/class-plugin-theme-repair.php';
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
    SWPS_Email_Alerts::init();
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
    SWPS_Plugin_Theme_Repair::init();
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
}

// ─── Admin menu ───────────────────────────────────────────────────────────────

/**
 * Other plugins' promo banners/upsell notices (admin_notices) render on
 * EVERY wp-admin screen by default, including ours — cluttering a security
 * dashboard with unrelated "Upgrade to Pro" banners from other plugins. This
 * plugin has no admin_notices of its own to lose, so on our own pages only
 * (never elsewhere in wp-admin) we drop every other plugin's notices.
 */
add_action( 'current_screen', 'swps_suppress_foreign_admin_notices' );
function swps_suppress_foreign_admin_notices( $screen ) {
    $page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
    if ( strpos( $page, 'swps-' ) !== 0 ) return;
    remove_all_actions( 'admin_notices' );
    remove_all_actions( 'all_admin_notices' );
    remove_all_actions( 'network_admin_notices' );

    // Fix: confirmed live (with LiteSpeed Cache) that a page-cache plugin can
    // still end up caching a wp-admin screen — a site owner saving a setting
    // here, then refreshing, saw their own save "undo itself" because the
    // refresh served a cached copy of the page from BEFORE the save, not
    // because the save actually failed. WordPress admin pages are normally
    // excluded by well-behaved cache plugins, but this costs nothing to send
    // ourselves and removes the dependency on every cache plugin getting
    // that exclusion right.
    swps_send_no_cache_headers();
}

function swps_send_no_cache_headers() {
    if ( headers_sent() ) return;
    nocache_headers(); // WordPress's own standard no-cache header set
    header( 'X-LiteSpeed-Cache-Control: no-cache' );
    if ( has_action( 'litespeed_control_set_nocache' ) ) {
        do_action( 'litespeed_control_set_nocache', 'SecureWP Shield admin page' );
    }
}

add_action( 'admin_menu', 'swps_admin_menu' );
function swps_admin_menu() {
    $wl       = get_option('swps_white_label', array());
    $menu_name = ( ! empty($wl['enabled']) && ! empty($wl['menu_name']) ) ? $wl['menu_name'] : 'SecureWP Shield';

    add_menu_page(
        $menu_name, $menu_name, 'manage_options',
        'swps-dashboard', 'swps_shell_dashboard',
        'dashicons-shield', 2
    );

    // ── Visible sidebar (9 items) — everything else below is grouped under
    // these via tabs, so a site owner isn't facing 23 separate pages. Each
    // is wrapped in swps_shell_*() (see swps_page_shell()) so its output
    // sits inside a stable #swps-page-content container that JS can swap
    // out for AJAX-driven navigation (see swps_ajax_load_page()). ──
    add_submenu_page( 'swps-dashboard', 'Dashboard',           'Dashboard',             'manage_options', 'swps-dashboard',    'swps_shell_dashboard' );
    add_submenu_page( 'swps-dashboard', '⚡ Full Site Scan',    '⚡ Full Scan',          'manage_options', 'swps-full-scan',    'swps_shell_full_scan' );
    add_submenu_page( 'swps-dashboard', 'Firewall & Hardening','Firewall & Hardening',  'manage_options', 'swps-firewall',     'swps_shell_firewall' );
    add_submenu_page( 'swps-dashboard', 'File & Core Protection','File & Core Protection','manage_options','swps-protection',  'swps_shell_protection' );
    add_submenu_page( 'swps-dashboard', 'Access Control',      'Access Control',        'manage_options', 'swps-access',       'swps_shell_access' );
    add_submenu_page( 'swps-dashboard', 'Monitoring & Logs',   'Monitoring & Logs',     'manage_options', 'swps-monitoring',   'swps_shell_monitoring' );
    add_submenu_page( 'swps-dashboard', 'Threat Intelligence', 'Threat Intelligence',   'manage_options', 'swps-threat-intel', 'swps_shell_threat_intel' );
    add_submenu_page( 'swps-dashboard', 'Multi-Site',          'Multi-Site',            'manage_options', 'swps-multisite',    'swps_shell_multisite' );
    add_submenu_page( 'swps-dashboard', 'Settings',            'Settings',              'manage_options', 'swps-settings',     'swps_shell_settings' );

    // ── Hidden pages — still fully reachable by URL (AJAX handlers, direct
    // links, bookmarks keep working), just no longer shown in the sidebar
    // since their content now lives as a tab inside one of the 9 pages above.
    $hidden = array(
        array( 'Activity Log',     'swps-activity-log',   'swps_activity_log_page' ),
        array( 'IP Blocker',       'swps-ip-blocker',     'swps_ip_blocker_page' ),
        array( 'Security Scanner', 'swps-scanner',        'swps_scanner_page' ),
        array( 'Firewall (WAF)',   'swps-waf',            'swps_waf_page' ),
        array( 'Two-Factor Auth',  'swps-2fa',            'swps_2fa_page' ),
        array( 'Hardening',        'swps-hardening',      'swps_hardening_page' ),
        array( 'Security Headers', 'swps-headers',        'swps_headers_page' ),
        array( 'Live Traffic',     'swps-live-traffic',   'swps_live_traffic_page' ),
        array( 'Vuln Scanner',     'swps-vuln-scanner',   'swps_vuln_scanner_page' ),
        array( 'DB Monitor',       'swps-db-monitor',     'swps_db_monitor_page' ),
        array( 'File Integrity',   'swps-file-integrity', 'swps_file_integrity_page' ),
        array( 'Sessions',         'swps-sessions',       'swps_sessions_page' ),
        array( 'Uptime Monitor',   'swps-uptime',         'swps_uptime_page' ),
        array( 'Attack Map',       'swps-attack-map',     'swps_attack_map_page' ),
        array( 'Timeline',         'swps-timeline',       'swps_timeline_page' ),
        array( 'Audit Trail',      'swps-audit',          'swps_audit_page' ),
        array( 'Core Repair',      'swps-core-repair',    'swps_core_repair_page' ),
        array( 'Advanced',         'swps-advanced',       'swps_advanced_page' ),
    );
    foreach ( $hidden as $p ) {
        add_submenu_page( null, $p[0], $p[0], 'manage_options', $p[1], $p[2] );
    }
}

/**
 * Renders the group-level tab bar and includes exactly the one original
 * page file for the active tab. Only one original page's markup/JS is ever
 * in the DOM at a time, so this carries zero risk of the ID/JS collisions
 * that merging multiple pages' HTML into one DOM would risk.
 *
 * Fix: this used to use the same .swps-tabs/.swps-tab/.swps-tab-active
 * classes that several of the included pages (Threat Intelligence,
 * Multi-Site, Advanced Settings) already use for their OWN internal
 * JS-driven tabs — nesting a group tab bar around a page with its own tab
 * bar of the identical classname broke both the layout (CSS meant for one
 * tab bar applied to two nested ones) and the inner page's own tab-switch
 * JS (which matched ALL .swps-tab elements, including the outer, real-link
 * ones). The group bar now uses its own swps-gtabs/swps-gtab namespace so
 * it never collides with an included page's internal tabs.
 *
 * Fix: tab clicks used to be plain links (full page reload on every click).
 * They're now intercepted with JS and the new tab's HTML is fetched over
 * admin-ajax and swapped in — same current data, no full navigation reload.
 * The plain <a href> is kept as-is so the tab still works with JS off, and
 * as the real bookmarkable/shareable URL.
 *
 * @param array  $tabs    tab_slug => array( 'label' => ..., 'file' => 'admin/page-x.php' )
 * @param string $page    current ?page= slug (for building tab links)
 */
function swps_render_group_tabs( $title, $icon, $tabs, $page ) {
    $current = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : array_key_first( $tabs );
    if ( ! isset( $tabs[ $current ] ) ) $current = array_key_first( $tabs );
    ?>
    <div class="swps-gtab-bar">
        <h1 class="swps-page-title"><span class="dashicons <?php echo esc_attr($icon); ?>"></span> <?php echo esc_html($title); ?></h1>
        <div class="swps-gtabs" data-swps-group-page="<?php echo esc_attr($page); ?>">
            <?php foreach ( $tabs as $slug => $t ) : ?>
                <a class="swps-gtab <?php echo $slug === $current ? 'swps-gtab-active' : ''; ?>"
                   data-tab="<?php echo esc_attr($slug); ?>"
                   href="<?php echo esc_url( admin_url( 'admin.php?page=' . $page . '&tab=' . $slug ) ); ?>"><?php echo esc_html( $t['label'] ); ?></a>
            <?php endforeach; ?>
        </div>
    </div>
    <div id="swps-gtab-content">
    <?php
    // Fix: this container used to be a second, OUTER .wrap.swps-wrap, with
    // the included page's own .wrap.swps-wrap nested directly inside it —
    // nesting WordPress's .wrap container inside itself double-applies our
    // own width/margin/padding rules and was part of why the tab bar
    // rendered squeezed into a vertical sliver. The outer shell above is now
    // a plain, unrelated wrapper; the included page below provides the only
    // real .wrap on the page, exactly as it does when visited directly.
    include SWPS_PLUGIN_DIR . $tabs[ $current ]['file'];
    ?>
    </div>
    <?php
}

/**
 * Maps every one of the 9 sidebar page slugs to its real render function.
 * Single source of truth used by both the normal (full-load) submenu
 * registration and the AJAX nav dispatcher below, so the two can never
 * drift out of sync.
 */
function swps_page_registry() {
    return array(
        'swps-dashboard'    => 'swps_dashboard_page',
        'swps-full-scan'    => 'swps_full_scan_page',
        'swps-firewall'     => 'swps_group_firewall_page',
        'swps-protection'   => 'swps_group_protection_page',
        'swps-access'       => 'swps_group_access_page',
        'swps-monitoring'   => 'swps_group_monitoring_page',
        'swps-threat-intel' => 'swps_threat_intel_page',
        'swps-multisite'    => 'swps_multisite_page',
        'swps-settings'     => 'swps_group_settings_page',
    );
}

/**
 * Wraps a page's real render function in a stable #swps-page-content
 * container so JS has something consistent to replace for AJAX-driven
 * navigation (see swps_ajax_load_page() and the click handler in
 * admin/js/script.js) — switching between the 9 sidebar pages, or between
 * tabs within a grouped one, no longer triggers a full browser reload.
 */
function swps_page_shell( $page_slug ) {
    echo '<div id="swps-page-content">';
    $registry = swps_page_registry();
    if ( isset( $registry[ $page_slug ] ) ) call_user_func( $registry[ $page_slug ] );
    echo '</div>';
}
function swps_shell_dashboard()    { swps_page_shell( 'swps-dashboard' ); }
function swps_shell_full_scan()    { swps_page_shell( 'swps-full-scan' ); }
function swps_shell_firewall()     { swps_page_shell( 'swps-firewall' ); }
function swps_shell_protection()   { swps_page_shell( 'swps-protection' ); }
function swps_shell_access()       { swps_page_shell( 'swps-access' ); }
function swps_shell_monitoring()   { swps_page_shell( 'swps-monitoring' ); }
function swps_shell_threat_intel() { swps_page_shell( 'swps-threat-intel' ); }
function swps_shell_multisite()    { swps_page_shell( 'swps-multisite' ); }
function swps_shell_settings()     { swps_page_shell( 'swps-settings' ); }

add_action( 'wp_ajax_swps_load_page', 'swps_ajax_load_page' );
function swps_ajax_load_page() {
    check_ajax_referer( 'swps_nonce', 'nonce' );
    if ( ! current_user_can('manage_options') ) wp_send_json_error( 'Unauthorized' );

    $page = isset( $_POST['page'] ) ? sanitize_key( $_POST['page'] ) : '';
    $tab  = isset( $_POST['tab'] )  ? sanitize_key( $_POST['tab'] )  : '';
    $registry = swps_page_registry();

    if ( ! isset( $registry[ $page ] ) ) wp_send_json_error( 'Unknown page.' );
    if ( $tab ) $_GET['tab'] = $tab; // grouped pages read their active tab from here

    ob_start();
    call_user_func( $registry[ $page ] ); // no shell wrapper — JS replaces #swps-page-content's innards directly
    $html = ob_get_clean();

    wp_send_json_success( array( 'html' => $html, 'title' => get_admin_page_title() ) );
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
        'login_allowed_ips','github_token',
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
    // Fix: TRUNCATE needs the DROP privilege in MySQL, not just DELETE —
    // many shared-hosting DB users only get DELETE/INSERT/UPDATE/SELECT, so
    // TRUNCATE silently failed there. Its return value was never checked
    // either, so the handler reported "Log cleared." (and the page reloaded
    // looking successful) even though nothing was actually removed. DELETE
    // only needs the DELETE privilege, which is essentially always granted,
    // and the result is now actually checked before claiming success.
    $result = $wpdb->query( "DELETE FROM " . $wpdb->prefix . SWPS_TABLE_LOG );
    if ( $result === false ) {
        wp_send_json_error( 'Could not clear the log: ' . $wpdb->last_error );
    }
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

// ── Grouped tab pages (reorganized UI — see swps_render_group_tabs()) ──
function swps_group_firewall_tabs() {
    return array(
        'waf'       => array( 'label' => 'Firewall (WAF)',   'file' => 'admin/page-waf.php' ),
        'hardening' => array( 'label' => 'Hardening',        'file' => 'admin/page-hardening.php' ),
        'headers'   => array( 'label' => 'Security Headers', 'file' => 'admin/page-headers.php' ),
    );
}
function swps_group_firewall_page() {
    swps_render_group_tabs( 'Firewall & Hardening', 'dashicons-shield-alt', swps_group_firewall_tabs(), 'swps-firewall' );
}

function swps_group_protection_tabs() {
    return array(
        'scanner'   => array( 'label' => 'Security Scanner', 'file' => 'admin/page-scanner.php' ),
        'integrity' => array( 'label' => 'File Integrity',   'file' => 'admin/page-file-integrity.php' ),
        'core'      => array( 'label' => 'Core Repair',      'file' => 'admin/page-core-repair.php' ),
        'vuln'      => array( 'label' => 'Vuln Scanner',     'file' => 'admin/page-vuln-scanner.php' ),
    );
}
function swps_group_protection_page() {
    swps_render_group_tabs( 'File & Core Protection', 'dashicons-media-code', swps_group_protection_tabs(), 'swps-protection' );
}

function swps_group_access_tabs() {
    return array(
        '2fa'       => array( 'label' => 'Two-Factor Auth', 'file' => 'admin/page-two-factor.php' ),
        'sessions'  => array( 'label' => 'Sessions',        'file' => 'admin/page-sessions.php' ),
        'ipblocker' => array( 'label' => 'IP Blocker',      'file' => 'admin/page-ip-blocker.php' ),
    );
}
function swps_group_access_page() {
    swps_render_group_tabs( 'Access Control', 'dashicons-admin-users', swps_group_access_tabs(), 'swps-access' );
}

function swps_group_monitoring_tabs() {
    return array(
        'traffic'  => array( 'label' => 'Live Traffic',  'file' => 'admin/page-live-traffic.php' ),
        'uptime'   => array( 'label' => 'Uptime Monitor', 'file' => 'admin/page-uptime-monitor.php' ),
        'db'       => array( 'label' => 'DB Monitor',     'file' => 'admin/page-db-monitor.php' ),
        'map'      => array( 'label' => 'Attack Map',     'file' => 'admin/page-attack-map.php' ),
        'timeline' => array( 'label' => 'Timeline',       'file' => 'admin/page-security-timeline.php' ),
        'activity' => array( 'label' => 'Activity Log',   'file' => 'admin/page-activity-log.php' ),
        'audit'    => array( 'label' => 'Audit Trail',    'file' => 'admin/page-audit-trail.php' ),
    );
}
function swps_group_monitoring_page() {
    swps_render_group_tabs( 'Monitoring & Logs', 'dashicons-visibility', swps_group_monitoring_tabs(), 'swps-monitoring' );
}

function swps_group_settings_tabs() {
    return array(
        'general'  => array( 'label' => 'Settings', 'file' => 'admin/page-settings.php' ),
        'advanced' => array( 'label' => 'Advanced', 'file' => 'admin/page-advanced-settings.php' ),
    );
}
function swps_group_settings_page() {
    swps_render_group_tabs( 'Settings', 'dashicons-admin-generic', swps_group_settings_tabs(), 'swps-settings' );
}

// DNA scan AJAX
add_action('wp_ajax_swps_dna_scan', function() {
    check_ajax_referer('swps_nonce', 'nonce');
    if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
    wp_send_json_success(SWPS_Malware_DNA::run_scan());
});

/**
 * Per-file "deep scan" for the Full Scan file-change panel — re-runs the
 * full Malware DNA signature set against ONE specific file on demand (the
 * whole set, not a lighter subset, regardless of the file's size up to the
 * scanner's own 5MB cap) and returns a Trust Score, plus whether Auto Fix
 * is available for it (same determine_fim_fix() logic the issue list
 * itself uses, so the two can never show conflicting fix options).
 */
add_action('wp_ajax_swps_fim_deep_scan', function() {
    check_ajax_referer('swps_nonce', 'nonce');
    if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');

    $rel = sanitize_text_field( wp_unslash( $_POST['file'] ?? '' ) );
    $rel = ltrim( str_replace('..', '', $rel), '/\\' );
    $full = ABSPATH . $rel;
    if ( ! $rel || ! file_exists($full) ) wp_send_json_error('File not found.');

    $findings = SWPS_Malware_DNA::scan_file($full);

    $score = 100;
    foreach ($findings as $f) {
        $score -= ($f['severity'] ?? '') === 'critical' ? 40 : 10;
    }
    $score = max(0, $score);

    $baseline    = get_option('swps_file_baseline', array());
    $change_type = isset($baseline[$rel]) ? 'modified' : 'added'; // best-effort when not called from a known change record
    $fix         = SWPS_Full_Scan::determine_fim_fix($rel, $change_type);

    wp_send_json_success(array(
        'file'      => $rel,
        'score'     => $score,
        'findings'  => array_map(fn($f) => array('sig_id'=>$f['sig_id'], 'severity'=>$f['severity'], 'match'=>$f['match'], 'line'=>$f['line'] ?? null), $findings),
        'fix_type'  => $fix[0],
        'fix_label' => $fix[1],
    ));
});
