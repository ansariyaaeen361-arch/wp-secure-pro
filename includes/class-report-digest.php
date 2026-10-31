<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Report_Digest {

    public static function init() {
        add_action( 'swps_weekly_digest',       array( __CLASS__, 'send_weekly' ) );
        add_action( 'swps_daily_cron',          array( __CLASS__, 'maybe_send_daily' ) );
        add_action( 'wp_ajax_swps_send_digest', array( __CLASS__, 'ajax_send_now' ) );

        // Schedule weekly digest
        if ( ! wp_next_scheduled('swps_weekly_digest') ) {
            wp_schedule_event( strtotime('next monday 08:00:00'), 'weekly', 'swps_weekly_digest' );
        }
    }

    public static function maybe_send_daily() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty($settings['daily_digest_enabled']) ) return;
        self::send_digest('daily');
    }

    public static function send_weekly() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty($settings['weekly_digest_enabled']) ) return;
        self::send_digest('weekly');
    }

    public static function ajax_send_now() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');
        $type = sanitize_key($_POST['type'] ?? 'weekly');
        self::send_digest($type);
        wp_send_json_success('Digest sent.');
    }

    public static function send_digest( $period = 'weekly' ) {
        $settings    = get_option( 'swps_settings', array() );
        $email       = $settings['alert_email'] ?? get_option('admin_email');
        $since       = $period === 'daily' ? DAY_IN_SECONDS : WEEK_IN_SECONDS;
        $since_label = $period === 'daily' ? 'Yesterday' : 'Last 7 Days';

        global $wpdb;
        $table = $wpdb->prefix . SWPS_TABLE_LOG;
        $from  = date('Y-m-d H:i:s', time() - $since);

        $logs     = $wpdb->get_results( $wpdb->prepare("SELECT * FROM $table WHERE created_at >= %s ORDER BY created_at DESC", $from) );
        $critical = array_filter($logs, fn($l) => $l->severity === 'critical');
        $warnings = array_filter($logs, fn($l) => $l->severity === 'warning');

        // Scan results
        $scan    = get_option('swps_last_scan', array());
        $threats = count($scan['threats'] ?? array());

        // Blocked IPs
        $blocked_count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}swps_blocked_ips WHERE expires_at IS NULL OR expires_at > NOW()");

        // SSL
        $ssl = SWPS_SSL_Monitor::get_last_check();
        $ssl_days = $ssl['days_remaining'] ?? 'N/A';

        // Build HTML email
        $site  = get_site_url();
        $name  = get_bloginfo('name');
        $color = count($critical) > 0 ? '#e74c3c' : (count($warnings) > 0 ? '#f39c12' : '#27ae60');
        $status_label = count($critical) > 0 ? 'ACTION REQUIRED' : (count($warnings) > 0 ? 'WARNINGS' : 'ALL CLEAR');

        $html = "
<!DOCTYPE html><html><head><meta charset='utf-8'><style>
body{font-family:Arial,sans-serif;color:#333;background:#f5f5f5;margin:0;padding:0}
.wrap{max-width:600px;margin:20px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)}
.header{background:#1e2a3b;color:#fff;padding:24px;text-align:center}
.header h1{margin:0;font-size:22px}.header p{margin:4px 0 0;opacity:.7;font-size:13px}
.status-bar{background:$color;color:#fff;text-align:center;padding:12px;font-weight:700;font-size:15px;letter-spacing:1px}
.body{padding:24px}
.stats-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:20px}
.stat{background:#f9f9f9;border-radius:6px;padding:16px;text-align:center;border-top:3px solid #ddd}
.stat-num{font-size:28px;font-weight:800;line-height:1}
.stat-label{font-size:11px;color:#888;text-transform:uppercase;margin-top:4px}
.stat-critical .stat-num{color:#e74c3c}.stat-critical{border-top-color:#e74c3c}
.stat-warning .stat-num{color:#f39c12}.stat-warning{border-top-color:#f39c12}
.stat-ok .stat-num{color:#27ae60}.stat-ok{border-top-color:#27ae60}
.section{margin-bottom:20px}
.section h3{font-size:14px;font-weight:700;margin:0 0 10px;color:#555;text-transform:uppercase;letter-spacing:.5px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#f5f5f5;padding:6px 10px;text-align:left;color:#666}
td{padding:6px 10px;border-bottom:1px solid #eee}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700}
.badge-crit{background:#fde8e8;color:#c0392b}.badge-warn{background:#fef3cd;color:#856404}.badge-ok{background:#d4edda;color:#155724}
.footer{background:#f9f9f9;padding:16px;text-align:center;font-size:11px;color:#999;border-top:1px solid #eee}
a{color:#1a56a8}
</style></head><body>
<div class='wrap'>
<div class='header'>
    <h1>🛡 SecureWP Shield</h1>
    <p>Security Report — $since_label — $name</p>
</div>
<div class='status-bar'>$status_label</div>
<div class='body'>

<div class='stats-grid'>
    <div class='stat " . (count($critical) > 0 ? 'stat-critical' : 'stat-ok') . "'>
        <div class='stat-num'>" . count($critical) . "</div>
        <div class='stat-label'>Critical Events</div>
    </div>
    <div class='stat " . (count($warnings) > 0 ? 'stat-warning' : 'stat-ok') . "'>
        <div class='stat-num'>" . count($warnings) . "</div>
        <div class='stat-label'>Warnings</div>
    </div>
    <div class='stat " . ($threats > 0 ? 'stat-critical' : 'stat-ok') . "'>
        <div class='stat-num'>$threats</div>
        <div class='stat-label'>Malware Found</div>
    </div>
    <div class='stat stat-ok'>
        <div class='stat-num'>" . count($logs) . "</div>
        <div class='stat-label'>Total Events</div>
    </div>
    <div class='stat stat-ok'>
        <div class='stat-num'>$blocked_count</div>
        <div class='stat-label'>IPs Blocked</div>
    </div>
    <div class='stat " . (is_numeric($ssl_days) && $ssl_days < 30 ? 'stat-warning' : 'stat-ok') . "'>
        <div class='stat-num'>$ssl_days</div>
        <div class='stat-label'>SSL Days Left</div>
    </div>
</div>";

        // Critical events table
        if (!empty($critical)) {
            $html .= "<div class='section'><h3>Critical Events</h3><table><tr><th>Time</th><th>Event</th><th>Details</th></tr>";
            foreach (array_slice($critical, 0, 10) as $log) {
                $html .= "<tr><td>" . esc_html($log->created_at) . "</td><td><span class='badge badge-crit'>" . esc_html($log->event_type) . "</span></td><td>" . esc_html(substr($log->description,0,80)) . "</td></tr>";
            }
            $html .= "</table></div>";
        }

        $html .= "<p style='text-align:center;margin-top:20px'><a href='" . admin_url('admin.php?page=swps-dashboard') . "' style='background:#1a56a8;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:700'>View Full Dashboard</a></p>
</div>
<div class='footer'>SecureWP Shield v" . SWPS_VERSION . " &nbsp;|&nbsp; <a href='$site'>$site</a> &nbsp;|&nbsp; " . date_i18n('F j, Y') . "</div>
</div></body></html>";

        wp_mail(
            $email,
            "[SecureWP Shield] $since_label Security Digest — $name ($status_label)",
            $html,
            array('Content-Type: text/html; charset=UTF-8')
        );

        update_option('swps_last_digest_sent', time());
    }
}
