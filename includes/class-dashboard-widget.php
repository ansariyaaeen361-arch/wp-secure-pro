<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Dashboard_Widget {

    public static function init() {
        add_action( 'wp_dashboard_setup', array( __CLASS__, 'register' ) );
    }

    public static function register() {
        wp_add_dashboard_widget(
            'swps_security_overview',
            '🛡 WP Secure Pro — Security Overview',
            array( __CLASS__, 'render' )
        );
    }

    public static function render() {
        global $wpdb;

        $settings = get_option('swps_settings', array());
        $table    = $wpdb->prefix . SWPS_TABLE_LOG;

        // Last 24h stats
        $stats = $wpdb->get_row("
            SELECT
                COUNT(*) as total,
                SUM(severity='critical') as critical,
                SUM(severity='warning') as warning
            FROM $table
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ", ARRAY_A);

        $blocked_count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}swps_blocked_ips WHERE expires_at IS NULL OR expires_at > NOW()");
        $scan          = get_option('swps_last_scan', array());
        $threats       = count($scan['threats'] ?? array());
        $ssl           = SWPS_SSL_Monitor::get_last_check();
        $ssl_days      = $ssl['days_remaining'] ?? null;
        $fim           = SWPS_File_Integrity::get_stats();
        $fim_changes   = count($fim['changes'] ?? array());

        // Security score
        $score = 100;
        if (intval($stats['critical'] ?? 0) > 0) $score -= 20;
        if ($threats > 0) $score -= 30;
        if ($fim_changes > 0) $score -= 20;
        if (is_numeric($ssl_days) && $ssl_days < 30) $score -= 10;
        $score = max(0, $score);
        $score_color = $score >= 70 ? '#27ae60' : ($score >= 40 ? '#f39c12' : '#e74c3c');
        ?>

        <style>
        #swps_security_overview .inside { margin: 0; padding: 0; }
        .swps-widget-score { display: flex; align-items: center; gap: 16px; padding: 14px 16px; background: #f8fafc; border-bottom: 1px solid #e0e6ef; }
        .swps-widget-score-num { font-size: 36px; font-weight: 900; line-height: 1; }
        .swps-widget-score-label { font-size: 11px; color: #888; text-transform: uppercase; font-weight: 600; }
        .swps-widget-stats { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1px; background: #e0e6ef; }
        .swps-widget-stat { background: #fff; padding: 12px; text-align: center; }
        .swps-widget-stat-num { font-size: 22px; font-weight: 800; }
        .swps-widget-stat-label { font-size: 10px; color: #888; text-transform: uppercase; margin-top: 2px; }
        .swps-widget-alerts { padding: 10px 16px; }
        .swps-widget-alert { display: flex; align-items: center; gap: 8px; padding: 6px 0; border-bottom: 1px solid #f0f0f0; font-size: 12px; }
        .swps-widget-alert:last-child { border-bottom: none; }
        .swps-widget-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
        .swps-widget-footer { padding: 10px 16px; background: #f8fafc; border-top: 1px solid #e0e6ef; display: flex; justify-content: space-between; align-items: center; }
        </style>

        <!-- Score -->
        <div class="swps-widget-score">
            <div>
                <div class="swps-widget-score-num" style="color:<?php echo $score_color; ?>"><?php echo $score; ?></div>
                <div class="swps-widget-score-label">Security Score</div>
            </div>
            <div style="flex:1">
                <div style="height:8px;background:#e0e6ef;border-radius:4px;overflow:hidden">
                    <div style="width:<?php echo $score; ?>%;height:100%;background:<?php echo $score_color; ?>;border-radius:4px;transition:width .5s"></div>
                </div>
                <div style="font-size:11px;color:#888;margin-top:4px">
                    <?php
                    $label = $score >= 70 ? 'Good' : ($score >= 40 ? 'Needs Attention' : 'Critical Issues');
                    echo $label;
                    ?>
                </div>
            </div>
        </div>

        <!-- Stats -->
        <div class="swps-widget-stats">
            <div class="swps-widget-stat">
                <div class="swps-widget-stat-num" style="color:<?php echo intval($stats['critical']??0) > 0 ? '#e74c3c' : '#27ae60'; ?>">
                    <?php echo intval($stats['critical']??0); ?>
                </div>
                <div class="swps-widget-stat-label">Critical (24h)</div>
            </div>
            <div class="swps-widget-stat">
                <div class="swps-widget-stat-num" style="color:#1a56a8"><?php echo $blocked_count; ?></div>
                <div class="swps-widget-stat-label">IPs Blocked</div>
            </div>
            <div class="swps-widget-stat">
                <div class="swps-widget-stat-num" style="color:<?php echo $threats > 0 ? '#e74c3c' : '#27ae60'; ?>">
                    <?php echo $threats; ?>
                </div>
                <div class="swps-widget-stat-label">Threats Found</div>
            </div>
        </div>

        <!-- Status checks -->
        <div class="swps-widget-alerts">
            <?php
            $checks = array(
                array('WAF', !empty($settings['waf_enabled']), 'Firewall', '#27ae60', '#e74c3c'),
                array('2FA', !empty($settings['two_factor_enabled']), 'Two-Factor Auth', '#27ae60', '#f39c12'),
                array('FIM', ($fim['baseline_files'] > 0), 'File Monitor', '#27ae60', '#f39c12'),
                array('SSL', (is_numeric($ssl_days) && $ssl_days > 30), "SSL ($ssl_days days)", '#27ae60', '#e74c3c'),
                array('Scan', $threats === 0, $threats === 0 ? 'No Malware' : "$threats Threats!", '#27ae60', '#e74c3c'),
                array('Files', $fim_changes === 0, $fim_changes === 0 ? 'Files Intact' : "$fim_changes File Changes!", '#27ae60', '#e74c3c'),
            );
            foreach ($checks as [$label, $ok, $text, $ok_color, $fail_color]):
            ?>
            <div class="swps-widget-alert">
                <div class="swps-widget-dot" style="background:<?php echo $ok ? $ok_color : $fail_color; ?>"></div>
                <strong style="min-width:40px;font-size:11px"><?php echo $label; ?></strong>
                <span style="color:<?php echo $ok ? '#27ae60' : $fail_color; ?>"><?php echo esc_html($text); ?></span>
            </div>
            <?php endforeach; ?>
        </div>

        <!-- Footer -->
        <div class="swps-widget-footer">
            <span style="font-size:11px;color:#888">
                <?php
                $last_events = $wpdb->get_var("SELECT created_at FROM $table ORDER BY id DESC LIMIT 1");
                echo $last_events ? 'Last event: ' . human_time_diff(strtotime($last_events)) . ' ago' : 'No events yet';
                ?>
            </span>
            <a href="<?php echo admin_url('admin.php?page=swps-dashboard'); ?>" class="button button-small">View Dashboard</a>
        </div>
        <?php
    }
}
