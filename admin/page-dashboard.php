<?php if ( ! defined('ABSPATH') ) exit; ?>
<?php
global $wpdb;
$settings     = get_option( 'swps_settings', array() );
$log_counts   = SWPS_Activity_Log::get_counts_by_severity();
$blocked_ips  = SWPS_IP_Blocker::get_count();
$admins       = SWPS_Admin_Monitor::get_all_admins();
$known_admins = get_option( 'swps_known_admins', array() );
$last_scan    = SWPS_Scanner::get_last_scan();
$recent_fails = SWPS_Login_Protection::get_recent_failed_logins(5);
$recent_logs  = SWPS_Activity_Log::get_logs( array('limit' => 8) );
$waf_stats    = class_exists('SWPS_WAF') ? SWPS_WAF::get_stats() : array('total'=>0,'by_type'=>array());

// Overall security grade (reuse Full Scan scoring if available).
// Fix: calculate_score() deducts points only for issues in a STORED scan
// result — on a brand-new install (or right after activation, before the
// owner has ever clicked "Run Full Scan") that option is empty, so the
// math produced a perfect, unearned "Grade A" with nothing actually having
// been checked yet. Track whether a scan has ever actually completed and
// show that honestly instead of a fake score.
$has_ever_scanned = class_exists('SWPS_Full_Scan') && ! empty( get_option( SWPS_Full_Scan::RESULT_OPT, array() ) );
if ( $has_ever_scanned ) {
    $sc    = SWPS_Full_Scan::calculate_score();
    $score = $sc['score']; $grade = $sc['grade']; $score_color = $sc['color'];
} else {
    $score = 100;
    if ( $log_counts['critical'] > 0 ) $score -= 30;
    if ( $log_counts['warning']  > 5 ) $score -= 15;
    $score = max(0, $score);
    $grade = $score >= 90 ? 'A' : ($score >= 70 ? 'B' : ($score >= 50 ? 'C' : 'D'));
    $score_color = $score >= 80 ? '#27ae60' : ($score >= 50 ? '#f39c12' : '#e74c3c');
}

// 7-day event trend
$table = $wpdb->prefix . SWPS_TABLE_LOG;
$rows  = $wpdb->get_results( "SELECT DATE(created_at) d,
            SUM(severity='critical') c, SUM(severity='warning') w, SUM(severity='info') i
            FROM $table WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
            GROUP BY DATE(created_at)", OBJECT_K );
$days = array(); $d_crit = array(); $d_warn = array(); $d_info = array();
for ( $i = 6; $i >= 0; $i-- ) {
    $key = date('Y-m-d', strtotime("-$i day"));
    $days[]   = date('M j', strtotime($key));
    $d_crit[] = isset($rows[$key]) ? (int)$rows[$key]->c : 0;
    $d_warn[] = isset($rows[$key]) ? (int)$rows[$key]->w : 0;
    $d_info[] = isset($rows[$key]) ? (int)$rows[$key]->i : 0;
}

// Protection status
$features = array(
    array('WAF Firewall',   !empty($settings['waf_enabled']),              'swps-waf'),
    array('Two-Factor Auth',!empty($settings['two_factor_enabled']),       'swps-2fa'),
    array('File Integrity', !empty($settings['fim_enabled']),              'swps-file-integrity'),
    array('Security Headers',!empty($settings['security_headers_enabled']), 'swps-headers'),
    array('Rate Limiter',   !empty($settings['rate_limiter_enabled']),     'swps-advanced'),
    array('Honeypot',       !empty($settings['honeypot_enabled']),         'swps-threat-intel'),
    array('SSL Monitor',    !empty($settings['ssl_monitor_enabled']),      'swps-uptime'),
    array('Core Repair',    !empty($settings['core_repair_enabled']),      'swps-core-repair'),
);
$active_features = count(array_filter($features, fn($f) => $f[1]));
$threat_count   = $last_scan ? count($last_scan['threats'] ?? array()) : 0;
?>
<div class="wrap swps-wrap">
    <div class="swps-header">
        <?php echo swps_brand_logo_svg( 40 ); ?>
        <div>
            <h1>WP Secure Pro <span class="swps-version">v<?php echo SWPS_VERSION; ?></span></h1>
            <p>Security overview for <strong><?php echo esc_html(get_bloginfo('name')); ?></strong></p>
        </div>
        <div style="margin-left:auto;display:flex;gap:8px">
            <a href="<?php echo admin_url('admin.php?page=swps-full-scan'); ?>" class="swps-btn swps-btn-primary"><span class="dashicons dashicons-search"></span> Full Scan</a>
            <a href="<?php echo admin_url('admin.php?page=swps-settings'); ?>" class="swps-btn"><span class="dashicons dashicons-admin-settings"></span> Settings</a>
        </div>
    </div>

    <!-- Hero: score + KPIs -->
    <div class="swps-dash-hero">
        <div class="swps-card swps-score-card" style="margin:0">
            <?php if ( ! $has_ever_scanned ) : ?>
            <div class="swps-score-circle" style="--score-color: #94a3b8">
                <span class="swps-score-number" style="font-size:16px">—</span>
                <span class="swps-score-label">Not scanned</span>
            </div>
            <div class="swps-score-info">
                <h2>Security Score</h2>
                <p>No score yet — this site hasn't been scanned. Run a Full Scan to see where it actually stands.</p>
                <p class="swps-muted"><?php echo $active_features; ?> of <?php echo count($features); ?> core protections active</p>
            </div>
            <?php else : ?>
            <div class="swps-score-circle" style="--score-color: <?php echo $score_color; ?>">
                <span class="swps-score-number"><?php echo $score; ?></span>
                <span class="swps-score-label">Grade <?php echo $grade; ?></span>
            </div>
            <div class="swps-score-info">
                <h2>Security Score</h2>
                <p><?php echo $score >= 80 ? 'Your site is well protected.' : ($score >= 50 ? 'A few things need your attention.' : 'Action needed — review critical items.'); ?></p>
                <p class="swps-muted"><?php echo $active_features; ?> of <?php echo count($features); ?> core protections active</p>
            </div>
            <?php endif; ?>
        </div>

        <div class="swps-stats-row" style="margin:0">
            <div class="swps-stat-card swps-stat-critical">
                <span class="dashicons dashicons-warning"></span>
                <div class="swps-stat-number"><?php echo $log_counts['critical']; ?></div>
                <div class="swps-stat-label">Critical Events</div>
            </div>
            <div class="swps-stat-card swps-stat-warning">
                <span class="dashicons dashicons-flag"></span>
                <div class="swps-stat-number"><?php echo $log_counts['warning']; ?></div>
                <div class="swps-stat-label">Warnings</div>
            </div>
            <div class="swps-stat-card swps-stat-blocked">
                <span class="dashicons dashicons-dismiss"></span>
                <div class="swps-stat-number"><?php echo number_format($blocked_ips); ?></div>
                <div class="swps-stat-label">Blocked IPs</div>
            </div>
            <div class="swps-stat-card swps-stat-info">
                <span class="dashicons dashicons-shield"></span>
                <div class="swps-stat-number"><?php echo number_format($waf_stats['total'] ?? 0); ?></div>
                <div class="swps-stat-label">Attacks Blocked</div>
            </div>
        </div>
    </div>

    <!-- Analytics -->
    <div class="swps-grid-2col">
        <div class="swps-card">
            <div class="swps-card-header"><span class="dashicons dashicons-chart-area"></span> Security Events — Last 7 Days</div>
            <div class="swps-card-body swps-chart-wrap" style="border:0">
                <canvas id="swps-trend-chart" height="120"></canvas>
            </div>
        </div>
        <div class="swps-card">
            <div class="swps-card-header"><span class="dashicons dashicons-chart-pie"></span> Attacks Blocked by Type</div>
            <div class="swps-card-body swps-chart-wrap" style="border:0">
                <?php if (!empty($waf_stats['by_type'])): ?>
                <canvas id="swps-attack-chart" height="120"></canvas>
                <?php else: ?>
                <p class="swps-empty">No attacks blocked yet. The firewall is watching.</p>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Protection status -->
    <div class="swps-card">
        <div class="swps-card-header"><span class="dashicons dashicons-yes-alt"></span> Protection Status</div>
        <div class="swps-card-body">
            <div class="swps-feature-grid">
                <?php foreach ($features as $f): ?>
                <a class="swps-feature-chip <?php echo $f[1] ? 'on' : 'off'; ?>" href="<?php echo admin_url('admin.php?page=' . $f[2]); ?>">
                    <span class="dashicons <?php echo $f[1] ? 'dashicons-yes' : 'dashicons-no-alt'; ?>"></span>
                    <span class="swps-feature-name"><?php echo esc_html($f[0]); ?></span>
                    <span class="swps-feature-state"><?php echo $f[1] ? 'ON' : 'OFF'; ?></span>
                </a>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <div class="swps-main-grid">
        <!-- Admin Users -->
        <div class="swps-card">
            <div class="swps-card-header"><span class="dashicons dashicons-admin-users"></span> Admin Users
                <span class="swps-badge swps-badge-<?php echo count($admins) > 1 ? 'warning' : 'ok'; ?>" style="margin-left:auto"><?php echo count($admins); ?></span>
            </div>
            <div class="swps-card-body">
                <table class="swps-table">
                    <thead><tr><th>Username</th><th>Email</th><th>Status</th></tr></thead>
                    <tbody>
                    <?php foreach ($admins as $admin): $is_known = in_array($admin->ID, $known_admins); ?>
                        <tr class="<?php echo !$is_known ? 'swps-row-danger' : ''; ?>">
                            <td><strong><?php echo esc_html($admin->user_login); ?></strong></td>
                            <td><?php echo esc_html($admin->user_email); ?></td>
                            <td><?php echo $is_known ? '<span class="swps-badge swps-badge-ok">Known</span>' : '<span class="swps-badge swps-badge-danger">Unknown</span>'; ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Recent Failed Logins -->
        <div class="swps-card">
            <div class="swps-card-header"><span class="dashicons dashicons-lock"></span> Recent Failed Logins</div>
            <div class="swps-card-body">
                <?php if (empty($recent_fails)): ?>
                    <p class="swps-empty">No failed logins recorded.</p>
                <?php else: ?>
                <table class="swps-table">
                    <thead><tr><th>IP Address</th><th>User</th><th>Tries</th></tr></thead>
                    <tbody>
                    <?php foreach ($recent_fails as $fail): ?>
                        <tr>
                            <td><code><?php echo esc_html($fail->ip_address); ?></code>
                                <button class="swps-btn-sm swps-block-btn" data-ip="<?php echo esc_attr($fail->ip_address); ?>">Block</button></td>
                            <td><?php echo esc_html($fail->username); ?></td>
                            <td><span class="swps-badge swps-badge-warning"><?php echo intval($fail->attempts); ?></span></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>
            </div>
        </div>

        <!-- Recent Activity -->
        <div class="swps-card swps-card-full">
            <div class="swps-card-header"><span class="dashicons dashicons-list-view"></span> Recent Activity
                <a href="<?php echo admin_url('admin.php?page=swps-monitoring&tab=activity'); ?>" style="margin-left:auto;font-size:12px">View All &rarr;</a>
            </div>
            <div class="swps-card-body">
                <table class="swps-table swps-table-striped">
                    <thead><tr><th>Time</th><th>Event</th><th>Severity</th><th>User</th><th>IP</th><th>Description</th></tr></thead>
                    <tbody>
                    <?php foreach ($recent_logs as $log): ?>
                        <tr>
                            <td class="swps-nowrap"><small><?php echo esc_html(date('M d H:i', strtotime($log->created_at))); ?></small></td>
                            <td><code><?php echo esc_html($log->event_type); ?></code></td>
                            <td><span class="swps-badge swps-badge-<?php echo esc_attr($log->severity); ?>"><?php echo esc_html($log->severity); ?></span></td>
                            <td><?php echo esc_html($log->username ?: '-'); ?></td>
                            <td><code><?php echo esc_html($log->ip_address ?: '-'); ?></code></td>
                            <td><?php echo esc_html(mb_substr($log->description, 0, 70)); ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script>
jQuery(function($){
    var dashChartTries = 0;
    function initDashCharts() {
        if (typeof Chart === 'undefined') {
            dashChartTries++;
            if (dashChartTries > 50) {
                $('#swps-trend-chart, #swps-attack-chart').each(function(){
                    $(this).replaceWith('<p style="color:#f87171;text-align:center;padding:20px">Chart library failed to load — check your connection and refresh.</p>');
                });
                return;
            }
            setTimeout(initDashCharts, 100);
            return;
        }
    Chart.defaults.font.family = '-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif';
    Chart.defaults.color = '#7f8c8d';

    var tctx = document.getElementById('swps-trend-chart');
    if (tctx) new Chart(tctx, {
        type: 'line',
        data: {
            labels: <?php echo wp_json_encode($days); ?>,
            datasets: [
                { label:'Critical', data:<?php echo wp_json_encode($d_crit); ?>, borderColor:'#e74c3c', backgroundColor:'rgba(231,76,60,.12)', fill:true, tension:.35 },
                { label:'Warnings', data:<?php echo wp_json_encode($d_warn); ?>, borderColor:'#f39c12', backgroundColor:'rgba(243,156,18,.10)', fill:true, tension:.35 },
                { label:'Info',     data:<?php echo wp_json_encode($d_info); ?>, borderColor:'#2980b9', backgroundColor:'rgba(41,128,185,.08)', fill:true, tension:.35 }
            ]
        },
        options: { responsive:true, maintainAspectRatio:false,
            plugins:{ legend:{ position:'bottom', labels:{ boxWidth:12, usePointStyle:true } } },
            scales:{ y:{ beginAtZero:true, ticks:{ precision:0 }, grid:{ color:'#eef2f7' } }, x:{ grid:{ display:false } } }
        }
    });

    <?php if (!empty($waf_stats['by_type'])): ?>
    var actx = document.getElementById('swps-attack-chart');
    if (actx) new Chart(actx, {
        type: 'doughnut',
        data: {
            labels: <?php echo wp_json_encode(array_map('strtoupper', array_keys($waf_stats['by_type']))); ?>,
            datasets: [{ data: <?php echo wp_json_encode(array_values($waf_stats['by_type'])); ?>,
                backgroundColor:['#e74c3c','#f39c12','#2980b9','#27ae60','#8e44ad','#16a085','#d35400'] }]
        },
        options: { responsive:true, maintainAspectRatio:false, cutout:'62%',
            plugins:{ legend:{ position:'right', labels:{ boxWidth:12, usePointStyle:true } } } }
    });
    <?php endif; ?>
    } // end initDashCharts
    initDashCharts();
});
</script>
