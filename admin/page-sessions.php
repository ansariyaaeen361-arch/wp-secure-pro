<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-admin-users"></span> Session Manager</h1>
    <p class="description" style="margin:-8px 0 16px;max-width:760px">
        See everyone currently logged into your site and from where. You can instantly log out (kill)
        any session — very handy if an account looks compromised.
    </p>

    <?php
    $sessions = SWPS_Session_Manager::get_all_sessions();
    $stats    = SWPS_Session_Manager::get_stats();
    $my_token = wp_get_session_token();
    $anomalies= SWPS_Anomaly_Detection::get_history(20);
    ?>

    <!-- Stats -->
    <div class="swps-stats-grid">
        <div class="swps-stat-card">
            <div class="swps-stat-num"><?php echo $stats['total']; ?></div>
            <div class="swps-stat-label">Active Sessions</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-red"><?php echo $stats['admin_count']; ?></div>
            <div class="swps-stat-label">Admin Sessions</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-blue"><?php echo $stats['unique_users']; ?></div>
            <div class="swps-stat-label">Unique Users</div>
        </div>
    </div>

    <!-- Kill All -->
    <div class="swps-card">
        <div class="swps-card-header">
            <h2>Active Sessions</h2>
            <div class="swps-card-actions">
                <button id="swps-kill-all-sessions" class="button button-link-delete">
                    <span class="dashicons dashicons-dismiss"></span> Terminate All Other Sessions
                </button>
            </div>
        </div>

        <table class="swps-table widefat striped">
            <thead><tr><th>User</th><th>IP Address</th><th>Country</th><th>Device</th><th>Logged In</th><th>Status</th><th>Action</th></tr></thead>
            <tbody>
            <?php if (empty($sessions)): ?>
            <tr><td colspan="7" style="text-align:center;padding:20px">No active sessions tracked. Sessions are recorded on next login.</td></tr>
            <?php endif; ?>
            <?php foreach ($sessions as $token => $session):
                $user = get_userdata($session['user_id']);
                $is_me = ($token === $my_token);
                $ua_short = substr($session['ua'] ?? '', 0, 60);
                $is_admin_user = $user && user_can($user->ID, 'manage_options');
            ?>
            <tr <?php echo $is_me ? 'style="background:#f0fff0"' : ''; ?>>
                <td>
                    <strong><?php echo esc_html($user ? $user->display_name : '#'.$session['user_id']); ?></strong>
                    <?php if ($is_admin_user): ?><span class="swps-badge swps-badge-critical" style="font-size:9px">ADMIN</span><?php endif; ?>
                    <?php if ($is_me): ?><span class="swps-badge swps-badge-ok" style="font-size:9px">YOU</span><?php endif; ?>
                </td>
                <td><code><?php echo esc_html($session['ip'] ?? '—'); ?></code></td>
                <td><?php echo esc_html($session['country'] ?: '—'); ?></td>
                <td class="swps-muted" title="<?php echo esc_attr($session['ua'] ?? ''); ?>"><?php echo esc_html($ua_short); ?></td>
                <td><?php echo $session['login_time'] ? human_time_diff($session['login_time']) . ' ago' : '—'; ?></td>
                <td>
                    <span class="swps-badge swps-badge-ok">Active</span>
                </td>
                <td>
                    <?php if (!$is_me): ?>
                    <button class="button button-small swps-kill-session"
                        data-token="<?php echo esc_attr($token); ?>"
                        data-user="<?php echo esc_attr($session['user_id']); ?>">
                        Terminate
                    </button>
                    <?php else: ?>
                    <span class="swps-muted">Current</span>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- Session Limits -->
    <div class="swps-card">
        <h2>Session Settings</h2>
        <form method="post" action="options.php">
            <?php settings_fields('swps_settings_group'); ?>
            <table class="form-table swps-form-table">
                <tr>
                    <th>Max Sessions per User</th>
                    <td>
                        <input type="number" name="swps_settings[max_sessions_per_user]" value="<?php echo esc_attr(get_option('swps_settings')['max_sessions_per_user'] ?? 0); ?>" min="0" max="10" class="small-text">
                        <p class="description">0 = unlimited. When exceeded, oldest sessions are terminated automatically.</p>
                    </td>
                </tr>
                <tr>
                    <th>Anomaly Detection</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_settings[anomaly_detection_enabled]" value="1" <?php checked(!empty(get_option('swps_settings')['anomaly_detection_enabled'])); ?>>
                            <span class="swps-slider"></span>
                        </label> Detect suspicious login patterns (new country, new IP, odd hours)
                    </td>
                </tr>
                <tr>
                    <th>Alert on All Anomalies</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_settings[anomaly_alert_all]" value="1" <?php checked(!empty(get_option('swps_settings')['anomaly_alert_all'])); ?>>
                            <span class="swps-slider"></span>
                        </label> Send alert for warnings too (not just critical anomalies)
                    </td>
                </tr>
            </table>
            <?php submit_button('Save Session Settings'); ?>
        </form>
    </div>

    <!-- Anomaly History -->
    <?php if (!empty($anomalies)): ?>
    <div class="swps-card">
        <h2>Login Anomaly History</h2>
        <table class="swps-table widefat striped">
            <thead><tr><th>Time</th><th>User</th><th>IP</th><th>Country</th><th>Anomalies</th></tr></thead>
            <tbody>
            <?php foreach ($anomalies as $a): ?>
            <tr>
                <td><?php echo human_time_diff($a['time']); ?> ago</td>
                <td><strong><?php echo esc_html($a['user_login']); ?></strong></td>
                <td><code><?php echo esc_html($a['ip']); ?></code></td>
                <td><?php echo esc_html($a['country'] ?: '—'); ?></td>
                <td>
                    <?php foreach ($a['anomalies'] as $anomaly): ?>
                    <span class="swps-badge <?php echo $anomaly['severity'] === 'critical' ? 'swps-badge-critical' : 'swps-badge-warning'; ?>" style="margin-right:4px">
                        <?php echo esc_html($anomaly['type']); ?>
                    </span>
                    <?php endforeach; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>

<script>
jQuery(document).ready(function($) {
    $('#swps-kill-all-sessions').on('click', function() {
        if (!confirm('Terminate ALL other active sessions? You will stay logged in.')) return;
        $.post(ajaxurl, {action:'swps_kill_all_sessions', nonce:swps_vars.nonce}, function(res) {
            if (res.success) { alert(res.data); location.reload(); }
        });
    });
    $('.swps-kill-session').on('click', function() {
        var $btn = $(this);
        if (!confirm('Terminate this session?')) return;
        $.post(ajaxurl, {action:'swps_kill_session', nonce:swps_vars.nonce, token:$btn.data('token'), user_id:$btn.data('user')}, function(res) {
            if (res.success) $btn.closest('tr').fadeOut();
        });
    });
});
</script>
