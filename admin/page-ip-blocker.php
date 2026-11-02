<?php if ( ! defined('ABSPATH') ) exit; ?>
<?php
// Handle manual block form submit
if ( isset($_POST['swps_block_manual']) && check_admin_referer('swps_block_ip_nonce') ) {
    $ip     = sanitize_text_field( $_POST['ip_address'] ?? '' );
    $reason = sanitize_text_field( $_POST['reason'] ?? 'Manual block' );
    if ( filter_var($ip, FILTER_VALIDATE_IP) ) {
        SWPS_IP_Blocker::block_ip($ip, $reason);
        SWPS_Activity_Log::add('ip_blocked_manual', 'warning', "Manually blocked IP: $ip - $reason");
        echo '<div class="notice notice-success"><p>IP <strong>' . esc_html($ip) . '</strong> has been blocked.</p></div>';
    } else {
        echo '<div class="notice notice-error"><p>Invalid IP address.</p></div>';
    }
}

// Handle unblock
if ( isset($_GET['unblock']) && check_admin_referer('swps_unblock') ) {
    $ip = sanitize_text_field($_GET['unblock']);
    SWPS_IP_Blocker::unblock_ip($ip);
    echo '<div class="notice notice-success"><p>IP <strong>' . esc_html($ip) . '</strong> has been unblocked.</p></div>';
}

// Handle whitelist save — moved here from the WAF settings page since this
// is where every other IP-level action (block/unblock) already lives.
// Merges into swps_settings instead of overwriting it, same as every other
// single-field settings form in this plugin.
if ( isset($_POST['swps_save_whitelist']) && check_admin_referer('swps_whitelist_nonce') ) {
    $existing = get_option('swps_settings', array());
    $existing['waf_whitelist_ips'] = sanitize_textarea_field( wp_unslash( $_POST['waf_whitelist_ips'] ?? '' ) );
    update_option('swps_settings', $existing);
    echo '<div class="notice notice-success"><p>Whitelist saved.</p></div>';
}

$blocked = SWPS_IP_Blocker::get_blocked_ips();
$wl_settings = get_option('swps_settings', array());
?>
<div class="wrap swps-wrap">
    <div class="swps-header">
        <span class="dashicons dashicons-dismiss swps-logo-icon"></span>
        <div>
            <h1>IP Blocker</h1>
            <p>Block or unblock specific visitor IP addresses, and review the ones blocked automatically.</p>
        </div>
    </div>

    <div class="swps-grid-2col">
        <!-- Block New IP -->
        <div class="swps-card">
            <div class="swps-card-header"><span class="dashicons dashicons-plus-alt"></span> Block IP Address</div>
            <div class="swps-card-body">
                <form method="post">
                    <?php wp_nonce_field('swps_block_ip_nonce'); ?>
                    <table class="form-table">
                        <tr>
                            <th>IP Address</th>
                            <td><input type="text" name="ip_address" class="regular-text" placeholder="e.g. 192.168.1.100" required></td>
                        </tr>
                        <tr>
                            <th>Reason</th>
                            <td><input type="text" name="reason" class="regular-text" placeholder="e.g. Brute force attack"></td>
                        </tr>
                    </table>
                    <input type="hidden" name="swps_block_manual" value="1">
                    <button type="submit" class="swps-btn swps-btn-danger">🚫 Block This IP</button>
                </form>
            </div>
        </div>

        <!-- Quick Block from Login Attempts -->
        <div class="swps-card">
            <div class="swps-card-header"><span class="dashicons dashicons-lock"></span> Recent Attackers</div>
            <div class="swps-card-body">
                <?php $fails = SWPS_Login_Protection::get_recent_failed_logins(10); ?>
                <?php if (empty($fails)): ?>
                    <p class="swps-empty">✓ No recent failed login attempts.</p>
                <?php else: ?>
                <table class="swps-table">
                    <thead><tr><th>IP</th><th>User tried</th><th>Attempts</th><th>Action</th></tr></thead>
                    <tbody>
                    <?php foreach ($fails as $f): ?>
                        <tr>
                            <td><code><?php echo esc_html($f->ip_address); ?></code></td>
                            <td><?php echo esc_html($f->username); ?></td>
                            <td><span class="swps-badge swps-badge-warning"><?php echo intval($f->attempts); ?></span></td>
                            <td><button class="swps-btn-sm swps-block-btn" data-ip="<?php echo esc_attr($f->ip_address); ?>">Block</button></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Blocked IPs List -->
    <div class="swps-card">
        <div class="swps-card-header">
            <span class="dashicons dashicons-list-view"></span> Currently Blocked IPs
            <span class="swps-badge swps-badge-danger" style="float:right"><?php echo count($blocked); ?> blocked</span>
        </div>
        <div class="swps-card-body">
            <?php if (empty($blocked)): ?>
                <p class="swps-empty">No IPs are currently blocked.</p>
            <?php else: ?>
            <table class="swps-table swps-table-striped">
                <thead><tr><th>IP Address</th><th>Reason</th><th>Blocked At</th><th>Expires</th><th>Action</th></tr></thead>
                <tbody>
                <?php foreach ($blocked as $b): ?>
                    <tr>
                        <td><code><?php echo esc_html($b->ip_address); ?></code></td>
                        <td><?php echo esc_html($b->reason); ?></td>
                        <td><?php echo esc_html($b->blocked_at); ?></td>
                        <td><?php echo $b->expires_at ? esc_html($b->expires_at) : '<span class="swps-badge swps-badge-danger">Permanent</span>'; ?></td>
                        <td>
                            <a href="<?php echo wp_nonce_url(admin_url('admin.php?page=swps-access&tab=ipblocker&unblock=' . urlencode($b->ip_address)), 'swps_unblock'); ?>"
                               class="swps-btn-sm swps-btn-ok"
                               onclick="return confirm('Unblock <?php echo esc_attr($b->ip_address); ?>?')">Unblock</a>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
    </div>
</div>
