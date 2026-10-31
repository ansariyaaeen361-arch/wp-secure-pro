<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-database"></span> Database Security Monitor</h1>
    <p class="description" style="margin:-8px 0 16px;max-width:760px">
        Checks your database for signs of trouble — unknown database users, hidden malicious code in
        your settings table, suspicious scheduled tasks, and PHP files hiding in your uploads folder.
    </p>

    <?php
    global $wpdb;
    $last_scan = get_option('swps_last_db_scan', array());
    $settings  = get_option('swps_settings', array());
    ?>

    <div class="swps-card">
        <div class="swps-card-header">
            <h2>Database Security Scan</h2>
            <button id="swps-db-scan-btn" class="button button-primary">
                <span class="dashicons dashicons-database-view" style="margin-top:3px"></span> Scan Now
            </button>
        </div>
        <?php if (!empty($last_scan['time'])): ?>
        <p class="swps-muted">Last scan: <?php echo date_i18n('M j, Y H:i', $last_scan['time']); ?></p>
        <?php endif; ?>
    </div>

    <?php if (!empty($last_scan['results'])): ?>
    <div class="swps-card">
        <h2>Scan Results</h2>
        <table class="swps-table widefat striped">
            <thead><tr><th>Check</th><th>Value</th><th>Status</th><th>Details</th></tr></thead>
            <tbody>
            <?php foreach ($last_scan['results'] as $key => $result):
                $badge_class = $result['status'] === 'critical' ? 'swps-badge-critical' : ($result['status'] === 'warning' ? 'swps-badge-warning' : 'swps-badge-ok');
            ?>
            <tr>
                <td><strong><?php echo esc_html($result['label']); ?></strong></td>
                <td><?php echo esc_html($result['value']); ?></td>
                <td><span class="swps-badge <?php echo $badge_class; ?>"><?php echo esc_html(ucfirst($result['status'])); ?></span></td>
                <td>
                    <?php echo esc_html($result['note']); ?>
                    <?php if (!empty($result['items'])): ?>
                    <details style="margin-top:4px"><summary>Show <?php echo count($result['items']); ?> item(s)</summary>
                    <ul style="margin:6px 0 0 16px">
                        <?php foreach (array_slice($result['items'], 0, 10) as $item): ?>
                        <li><code><?php echo esc_html($item); ?></code></li>
                        <?php endforeach; ?>
                    </ul>
                    </details>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>

    <!-- Table Prefix Changer -->
    <div class="swps-card">
        <h2>Change Database Table Prefix</h2>
        <p>Your current prefix is: <strong><code><?php echo esc_html($wpdb->prefix); ?></code></strong>
        <?php if ($wpdb->prefix === 'wp_'): ?>
        <span class="swps-badge swps-badge-warning">Default — Recommend Changing</span>
        <?php else: ?>
        <span class="swps-badge swps-badge-ok">Custom Prefix</span>
        <?php endif; ?>
        </p>

        <div class="swps-warning-box">
            <strong>Important:</strong> After changing the prefix, you MUST manually update <code>$table_prefix</code> in your <code>wp-config.php</code> file. Failure to do so will lock you out of WordPress. <strong>Back up your database first.</strong>
        </div>

        <div id="swps-prefix-form" style="margin-top:16px">
            <input type="text" id="swps-new-prefix" placeholder="new_prefix_" pattern="[a-z][a-z0-9_]*_" class="regular-text" style="margin-right:8px">
            <button id="swps-change-prefix-btn" class="button button-secondary">Change Prefix</button>
        </div>
        <p class="description">Lowercase letters, numbers, underscores only. Must end with underscore. Example: <code>mywp_</code></p>
        <div id="swps-prefix-result" style="margin-top:12px"></div>
    </div>

    <!-- MySQL Users -->
    <?php $db_users = SWPS_DB_Monitor::get_db_users(); ?>
    <?php if (!empty($db_users)): ?>
    <div class="swps-card">
        <h2>MySQL Database Users</h2>
        <table class="swps-table widefat striped">
            <thead><tr><th>User</th><th>Host</th><th>Status</th></tr></thead>
            <tbody>
            <?php
            $known_users = SWPS_DB_Monitor::get_known_db_users();
            foreach ($db_users as $user):
                $user_str = $user['User'] . '@' . $user['Host'];
                $is_known = in_array($user_str, $known_users);
            ?>
            <tr>
                <td><code><?php echo esc_html($user['User']); ?></code></td>
                <td><code><?php echo esc_html($user['Host']); ?></code></td>
                <td>
                    <?php if ($is_known || empty($known_users)): ?>
                    <span class="swps-badge swps-badge-ok">Known</span>
                    <?php else: ?>
                    <span class="swps-badge swps-badge-critical">Unknown — Review!</span>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <form method="post" style="margin-top:10px">
            <?php wp_nonce_field('swps_approve_db_users', 'swps_db_nonce'); ?>
            <button type="submit" name="swps_approve_users" class="button">Mark All Current Users as Known</button>
        </form>
    </div>
    <?php endif; ?>
</div>

<script>
jQuery(document).ready(function($) {
    $('#swps-db-scan-btn').on('click', function() {
        var $btn = $(this).prop('disabled', true).text('Scanning...');
        $.post(ajaxurl, { action: 'swps_db_scan', nonce: swps_vars.nonce }, function(res) {
            $btn.prop('disabled', false).text('Scan Now');
            if (res.success) location.reload();
            else alert('Scan failed: ' + (res.data || 'Error'));
        });
    });

    $('#swps-change-prefix-btn').on('click', function() {
        var newPrefix = $('#swps-new-prefix').val().trim();
        if (!newPrefix || !/^[a-z][a-z0-9_]*_$/.test(newPrefix)) {
            alert('Invalid prefix format. Use lowercase letters/numbers/underscores and end with underscore.');
            return;
        }
        if (!confirm('Change table prefix to "' + newPrefix + '"?\n\nYou MUST update wp-config.php immediately after!')) return;

        var $btn = $(this).prop('disabled', true).text('Changing...');
        $.post(ajaxurl, { action: 'swps_db_change_prefix', nonce: swps_vars.nonce, new_prefix: newPrefix }, function(res) {
            $btn.prop('disabled', false).text('Change Prefix');
            var $result = $('#swps-prefix-result');
            if (res.success) $result.html('<div class="notice notice-success"><p>' + res.data + '</p></div>');
            else $result.html('<div class="notice notice-error"><p>Error: ' + res.data + '</p></div>');
        });
    });
});
</script>

<?php
// Handle approve DB users
if (isset($_POST['swps_approve_users']) && wp_verify_nonce($_POST['swps_db_nonce'] ?? '', 'swps_approve_db_users')) {
    $users = SWPS_DB_Monitor::get_db_users();
    $list  = array_map(fn($u) => $u['User'] . '@' . $u['Host'], $users);
    SWPS_DB_Monitor::save_known_db_users($list);
    echo '<div class="notice notice-success is-dismissible"><p>All current MySQL users marked as known.</p></div>';
}
?>
