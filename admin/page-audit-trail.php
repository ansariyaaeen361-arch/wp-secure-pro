<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-list-view"></span> Audit Trail</h1>
    <p class="description" style="margin:-8px 0 16px;max-width:760px">
        A detailed logbook of important actions on your site — logins, user changes, plugin/theme
        changes, settings edits and more. It answers "who did what, and when", which is perfect for
        spotting suspicious activity.
    </p>

    <?php
    $page    = max(1, intval($_GET['paged'] ?? 1));
    $limit   = 50;
    $offset  = ($page - 1) * $limit;
    $filter_action = sanitize_text_field($_GET['action_filter'] ?? '');
    $filter_user   = intval($_GET['user_filter'] ?? 0);

    $logs    = SWPS_Audit_Trail::get_logs(array('limit'=>$limit,'offset'=>$offset,'action'=>$filter_action,'user_id'=>$filter_user));

    $action_icons = array(
        'user_login'       => '🔑','user_logout'      => '🚪',
        'profile_updated'  => '✏️','user_deleted'     => '🗑️',
        'role_changed'     => '👑','plugin_activated' => '🔌',
        'plugin_deactivated'=>'🔌','theme_activated'  => '🎨',
        'option_updated'   => '⚙️','post_created'     => '📝',
        'post_updated'     => '📝','post_deleted'     => '🗑️',
        'media_uploaded'   => '🖼️',
    );
    ?>

    <!-- Filters & Export -->
    <div class="swps-card">
        <div class="swps-card-header">
            <form method="get" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                <input type="hidden" name="page" value="swps-audit">
                <select name="action_filter" class="swps-select-sm">
                    <option value="">All Actions</option>
                    <?php
                    $all_actions = array('user_login','user_logout','profile_updated','user_deleted','role_changed','plugin_activated','plugin_deactivated','theme_activated','option_updated','post_created','post_updated','post_deleted','media_uploaded');
                    foreach ($all_actions as $a):
                    ?>
                    <option value="<?php echo $a; ?>" <?php selected($filter_action, $a); ?>><?php echo esc_html(str_replace('_',' ',ucfirst($a))); ?></option>
                    <?php endforeach; ?>
                </select>
                <button type="submit" class="button">Filter</button>
                <?php if ($filter_action || $filter_user): ?>
                <a href="?page=swps-audit" class="button">Clear</a>
                <?php endif; ?>
            </form>
            <a href="<?php echo admin_url('admin-ajax.php?action=swps_audit_export&nonce=' . wp_create_nonce('swps_nonce')); ?>" class="button">
                Export CSV
            </a>
        </div>
    </div>

    <!-- Audit Log Table -->
    <div class="swps-card">
        <table class="swps-table widefat striped">
            <thead>
                <tr><th>Time</th><th>User</th><th>Action</th><th>Object</th><th>Details</th><th>IP</th></tr>
            </thead>
            <tbody>
            <?php if (empty($logs)): ?>
            <tr><td colspan="6" style="text-align:center;padding:24px">No audit records yet. Actions are tracked automatically.</td></tr>
            <?php endif; ?>
            <?php foreach ($logs as $log):
                $icon = $action_icons[$log['action']] ?? '📋';
                $action_label = str_replace('_', ' ', ucfirst($log['action']));
            ?>
            <tr>
                <td class="swps-nowrap">
                    <span title="<?php echo esc_attr($log['created_at']); ?>">
                        <?php echo human_time_diff(strtotime($log['created_at'])); ?> ago
                    </span>
                </td>
                <td>
                    <?php if ($log['user_id']): ?>
                    <a href="<?php echo admin_url('admin.php?page=swps-audit&user_filter=' . $log['user_id']); ?>">
                        <strong><?php echo esc_html($log['user_login']); ?></strong>
                    </a>
                    <?php else: ?>
                    <span class="swps-muted">system</span>
                    <?php endif; ?>
                </td>
                <td>
                    <span title="<?php echo esc_attr($log['action']); ?>">
                        <?php echo $icon; ?> <?php echo esc_html($action_label); ?>
                    </span>
                </td>
                <td>
                    <?php if ($log['object_type']): ?>
                    <span class="swps-badge swps-badge-ok"><?php echo esc_html($log['object_type']); ?></span>
                    <?php endif; ?>
                    <?php echo esc_html($log['object_name']); ?>
                </td>
                <td class="swps-muted"><?php echo esc_html($log['details']); ?></td>
                <td><code><?php echo esc_html($log['ip']); ?></code></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>

        <!-- Pagination -->
        <?php if (count($logs) === $limit): ?>
        <div class="swps-pagination" style="padding:12px 0">
            <?php if ($page > 1): ?>
            <a href="?page=swps-audit&paged=<?php echo $page-1; ?><?php echo $filter_action ? '&action_filter='.$filter_action : ''; ?>" class="button">← Previous</a>
            <?php endif; ?>
            <span class="swps-muted">Page <?php echo $page; ?></span>
            <a href="?page=swps-audit&paged=<?php echo $page+1; ?><?php echo $filter_action ? '&action_filter='.$filter_action : ''; ?>" class="button">Next →</a>
        </div>
        <?php endif; ?>
    </div>

    <!-- Pwned Check -->
    <div class="swps-card">
        <h2>Password Breach Check</h2>
        <p class="description">Check if any admin passwords appear in known data breach databases (HaveIBeenPwned). Your password is never sent — only a partial SHA-1 hash.</p>
        <div style="display:flex;gap:10px;align-items:center;margin-bottom:12px">
            <input type="password" id="swps-pwned-input" placeholder="Enter password to check..." class="regular-text">
            <button id="swps-pwned-check-btn" class="button button-primary">Check Password</button>
        </div>
        <div id="swps-pwned-result"></div>
    </div>
</div>

<script>
jQuery(document).ready(function($) {
    $('#swps-pwned-check-btn').on('click', function() {
        var pass = $('#swps-pwned-input').val();
        if (!pass) return;
        var $btn = $(this).prop('disabled',true).text('Checking...');
        $.post(ajaxurl, {action:'swps_check_pwned', nonce:swps_vars.nonce, password:pass}, function(res) {
            $btn.prop('disabled',false).text('Check Password');
            if (!res.success) return;
            var d = res.data;
            var cls = d.status === 'pwned' ? 'swps-notice-critical' : (d.status === 'safe' ? 'swps-notice-ok' : 'swps-notice-warning');
            $('#swps-pwned-result').html('<div class="swps-notice '+cls+'">'+d.message+'</div>');
            $('#swps-pwned-input').val('');
        });
    });
    $('#swps-pwned-input').on('keypress', function(e) { if(e.which===13) $('#swps-pwned-check-btn').click(); });
});
</script>
