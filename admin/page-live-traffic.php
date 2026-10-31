<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-chart-line"></span> Live Traffic Monitor</h1>
    <p class="description" style="margin:-8px 0 16px;max-width:760px">
        See who is visiting your site in real time — real people vs bots, which country they're from,
        and what pages they request. Helpful for spotting an attack as it happens.
    </p>

    <?php
    $settings = get_option('swps_settings', array());
    $enabled  = ! empty($settings['live_traffic_enabled']);
    $log      = get_transient(SWPS_Live_Traffic::TRANSIENT_KEY) ?: array();
    $stats    = SWPS_Live_Traffic::get_stats($log);
    ?>

    <div class="swps-status-bar <?php echo $enabled ? 'swps-status-active' : 'swps-status-inactive'; ?>">
        <span class="dashicons dashicons-chart-line"></span>
        Live Traffic Monitor is <strong><?php echo $enabled ? 'ENABLED' : 'DISABLED'; ?></strong>
    </div>

    <!-- Enable/Disable -->
    <div class="swps-card">
        <form method="post" action="options.php" style="display:inline">
            <?php settings_fields('swps_settings_group'); ?>
            <?php foreach ($settings as $k => $v): if ($k === 'live_traffic_enabled') continue; ?>
            <input type="hidden" name="swps_settings[<?php echo esc_attr($k); ?>]" value="<?php echo esc_attr($v); ?>">
            <?php endforeach; ?>
            <label class="swps-toggle" style="margin-right:12px">
                <input type="checkbox" name="swps_settings[live_traffic_enabled]" value="1" <?php checked($enabled); ?>>
                <span class="swps-slider"></span>
            </label>
            Enable Live Traffic Recording &nbsp;
            <?php submit_button('Save', 'secondary', 'submit', false); ?>
        </form>
    </div>

    <!-- Stats -->
    <div class="swps-stats-grid">
        <div class="swps-stat-card">
            <div class="swps-stat-num"><?php echo number_format($stats['total']); ?></div>
            <div class="swps-stat-label">Total Requests</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-green"><?php echo number_format($stats['humans']); ?></div>
            <div class="swps-stat-label">Human Visitors</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-red"><?php echo number_format($stats['bots']); ?></div>
            <div class="swps-stat-label">Bot Requests</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-blue"><?php echo number_format($stats['unique_ips']); ?></div>
            <div class="swps-stat-label">Unique IPs</div>
        </div>
    </div>

    <!-- Live Traffic Table -->
    <div class="swps-card">
        <div class="swps-card-header">
            <h2>Recent Requests</h2>
            <div class="swps-card-actions">
                <select id="swps-traffic-filter" class="swps-select-sm">
                    <option value="all">All Traffic</option>
                    <option value="bots">Bots Only</option>
                    <option value="humans">Humans Only</option>
                    <option value="blocked">Blocked IPs</option>
                </select>
                <button id="swps-traffic-refresh" class="button">Refresh</button>
                <button id="swps-traffic-clear" class="button button-link-delete">Clear Log</button>
            </div>
        </div>

        <table class="swps-table widefat striped" id="swps-traffic-table">
            <thead>
                <tr><th>Time</th><th>IP</th><th>Type</th><th>Method</th><th>URI</th><th>Country</th><th>Action</th></tr>
            </thead>
            <tbody>
            <?php
            $display = array_slice($log, 0, 50);
            foreach ($display as $entry):
                $time = date_i18n('H:i:s', $entry['time']);
                $is_bot = $entry['bot'];
            ?>
            <tr>
                <td class="swps-nowrap"><?php echo esc_html($time); ?></td>
                <td><code><?php echo esc_html($entry['ip']); ?></code></td>
                <td>
                    <?php if ($is_bot): ?>
                    <span class="swps-badge swps-badge-warning">Bot</span>
                    <?php else: ?>
                    <span class="swps-badge swps-badge-ok">Human</span>
                    <?php endif; ?>
                </td>
                <td><code><?php echo esc_html($entry['method']); ?></code></td>
                <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="<?php echo esc_attr($entry['uri']); ?>">
                    <code><?php echo esc_html($entry['uri']); ?></code>
                </td>
                <td><?php echo esc_html($entry['country'] ?: '—'); ?></td>
                <td>
                    <button class="button button-small swps-block-btn" data-ip="<?php echo esc_attr($entry['ip']); ?>">Block</button>
                </td>
            </tr>
            <?php endforeach; ?>
            <?php if (empty($display)): ?>
            <tr><td colspan="7" style="text-align:center;padding:24px">No traffic recorded yet. Enable the monitor and reload some pages.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- Top IPs -->
    <?php if (!empty($stats['top_ips'])): ?>
    <div class="swps-card">
        <h2>Top IPs (Last Hour)</h2>
        <table class="swps-table widefat striped">
            <thead><tr><th>IP Address</th><th>Requests</th><th>Status</th><th>Action</th></tr></thead>
            <tbody>
            <?php foreach ($stats['top_ips'] as $ip => $count): ?>
            <tr>
                <td><code><?php echo esc_html($ip); ?></code></td>
                <td><?php echo number_format($count); ?></td>
                <td>
                    <?php if (SWPS_IP_Blocker::is_blocked($ip)): ?>
                    <span class="swps-badge swps-badge-critical">Blocked</span>
                    <?php else: ?>
                    <span class="swps-badge swps-badge-ok">Active</span>
                    <?php endif; ?>
                </td>
                <td>
                    <button class="button button-small swps-block-btn" data-ip="<?php echo esc_attr($ip); ?>">Block IP</button>
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
    $('#swps-traffic-refresh').on('click', function() {
        var filter = $('#swps-traffic-filter').val();
        $.post(ajaxurl, { action: 'swps_live_traffic_data', nonce: swps_vars.nonce, filter: filter }, function(res) {
            if (res.success) location.reload();
        });
    });
    $('#swps-traffic-clear').on('click', function() {
        if (!confirm('Clear all traffic records?')) return;
        $.post(ajaxurl, { action: 'swps_live_traffic_clear', nonce: swps_vars.nonce }, function() { location.reload(); });
    });
    $('#swps-traffic-filter').on('change', function() { location.href = location.href + '&filter=' + $(this).val(); });
});
</script>
