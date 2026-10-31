<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-visibility"></span> Uptime Monitor</h1>
    <p class="description" style="margin:-8px 0 16px;max-width:760px">
        Regularly checks that your site is online and loading properly. If it ever goes down, you get an
        alert right away so you can act fast.
    </p>

    <?php
    $settings = get_option('swps_settings', array());
    $stats    = SWPS_Uptime_Monitor::get_stats();
    $up_count = count(array_filter($stats, fn($s) => $s['status'] === 'up'));
    $dn_count = count($stats) - $up_count;
    ?>

    <!-- Summary stats -->
    <div class="swps-stats-grid">
        <div class="swps-stat-card">
            <div class="swps-stat-num"><?php echo count($stats); ?></div>
            <div class="swps-stat-label">URLs Monitored</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-green"><?php echo $up_count; ?></div>
            <div class="swps-stat-label">Online</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-red"><?php echo $dn_count; ?></div>
            <div class="swps-stat-label">Down</div>
        </div>
    </div>

    <!-- Status cards -->
    <?php if (!empty($stats)): ?>
    <div class="swps-card">
        <div class="swps-card-header">
            <h2>Monitor Status</h2>
            <button id="swps-uptime-check-now" class="button button-primary">Check Now</button>
        </div>
        <table class="swps-table widefat striped">
            <thead>
                <tr><th>URL</th><th>Status</th><th>Response</th><th>Uptime (24h)</th><th>Last Checked</th><th>History</th><th>Action</th></tr>
            </thead>
            <tbody>
            <?php foreach ($stats as $key => $s):
                $is_up     = ($s['status'] === 'up');
                $pct_class = $s['uptime_pct'] >= 99 ? 'swps-color-green' : ($s['uptime_pct'] >= 95 ? 'swps-color-orange' : 'swps-color-red');
                $ms_label  = $s['avg_ms'] > 0 ? $s['avg_ms'] . 'ms' : '—';
                $history   = array_reverse($s['history'] ?? array());
            ?>
            <tr>
                <td style="max-width:200px;word-break:break-all">
                    <a href="<?php echo esc_url($s['url']); ?>" target="_blank"><?php echo esc_html(parse_url($s['url'], PHP_URL_HOST) ?: $s['url']); ?></a>
                    <div class="swps-muted" style="font-size:11px"><?php echo esc_html($s['url']); ?></div>
                </td>
                <td>
                    <span class="swps-badge <?php echo $is_up ? 'swps-badge-ok' : 'swps-badge-critical'; ?>">
                        <?php echo $is_up ? 'UP' : 'DOWN'; ?>
                    </span>
                    <?php if (!$is_up && !empty($s['error'])): ?>
                    <div class="swps-muted" style="font-size:11px"><?php echo esc_html($s['error']); ?></div>
                    <?php endif; ?>
                </td>
                <td><?php echo esc_html($ms_label); ?></td>
                <td>
                    <span class="<?php echo $pct_class; ?>"><strong><?php echo $s['uptime_pct']; ?>%</strong></span>
                </td>
                <td class="swps-muted">
                    <?php echo $s['checked'] ? human_time_diff($s['checked']) . ' ago' : '—'; ?>
                </td>
                <td>
                    <!-- Mini sparkline: last 48 checks -->
                    <div style="display:flex;gap:1px;align-items:center">
                    <?php
                    $hist_slice = array_slice(array_reverse($history), 0, 48);
                    $hist_slice = array_reverse($hist_slice);
                    foreach ($hist_slice as $h):
                        $c = $h['status'] === 'up' ? '#2ecc71' : '#e74c3c';
                    ?>
                    <span title="<?php echo date('H:i', $h['time']); ?> — <?php echo $h['status']; ?>"
                          style="width:4px;height:16px;background:<?php echo $c; ?>;border-radius:1px;display:inline-block"></span>
                    <?php endforeach; ?>
                    </div>
                </td>
                <td>
                    <button class="button button-small swps-uptime-remove" data-url="<?php echo esc_attr($s['url']); ?>">Remove</button>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>

    <!-- Add URL -->
    <div class="swps-card">
        <h2>Add URL to Monitor</h2>
        <div style="display:flex;gap:10px;align-items:center">
            <input type="url" id="swps-uptime-new-url" placeholder="https://example.com" class="regular-text" value="">
            <button id="swps-uptime-add-url" class="button button-primary">Add URL</button>
        </div>
        <div id="swps-uptime-add-result" style="margin-top:8px"></div>
    </div>

    <!-- Settings -->
    <div class="swps-card">
        <h2>Uptime Monitor Settings</h2>
        <form method="post" action="options.php">
            <?php settings_fields('swps_settings_group'); ?>
            <table class="form-table swps-form-table">
                <tr>
                    <th>Enable Uptime Monitor</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_settings[uptime_enabled]" value="1" <?php checked(!empty($settings['uptime_enabled'])); ?>>
                            <span class="swps-slider"></span>
                        </label> Check all URLs every 5 minutes
                    </td>
                </tr>
                <tr>
                    <th>URLs to Monitor</th>
                    <td>
                        <textarea name="swps_settings[uptime_urls]" rows="5" class="large-text"><?php echo esc_textarea($settings['uptime_urls'] ?? ''); ?></textarea>
                        <p class="description">One URL per line. Leave empty to monitor this site only.</p>
                    </td>
                </tr>
                <tr>
                    <th>Alert on Downtime</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_settings[uptime_alert_down]" value="1" <?php checked(!empty($settings['uptime_alert_down'])); ?>>
                            <span class="swps-slider"></span>
                        </label> Send alert when a site goes down
                    </td>
                </tr>
                <tr>
                    <th>Alert on Recovery</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_settings[uptime_alert_recover]" value="1" <?php checked(!empty($settings['uptime_alert_recover'])); ?>>
                            <span class="swps-slider"></span>
                        </label> Send alert when a site comes back up
                    </td>
                </tr>
            </table>
            <?php submit_button('Save Uptime Settings'); ?>
        </form>
    </div>
</div>

<script>
jQuery(document).ready(function($) {
    $('#swps-uptime-check-now').on('click', function() {
        var $btn = $(this).prop('disabled',true).text('Checking...');
        $.post(ajaxurl, {action:'swps_uptime_check_now', nonce:swps_vars.nonce}, function(res) {
            $btn.prop('disabled',false).text('Check Now');
            if (res.success) location.reload();
        });
    });

    $('#swps-uptime-add-url').on('click', function() {
        var url = $('#swps-uptime-new-url').val().trim();
        if (!url) return;
        var $btn = $(this).prop('disabled',true);
        $.post(ajaxurl, {action:'swps_uptime_add_url', nonce:swps_vars.nonce, url:url}, function(res) {
            $btn.prop('disabled',false);
            var cls = res.success ? 'swps-notice-ok' : 'swps-notice-critical';
            $('#swps-uptime-add-result').html('<div class="swps-notice '+cls+'">'+(res.data||'Done')+'</div>');
            if (res.success) { $('#swps-uptime-new-url').val(''); setTimeout(()=>location.reload(),1200); }
        });
    });

    $('.swps-uptime-remove').on('click', function() {
        if (!confirm('Remove this URL from monitoring?')) return;
        var url = $(this).data('url');
        $.post(ajaxurl, {action:'swps_uptime_remove_url', nonce:swps_vars.nonce, url:url}, function(res) {
            if (res.success) location.reload();
        });
    });
});
</script>
