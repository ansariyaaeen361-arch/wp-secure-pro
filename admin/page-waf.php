<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-shield"></span> Firewall (WAF)</h1>
    <p class="description" style="margin:-8px 0 16px;max-width:760px">
        The firewall is your site's security guard. It checks every visitor request and blocks
        common hacking attempts (like trying to break into your database or inject bad code)
        <strong>before</strong> they can reach your site. We recommend keeping this ON.
    </p>

    <?php
    $settings = get_option('swps_settings', array());
    $enabled  = ! empty($settings['waf_enabled']);
    $mode     = $settings['waf_mode'] ?? 'block';
    $stats    = SWPS_WAF::get_stats();
    $recent   = SWPS_WAF::get_recent_blocks(20);
    ?>

    <!-- Status Bar -->
    <div class="swps-status-bar <?php echo $enabled ? 'swps-status-active' : 'swps-status-inactive'; ?>">
        <span class="dashicons <?php echo $enabled ? 'dashicons-shield' : 'dashicons-shield-alt'; ?>"></span>
        WAF is <strong><?php echo $enabled ? strtoupper($mode) . ' MODE' : 'DISABLED'; ?></strong>
        <?php if ($enabled && $mode === 'learn'): ?>
        &nbsp;— Learning mode: threats are logged but not blocked
        <?php endif; ?>
    </div>

    <!-- Attack Stats Grid -->
    <div class="swps-stats-grid">
        <div class="swps-stat-card">
            <div class="swps-stat-num"><?php echo number_format($stats['total'] ?? 0); ?></div>
            <div class="swps-stat-label">Total Blocked</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-red"><?php echo number_format($stats['sqli'] ?? 0); ?></div>
            <div class="swps-stat-label">SQL Injection</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-orange"><?php echo number_format($stats['xss'] ?? 0); ?></div>
            <div class="swps-stat-label">XSS Attempts</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-yellow"><?php echo number_format($stats['lfi'] ?? 0); ?></div>
            <div class="swps-stat-label">Path Traversal</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-blue"><?php echo number_format(($stats['bad_bot'] ?? 0) + ($stats['rfi'] ?? 0)); ?></div>
            <div class="swps-stat-label">Bots / RFI</div>
        </div>
    </div>

    <!-- Settings Form -->
    <div class="swps-card">
        <h2>WAF Settings</h2>
        <form method="post" action="options.php">
            <?php settings_fields('swps_settings_group'); ?>
            <table class="form-table swps-form-table">
                <tr>
                    <th>WAF Status</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_settings[waf_enabled]" value="1" <?php checked($enabled); ?>>
                            <span class="swps-slider"></span>
                        </label>
                        Enable Web Application Firewall
                    </td>
                </tr>
                <tr>
                    <th>Mode</th>
                    <td>
                        <select name="swps_settings[waf_mode]" class="swps-select">
                            <option value="block"  <?php selected($mode, 'block'); ?>>Block Mode — stop attacks right away (recommended)</option>
                            <option value="learn"  <?php selected($mode, 'learn'); ?>>Learning Mode — only record attacks, don't block (for testing)</option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <th>Protection Rules</th>
                    <td>
                        <?php
                        $rules = array(
                            'waf_sqli'    => 'Database attacks (SQL Injection) — stops attempts to steal or damage your data',
                            'waf_xss'     => 'Malicious scripts (XSS) — stops bad code meant to hijack visitor browsers',
                            'waf_lfi'     => 'File-snooping (Path Traversal) — stops attempts to read private server files',
                            'waf_rfi'     => 'Remote file loading (RFI) — stops attempts to run outside malicious files',
                            'waf_bad_bot' => 'Bad bots & fake crawlers — blocks known hacking tools and scanners',
                        );
                        foreach ($rules as $key => $label):
                            $checked = empty($settings[$key]) ? false : true;
                            if (!isset($settings[$key])) $checked = true; // default on
                        ?>
                        <label style="display:block;margin-bottom:6px">
                            <input type="checkbox" name="swps_settings[<?php echo $key; ?>]" value="1" <?php checked($checked); ?>>
                            <?php echo esc_html($label); ?>
                        </label>
                        <?php endforeach; ?>
                    </td>
                </tr>
                <tr>
                    <th>Auto-block Threshold</th>
                    <td>
                        <input type="number" name="swps_settings[waf_auto_block_threshold]" value="<?php echo esc_attr($settings['waf_auto_block_threshold'] ?? 5); ?>" min="1" max="50" class="small-text">
                        <span class="description">If the same visitor triggers this many attacks within 10 minutes, their IP address is automatically blocked.</span>
                    </td>
                </tr>
            </table>
            <p class="description">Looking for "Whitelist IPs" (trusted IPs that skip every check)? That now lives on the <a href="<?php echo esc_url( admin_url('admin.php?page=swps-access&tab=ipblocker') ); ?>">IP Blocker</a> page, alongside the rest of IP-level blocking/unblocking.</p>
            <?php submit_button('Save WAF Settings'); ?>
        </form>
    </div>

    <!-- Recent Blocked Requests -->
    <?php if (!empty($recent)): ?>
    <div class="swps-card">
        <h2>Recent Blocked Requests</h2>
        <table class="swps-table widefat striped">
            <thead><tr><th>Time</th><th>IP</th><th>Attack Type</th><th>URI</th><th>Action</th></tr></thead>
            <tbody>
            <?php foreach ($recent as $r): ?>
            <tr>
                <td><?php echo esc_html(date_i18n('M j H:i:s', strtotime($r->created_at ?? 'now'))); ?></td>
                <td><code><?php echo esc_html($r->ip_address ?? ''); ?></code></td>
                <td><span class="swps-badge swps-badge-critical"><?php echo esc_html(strtoupper($r->event_type ?? '')); ?></span></td>
                <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis"><code><?php echo esc_html(substr($r->description ?? '', 0, 80)); ?></code></td>
                <td>
                    <button class="button button-small swps-block-btn" data-ip="<?php echo esc_attr($r->ip_address ?? ''); ?>">Block IP</button>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>
