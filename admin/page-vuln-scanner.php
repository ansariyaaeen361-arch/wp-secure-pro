<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-search"></span> Vulnerability Scanner</h1>
    <p class="description" style="margin:-8px 0 16px;max-width:760px">
        Checks your installed plugins, themes and WordPress version against a database of known security
        holes — so you know exactly what needs updating to stay safe.
    </p>

    <?php
    $settings  = get_option('swps_settings', array());
    $api_key   = $settings['wpscan_api_key'] ?? '';
    $last_scan = get_option('swps_last_vuln_scan', array());
    $api_status = $api_key ? SWPS_Vuln_Scanner::get_api_status($api_key) : array('valid' => false);
    ?>

    <!-- Scan Action Card -->
    <div class="swps-card">
        <div class="swps-card-header">
            <div>
                <h2>WordPress Vulnerability Scanner</h2>
                <p class="description">Checks your WordPress core, plugins, and themes against the WPScan vulnerability database.</p>
            </div>
            <div class="swps-card-actions">
                <?php if (!empty($last_scan['scanned_at'])): ?>
                <span class="swps-muted">Last scan: <?php echo human_time_diff($last_scan['scanned_at']); ?> ago</span>
                <?php endif; ?>
                <button id="swps-run-vuln-scan" class="button button-primary">
                    <span class="dashicons dashicons-update" style="margin-top:3px"></span> Run Scan Now
                </button>
            </div>
        </div>

        <?php if (!empty($last_scan['total_vulns'])): ?>
        <div class="swps-notice swps-notice-critical">
            <strong>Critical:</strong> <?php echo intval($last_scan['total_vulns']); ?> vulnerabilities found! Update your components immediately.
        </div>
        <?php elseif (isset($last_scan['total_vulns']) && $last_scan['total_vulns'] === 0): ?>
        <div class="swps-notice swps-notice-ok">No vulnerabilities found in last scan.</div>
        <?php endif; ?>

        <!-- API Key Status -->
        <div class="swps-api-status" style="margin-top:16px;padding:12px;background:#f9f9f9;border-radius:6px">
            <strong>WPScan API:</strong>
            <?php if ($api_key && !empty($api_status['valid'])): ?>
            <span class="swps-badge swps-badge-ok">Connected</span>
            Plan: <?php echo esc_html($api_status['plan'] ?? 'Unknown'); ?> |
            Requests remaining: <?php echo intval($api_status['requests_remaining'] ?? 0); ?>
            <?php elseif ($api_key): ?>
            <span class="swps-badge swps-badge-critical">Invalid Key</span>
            <?php else: ?>
            <span class="swps-badge swps-badge-warning">No API Key</span> — running in <em>no-API mode</em> (version checks only, no CVE details)
            <br><small>Get a free key at <a href="https://wpscan.com/register" target="_blank">wpscan.com/register</a> (25 free req/day)</small>
            <?php endif; ?>
        </div>
    </div>

    <!-- WordPress Core -->
    <?php if (!empty($last_scan['wordpress'])): $wp = $last_scan['wordpress']; ?>
    <div class="swps-card">
        <h2>WordPress Core — v<?php echo esc_html($wp['version']); ?>
            <span class="swps-badge <?php echo $wp['status'] === 'ok' ? 'swps-badge-ok' : 'swps-badge-critical'; ?>" style="margin-left:10px">
                <?php echo $wp['status'] === 'ok' ? 'No Vulnerabilities' : count($wp['vulnerabilities']) . ' Vulnerabilities'; ?>
            </span>
        </h2>
        <?php if (!empty($wp['vulnerabilities'])): ?>
        <?php foreach ($wp['vulnerabilities'] as $v): ?>
        <div class="swps-vuln-item">
            <strong><?php echo esc_html($v['title']); ?></strong>
            <?php if ($v['cvss_score']): ?><span class="swps-badge swps-badge-critical">CVSS <?php echo $v['cvss_score']; ?></span><?php endif; ?>
            <?php if ($v['cve']): ?><code>CVE-<?php echo esc_html($v['cve']); ?></code><?php endif; ?>
            <?php if ($v['fixed_in']): ?><span class="swps-muted">Fixed in <?php echo esc_html($v['fixed_in']); ?></span><?php endif; ?>
        </div>
        <?php endforeach; ?>
        <?php endif; ?>
    </div>
    <?php endif; ?>

    <!-- Plugins -->
    <?php
    $vuln_plugins = array_filter($last_scan['plugins'] ?? array(), fn($p) => !empty($p['vulnerabilities']));
    $ok_plugins   = array_filter($last_scan['plugins'] ?? array(), fn($p) => empty($p['vulnerabilities']));
    ?>
    <?php if (!empty($last_scan['plugins'])): ?>
    <div class="swps-card">
        <h2>Plugins
            <?php if (!empty($vuln_plugins)): ?>
            <span class="swps-badge swps-badge-critical"><?php echo count($vuln_plugins); ?> Vulnerable</span>
            <?php else: ?>
            <span class="swps-badge swps-badge-ok">All Clean</span>
            <?php endif; ?>
        </h2>
        <?php foreach ($vuln_plugins as $p): ?>
        <div class="swps-vuln-plugin">
            <h3><?php echo esc_html($p['name']); ?> <span class="swps-muted">v<?php echo esc_html($p['version']); ?></span></h3>
            <?php foreach ($p['vulnerabilities'] as $v): ?>
            <div class="swps-vuln-item">
                <strong><?php echo esc_html($v['title']); ?></strong>
                <?php if ($v['cvss_score']): ?><span class="swps-badge swps-badge-critical">CVSS <?php echo $v['cvss_score']; ?></span><?php endif; ?>
                <?php if ($v['fixed_in']): ?><span class="swps-badge swps-badge-warning">Fix: update to <?php echo esc_html($v['fixed_in']); ?></span><?php endif; ?>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endforeach; ?>
        <?php if (empty($vuln_plugins)): ?>
        <p class="swps-ok-msg"><span class="dashicons dashicons-yes-alt"></span> All <?php echo count($ok_plugins); ?> installed plugins are clean.</p>
        <?php endif; ?>
    </div>
    <?php endif; ?>

    <!-- Settings -->
    <div class="swps-card">
        <h2>Scanner Settings</h2>
        <form method="post" action="options.php">
            <?php settings_fields('swps_settings_group'); ?>
            <table class="form-table swps-form-table">
                <tr>
                    <th>WPScan API Key</th>
                    <td>
                        <input type="text" name="swps_settings[wpscan_api_key]" value="<?php echo esc_attr($api_key); ?>" class="regular-text" placeholder="Paste your WPScan API key here">
                        <p class="description">Free at <a href="https://wpscan.com/register" target="_blank">wpscan.com/register</a> — 25 requests/day free.</p>
                    </td>
                </tr>
                <tr>
                    <th>Auto-scan Daily</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_settings[vuln_auto_scan]" value="1" <?php checked(!empty($settings['vuln_auto_scan'])); ?>>
                            <span class="swps-slider"></span>
                        </label> Run vulnerability scan automatically every 24 hours
                    </td>
                </tr>
            </table>
            <?php submit_button('Save Scanner Settings'); ?>
        </form>
    </div>
</div>

<script>
jQuery(document).ready(function($) {
    $('#swps-run-vuln-scan').on('click', function() {
        var $btn = $(this).prop('disabled', true).html('<span class="dashicons dashicons-update swps-spin"></span> Scanning...');
        $.post(ajaxurl, { action: 'swps_run_vuln_scan', nonce: swps_vars.nonce }, function(res) {
            if (res.success) location.reload();
            else {
                alert('Scan failed: ' + (res.data || 'Unknown error'));
                $btn.prop('disabled', false).html('<span class="dashicons dashicons-update"></span> Run Scan Now');
            }
        });
    });
});
</script>
