<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-media-code"></span> File Integrity Monitor</h1>
    <p class="description" style="margin:-8px 0 16px;max-width:760px">
        This takes a "fingerprint" of all your files, then alerts you if any file is changed, added or
        deleted. It's one of the best ways to catch a hack early. It sets up its starting fingerprint
        (baseline) automatically — you don't need to do anything.
    </p>

    <?php
    $stats    = SWPS_File_Integrity::get_stats();
    $changes  = $stats['changes'] ?? array();
    $critical = array_filter($changes, fn($c) => $c['severity'] === 'critical');
    $settings = get_option('swps_settings', array());
    $q_log    = SWPS_File_Integrity::get_quarantine_log();
    ?>

    <?php if (!empty($critical)): ?>
    <div class="swps-notice swps-notice-critical">
        <strong><?php echo count($critical); ?> critical file change(s) detected!</strong> Core WordPress files have been modified. Investigate immediately.
    </div>
    <?php endif; ?>

    <!-- Stats -->
    <div class="swps-stats-grid">
        <div class="swps-stat-card">
            <div class="swps-stat-num"><?php echo number_format($stats['baseline_files']); ?></div>
            <div class="swps-stat-label">Files Monitored</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-red"><?php echo count($critical); ?></div>
            <div class="swps-stat-label">Critical Changes</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-orange"><?php echo count($changes) - count($critical); ?></div>
            <div class="swps-stat-label">Warnings</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num"><?php echo $stats['baseline_created'] ? human_time_diff($stats['baseline_created']) : 'None'; ?></div>
            <div class="swps-stat-label">Baseline Age</div>
        </div>
    </div>

    <!-- Actions -->
    <div class="swps-card">
        <div class="swps-card-header">
            <h2>File Integrity Scan</h2>
            <div class="swps-card-actions">
                <button id="swps-fim-baseline" class="button">Create New Baseline</button>
                <button id="swps-fim-scan" class="button button-primary">Scan Now</button>
            </div>
        </div>
        <div id="swps-fim-result" style="padding:0 0 8px"></div>

        <table class="form-table swps-form-table">
            <tr>
                <th>Enable File Monitor</th>
                <td>
                    <label class="swps-toggle">
                        <input type="checkbox" id="swps-fim-toggle" <?php checked(!empty($settings['fim_enabled'])); ?>>
                        <span class="swps-slider"></span>
                    </label> Auto-scan hourly for file changes
                </td>
            </tr>
        </table>
        <p class="description" style="margin:4px 0 8px">
            <?php if ($stats['last_scan']): ?>
            Last scan: <?php echo human_time_diff($stats['last_scan']); ?> ago
            <?php else: ?>
            No scan run yet. Create a baseline first, then run a scan.
            <?php endif; ?>
        </p>
    </div>

    <!-- Changes -->
    <?php if (!empty($changes)): ?>
    <div class="swps-card">
        <h2>File Changes Since Baseline</h2>
        <table class="swps-table widefat striped">
            <thead><tr><th>File</th><th>Change Type</th><th>Severity</th><th>Modified</th><th>Actions</th></tr></thead>
            <tbody>
            <?php foreach ($changes as $change): ?>
            <tr class="<?php echo $change['severity'] === 'critical' ? 'swps-row-critical' : ($change['severity'] === 'warning' ? 'swps-row-warning' : ''); ?>">
                <td style="word-break:break-all"><code><?php echo esc_html($change['file']); ?></code></td>
                <td>
                    <span class="swps-badge <?php echo $change['type'] === 'modified' ? 'swps-badge-warning' : ($change['type'] === 'added' ? 'swps-badge-critical' : 'swps-badge-ok'); ?>">
                        <?php echo esc_html(strtoupper($change['type'])); ?>
                    </span>
                </td>
                <td>
                    <span class="swps-badge <?php echo $change['severity'] === 'critical' ? 'swps-badge-critical' : 'swps-badge-warning'; ?>">
                        <?php echo esc_html(strtoupper($change['severity'])); ?>
                    </span>
                </td>
                <td class="swps-muted"><?php echo esc_html($change['mtime'] ?? '—'); ?></td>
                <td>
                    <?php if ($change['type'] !== 'deleted'): ?>
                    <button class="button button-small swps-quarantine-btn" data-file="<?php echo esc_attr($change['file']); ?>">Quarantine</button>
                    <?php endif; ?>
                    <button class="button button-small swps-fim-ignore-btn" data-file="<?php echo esc_attr($change['file']); ?>">Ignore</button>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php elseif ($stats['baseline_files'] > 0 && $stats['last_scan']): ?>
    <div class="swps-card">
        <div class="swps-notice swps-notice-ok">All <?php echo number_format($stats['baseline_files']); ?> monitored files match the baseline. No changes detected.</div>
    </div>
    <?php endif; ?>

    <!-- Quarantine Log -->
    <?php if (!empty($q_log)): ?>
    <div class="swps-card">
        <h2>Quarantine Log</h2>
        <table class="swps-table widefat striped">
            <thead><tr><th>Original File</th><th>Quarantined</th><th>Restore</th></tr></thead>
            <tbody>
            <?php foreach (array_reverse($q_log) as $q): ?>
            <tr>
                <td><code><?php echo esc_html($q['original']); ?></code></td>
                <td><?php echo date_i18n('M j Y H:i', $q['time']); ?></td>
                <td>
                    <button class="button button-small swps-restore-btn"
                        data-original="<?php echo esc_attr($q['original']); ?>"
                        data-quarantine="<?php echo esc_attr($q['quarantine']); ?>">Restore</button>
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
    $('#swps-fim-baseline').on('click', function() {
        if (!confirm('Create new baseline? This will reset all current change tracking.')) return;
        var $btn = $(this).prop('disabled', true).text('Creating...');
        $.post(ajaxurl, {action:'swps_fim_baseline', nonce:swps_vars.nonce}, function(res) {
            $btn.prop('disabled',false).text('Create New Baseline');
            if (res.success) { $('#swps-fim-result').html('<div class="swps-notice swps-notice-ok">'+res.data.message+'</div>'); setTimeout(()=>location.reload(),1500); }
            else { $('#swps-fim-result').html('<div class="swps-notice swps-notice-error">'+(res.data||'Failed')+'</div>'); }
        }).fail(function(){ $btn.prop('disabled',false).text('Create New Baseline'); $('#swps-fim-result').html('<div class="swps-notice swps-notice-error">Request failed (server/network error).</div>'); });
    });
    $('#swps-fim-toggle').on('change', function() {
        var en = this.checked ? 1 : 0;
        var $t = $(this).prop('disabled', true);
        $.post(ajaxurl, {action:'swps_fim_toggle', nonce:swps_vars.nonce, enabled:en}, function(res) {
            $t.prop('disabled', false);
            $('#swps-fim-result').html('<div class="swps-notice swps-notice-ok">Auto-scan ' + (en ? 'enabled' : 'disabled') + '.</div>');
        }).fail(function(){ $t.prop('disabled', false).prop('checked', !en); });
    });
    $('#swps-fim-scan').on('click', function() {
        var $btn = $(this).prop('disabled',true).text('Scanning...');
        $.post(ajaxurl, {action:'swps_fim_scan', nonce:swps_vars.nonce}, function(res) {
            $btn.prop('disabled',false).text('Scan Now');
            if (res.success) location.reload();
            else { $('#swps-fim-result').html('<div class="swps-notice swps-notice-error">'+(res.data||'Scan failed')+'</div>'); }
        }).fail(function(){ $btn.prop('disabled',false).text('Scan Now'); $('#swps-fim-result').html('<div class="swps-notice swps-notice-error">Request failed (server/network error).</div>'); });
    });
    $('.swps-quarantine-btn').on('click', function() {
        if (!confirm('Move this file to quarantine?')) return;
        var $btn = $(this).prop('disabled', true).text('Quarantining...');
        var file = $btn.data('file');
        $.post(ajaxurl, {action:'swps_quarantine_file', nonce:swps_vars.nonce, file:file}, function(res) {
            if (res.success) location.reload();
            else { alert('Error: ' + res.data); $btn.prop('disabled', false).text('Quarantine'); }
        }).fail(function(){ alert('Request failed (server/network error).'); $btn.prop('disabled', false).text('Quarantine'); });
    });
    $('.swps-fim-ignore-btn').on('click', function() {
        var $btn = $(this).prop('disabled', true);
        var file = $btn.data('file');
        $.post(ajaxurl, {action:'swps_fim_ignore', nonce:swps_vars.nonce, file:file}, function(res) {
            if (res.success) location.reload();
            else $btn.prop('disabled', false);
        }).fail(function(){ $btn.prop('disabled', false); });
    });
    $('.swps-restore-btn').on('click', function() {
        if (!confirm('Restore this file from quarantine?')) return;
        var $btn = $(this).prop('disabled', true).text('Restoring...');
        $.post(ajaxurl, {action:'swps_fim_restore', nonce:swps_vars.nonce, original_path:$btn.data('original'), quarantine_path:$btn.data('quarantine')}, function(res) {
            if (res.success) location.reload();
            else { alert('Restore failed: ' + res.data); $btn.prop('disabled', false).text('Restore'); }
        }).fail(function(){ alert('Request failed (server/network error).'); $btn.prop('disabled', false).text('Restore'); });
    });
});
</script>
<?php
add_action('wp_ajax_swps_quarantine_file', function() {
    check_ajax_referer('swps_nonce','nonce');
    if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
    $file = sanitize_text_field($_POST['file'] ?? '');
    $ok   = SWPS_File_Integrity::quarantine_file($file);
    $ok ? wp_send_json_success('Quarantined.') : wp_send_json_error('Failed.');
});
?>
