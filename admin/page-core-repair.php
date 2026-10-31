<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-admin-tools"></span> Core Repair</h1>
    <p class="description" style="margin:-8px 0 16px;max-width:760px">
        This compares your WordPress core files with the official originals from WordPress.org.
        If a hacker has changed or added a core file, it's detected here — and you can restore the
        clean, original version in one click.
    </p>

    <?php
    $settings = get_option('swps_settings', array());
    $result   = get_option('swps_core_verify_result', null);
    $modified = $result['modified'] ?? array();
    $missing  = $result['missing']  ?? array();
    $total_issues = count($modified) + count($missing);
    ?>

    <?php if ($total_issues > 0): ?>
    <div class="swps-notice swps-notice-critical">
        <strong><?php echo $total_issues; ?> WordPress core file issue(s) detected.</strong>
        <?php echo count($modified); ?> modified, <?php echo count($missing); ?> missing.
        <button id="swps-repair-all" class="button button-primary" style="margin-left:12px">Repair All Now</button>
    </div>
    <?php elseif ($result): ?>
    <div class="swps-notice swps-notice-ok">All <?php echo number_format($result['total']); ?> core files verified clean. Last check: <?php echo human_time_diff($result['checked_at']); ?> ago.</div>
    <?php endif; ?>

    <!-- Stats -->
    <div class="swps-stats-grid">
        <div class="swps-stat-card">
            <div class="swps-stat-num"><?php echo $result ? number_format($result['total']) : '—'; ?></div>
            <div class="swps-stat-label">Core Files Checked</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-red"><?php echo count($modified); ?></div>
            <div class="swps-stat-label">Modified</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-orange"><?php echo count($missing); ?></div>
            <div class="swps-stat-label">Missing</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-green"><?php echo $result ? number_format($result['ok']) : '—'; ?></div>
            <div class="swps-stat-label">Healthy</div>
        </div>
    </div>

    <!-- Actions -->
    <div class="swps-card">
        <div class="swps-card-header">
            <h2>Verify & Repair</h2>
            <div class="swps-card-actions">
                <button id="swps-core-verify" class="button">Verify Core Files</button>
                <?php if ($total_issues > 0): ?>
                <button id="swps-repair-all-2" class="button button-primary">Repair All (<?php echo $total_issues; ?>)</button>
                <?php endif; ?>
            </div>
        </div>
        <div id="swps-core-result"></div>
        <p class="description" style="padding:8px 0 0">
            Fetches official checksums from <strong>api.wordpress.org</strong> and compares every core PHP file.
            Modified files are re-downloaded from WordPress SVN. A backup (<code>.swps_bak_*</code>) is created before overwriting.
            WordPress version: <strong><?php echo get_bloginfo('version'); ?></strong>
        </p>
    </div>

    <!-- Modified files -->
    <?php if (!empty($modified)): ?>
    <div class="swps-card">
        <h2>Modified Files</h2>
        <table class="swps-table widefat striped">
            <thead><tr><th>File</th><th>Action</th></tr></thead>
            <tbody>
            <?php foreach ($modified as $item): ?>
            <tr>
                <td><code><?php echo esc_html($item['file']); ?></code></td>
                <td>
                    <button class="button button-small swps-repair-single" data-file="<?php echo esc_attr($item['file']); ?>">Repair</button>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>

    <!-- Missing files -->
    <?php if (!empty($missing)): ?>
    <div class="swps-card">
        <h2>Missing Files</h2>
        <table class="swps-table widefat striped">
            <thead><tr><th>File</th><th>Action</th></tr></thead>
            <tbody>
            <?php foreach ($missing as $file): ?>
            <tr>
                <td><code><?php echo esc_html($file); ?></code></td>
                <td><button class="button button-small swps-repair-single" data-file="<?php echo esc_attr($file); ?>">Restore</button></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>

    <!-- Settings -->
    <div class="swps-card">
        <h2>Core Repair Settings</h2>
        <form method="post" action="options.php">
            <?php settings_fields('swps_settings_group'); ?>
            <table class="form-table swps-form-table">
                <tr>
                    <th>Enable Core Repair</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_settings[core_repair_enabled]" value="1" <?php checked(!empty($settings['core_repair_enabled'])); ?>>
                            <span class="swps-slider"></span>
                        </label> Verify core files daily and alert on changes
                    </td>
                </tr>
                <tr>
                    <th>Auto-Repair on Detection</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_settings[core_auto_repair]" value="1" <?php checked(!empty($settings['core_auto_repair'])); ?>>
                            <span class="swps-slider"></span>
                        </label> Automatically repair modified core files (backup created first)
                    </td>
                </tr>
            </table>
            <?php submit_button('Save Settings'); ?>
        </form>
    </div>
</div>

<script>
jQuery(document).ready(function($) {
    function doVerify() {
        var $btn = $('#swps-core-verify').prop('disabled',true).text('Verifying…');
        $.post(ajaxurl, {action:'swps_core_verify', nonce:swps_vars.nonce}, function(res) {
            $btn.prop('disabled',false).text('Verify Core Files');
            if (res.success) location.reload();
            else $('#swps-core-result').html('<div class="swps-notice swps-notice-critical">'+(res.data||'Error')+'</div>');
        });
    }
    function doRepair(file) {
        return $.post(ajaxurl, {action:'swps_core_repair', nonce:swps_vars.nonce, file:file});
    }
    $('#swps-core-verify').on('click', doVerify);
    $('#swps-repair-all, #swps-repair-all-2').on('click', function() {
        if (!confirm('Repair all modified/missing core files? Backups will be created.')) return;
        $(this).prop('disabled',true).text('Repairing…');
        doRepair('__all__').done(function(res) {
            if (res.success) {
                var d = res.data;
                $('#swps-core-result').html('<div class="swps-notice swps-notice-ok">Repaired: '+d.repaired+' | Failed: '+d.failed+'</div>');
                setTimeout(()=>location.reload(), 1500);
            }
        });
    });
    $('.swps-repair-single').on('click', function() {
        var $btn = $(this).prop('disabled',true).text('…');
        var file = $btn.data('file');
        doRepair(file).done(function(res) {
            $btn.prop('disabled',false).text(res.success ? '✓ Done' : '✗ Failed');
        });
    });
});
</script>
