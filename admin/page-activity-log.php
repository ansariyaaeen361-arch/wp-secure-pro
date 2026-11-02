<?php if ( ! defined('ABSPATH') ) exit; ?>
<?php
$severity = sanitize_text_field( $_GET['severity'] ?? '' );
$event    = sanitize_text_field( $_GET['event'] ?? '' );
$paged    = max(1, intval($_GET['paged'] ?? 1));
$per_page = 30;
$logs     = SWPS_Activity_Log::get_logs(array('limit' => $per_page, 'offset' => ($paged-1)*$per_page, 'severity' => $severity, 'event' => $event));
$counts   = SWPS_Activity_Log::get_counts_by_severity();
?>
<div class="wrap swps-wrap">
    <div class="swps-header">
        <span class="dashicons dashicons-list-view swps-logo-icon"></span>
        <div>
            <h1>Activity Log</h1>
            <p>A running record of security events on your site — logins, blocks, scans and changes.</p>
        </div>
    </div>

    <div class="swps-stats-row swps-stats-small">
        <div class="swps-stat-card swps-stat-critical"><div class="swps-stat-number"><?php echo $counts['critical']; ?></div><div class="swps-stat-label">Critical</div></div>
        <div class="swps-stat-card swps-stat-warning"><div class="swps-stat-number"><?php echo $counts['warning']; ?></div><div class="swps-stat-label">Warnings</div></div>
        <div class="swps-stat-card swps-stat-info"><div class="swps-stat-number"><?php echo $counts['info']; ?></div><div class="swps-stat-label">Info</div></div>
    </div>

    <div class="swps-card">
        <div class="swps-card-header">
            <span class="dashicons dashicons-filter"></span> Filter
            <form method="get" style="display:inline;float:right;">
                <input type="hidden" name="page" value="swps-monitoring">
                <input type="hidden" name="tab" value="activity">
                <select name="severity" onchange="this.form.submit()">
                    <option value="">All Severities</option>
                    <option value="critical" <?php selected($severity,'critical'); ?>>Critical</option>
                    <option value="warning"  <?php selected($severity,'warning');  ?>>Warning</option>
                    <option value="info"     <?php selected($severity,'info');     ?>>Info</option>
                </select>
                <button id="swps-clear-log-btn" class="swps-btn swps-btn-danger" type="button" style="margin-left:10px">Clear All Logs</button>
            </form>
        </div>
        <div class="swps-card-body">
            <table class="swps-table swps-table-striped">
                <thead>
                    <tr>
                        <th>ID</th><th>Time</th><th>Event</th><th>Severity</th>
                        <th>User</th><th>IP Address</th><th>Description</th>
                    </tr>
                </thead>
                <tbody>
                <?php if (empty($logs)): ?>
                    <tr><td colspan="7" class="swps-empty">No log entries found.</td></tr>
                <?php else: ?>
                    <?php foreach ($logs as $log): ?>
                    <tr class="swps-row-<?php echo esc_attr($log->severity); ?>">
                        <td>#<?php echo intval($log->id); ?></td>
                        <td><small><?php echo esc_html($log->created_at); ?></small></td>
                        <td><code><?php echo esc_html($log->event_type); ?></code></td>
                        <td><span class="swps-badge swps-badge-<?php echo esc_attr($log->severity); ?>"><?php echo esc_html($log->severity); ?></span></td>
                        <td><?php echo esc_html($log->username ?: '-'); ?></td>
                        <td>
                            <code><?php echo esc_html($log->ip_address ?: '-'); ?></code>
                            <?php if ($log->ip_address): ?>
                                <button class="swps-btn-sm swps-block-btn" data-ip="<?php echo esc_attr($log->ip_address); ?>">Block</button>
                            <?php endif; ?>
                        </td>
                        <td><?php echo esc_html($log->description); ?></td>
                    </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>

            <?php if ($paged > 1 || count($logs) === $per_page): ?>
            <div class="swps-pagination">
                <?php if ($paged > 1): ?>
                    <a href="?page=swps-monitoring&tab=activity&paged=<?php echo $paged-1; ?>&severity=<?php echo $severity; ?>" class="swps-btn">← Previous</a>
                <?php endif; ?>
                <span>Page <?php echo $paged; ?></span>
                <?php if (count($logs) === $per_page): ?>
                    <a href="?page=swps-monitoring&tab=activity&paged=<?php echo $paged+1; ?>&severity=<?php echo $severity; ?>" class="swps-btn">Next →</a>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </div>
    </div>
</div>
