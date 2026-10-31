<?php if ( ! defined('ABSPATH') ) exit; ?>
<?php $last_scan = SWPS_Scanner::get_last_scan(); ?>
<div class="wrap swps-wrap">
    <div class="swps-header">
        <span class="dashicons dashicons-search swps-logo-icon"></span>
        <div>
            <h1>Security Scanner</h1>
            <p>Scan your site's files for malware, backdoors and hidden hacking code.</p>
        </div>
    </div>

    <div class="swps-card">
        <div class="swps-card-header"><span class="dashicons dashicons-search"></span> Run Security Scan</div>
        <div class="swps-card-body">
            <p>Scans all the code files in your <code>wp-content</code> folder (plugins, themes and uploads) looking for malware and hacking code.</p>
            <p><strong>What it looks for:</strong> hidden/encoded malicious code, known hacker tools (webshells), code that lets attackers run commands, and secret backdoors.</p>
            <button id="swps-run-scan-btn" class="swps-btn swps-btn-primary">
                <span class="dashicons dashicons-search"></span> Start Full Scan
            </button>
            <div id="swps-scan-progress" style="display:none;margin-top:15px">
                <div class="swps-progress-bar"><div class="swps-progress-fill"></div></div>
                <p>Scanning files... please wait.</p>
            </div>
            <div id="swps-scan-result" style="margin-top:15px"></div>
        </div>
    </div>

    <?php if ($last_scan): ?>
    <div class="swps-card">
        <div class="swps-card-header">
            <span class="dashicons dashicons-clipboard"></span> Last Scan Results
            <small style="float:right"><?php echo esc_html($last_scan['scan_time']); ?></small>
        </div>
        <div class="swps-card-body">
            <div class="swps-stats-row swps-stats-small">
                <div class="swps-stat-card">
                    <div class="swps-stat-number"><?php echo intval($last_scan['scanned_files']); ?></div>
                    <div class="swps-stat-label">Files Scanned</div>
                </div>
                <div class="swps-stat-card swps-stat-<?php echo count($last_scan['threats']) > 0 ? 'critical' : 'ok'; ?>">
                    <div class="swps-stat-number"><?php echo count($last_scan['threats']); ?></div>
                    <div class="swps-stat-label">Threats Found</div>
                </div>
            </div>

            <?php if (empty($last_scan['threats'])): ?>
                <div class="swps-alert-inline swps-ok">✓ No malware or suspicious files detected in last scan.</div>
            <?php else: ?>
                <div class="swps-alert-inline swps-critical">⚠️ <?php echo count($last_scan['threats']); ?> suspicious files found! Review and clean immediately.</div>
                <table class="swps-table swps-table-striped" style="margin-top:15px">
                    <thead><tr><th>File Path</th><th>Issues Found</th><th>File Size</th><th>Last Modified</th></tr></thead>
                    <tbody>
                    <?php foreach ($last_scan['threats'] as $threat): ?>
                        <tr class="swps-row-critical">
                            <td><code><?php echo esc_html($threat['file']); ?></code></td>
                            <td>
                                <?php foreach ($threat['threats'] as $t): ?>
                                    <span class="swps-badge swps-badge-danger"><?php echo esc_html($t); ?></span><br>
                                <?php endforeach; ?>
                            </td>
                            <td><?php echo number_format($threat['size'] / 1024, 1); ?> KB</td>
                            <td><?php echo esc_html($threat['modified']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>

    <!-- Core File Monitor -->
    <?php $core_changes = SWPS_Scanner::check_core_files(); ?>
    <?php if (!empty($core_changes)): ?>
    <div class="swps-card">
        <div class="swps-card-header swps-header-warning">
            <span class="dashicons dashicons-warning"></span> Core File Changes (Last 7 Days)
        </div>
        <div class="swps-card-body">
            <div class="swps-alert-inline swps-critical">⚠️ <?php echo count($core_changes); ?> WordPress core files were modified in the last 7 days. This could indicate tampering.</div>
            <table class="swps-table" style="margin-top:10px">
                <thead><tr><th>File</th><th>Modified</th></tr></thead>
                <tbody>
                <?php foreach (array_slice($core_changes, 0, 20) as $cf): ?>
                    <tr><td><code><?php echo esc_html($cf['file']); ?></code></td><td><?php echo esc_html($cf['modified']); ?></td></tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <?php endif; ?>
    <?php endif; ?>
</div>
