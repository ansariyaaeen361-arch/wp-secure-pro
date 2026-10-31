<?php if ( ! defined('ABSPATH') ) exit; ?>
<?php
$results   = get_option(SWPS_Full_Scan::RESULT_OPT, array());
$skipped   = get_option(SWPS_Full_Scan::SKIPPED_OPT, array());
$whitelist = get_option(SWPS_Full_Scan::WHITELIST_OPT, array());
$steps     = SWPS_Full_Scan::get_steps();
$score_data= SWPS_Full_Scan::calculate_score($results, $skipped, $whitelist);
$summary   = SWPS_Full_Scan::get_summary($results);
$history   = SWPS_Full_Scan::get_history();
$settings  = get_option('swps_settings', array());
$has_scan  = !empty($results);
?>

<style>
/* ── Scoped to plugin wrapper only — prevents theme/plugin CSS conflicts ── */
#swps-fs-page *{box-sizing:border-box}
#swps-fs-page{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,sans-serif!important;color:#1e293b!important;background:transparent!important}
#swps-fs-page h1,#swps-fs-page h2,#swps-fs-page h3{color:#1e293b!important;margin:0!important}
#swps-fs-page p{margin:0!important}

/* Cards */
#swps-fs-page .fs-card{background:#ffffff!important;border:1px solid #e2e8f0!important;border-radius:10px!important;overflow:hidden!important;margin-bottom:18px!important;box-shadow:0 1px 3px rgba(0,0,0,.06)!important}
#swps-fs-page .fs-card-head{background:#f8fafc!important;border-bottom:1px solid #e2e8f0!important;padding:14px 20px!important;display:flex!important;align-items:center!important;gap:10px!important}
#swps-fs-page .fs-card-head h2{font-size:14px!important;font-weight:700!important;color:#1e293b!important}
#swps-fs-page .fs-card-body{padding:20px!important}

/* Score section */
#swps-fs-page .fs-score-wrap{background:#ffffff!important;border:1px solid #e2e8f0!important;border-radius:10px!important;padding:24px 28px!important;margin-bottom:18px!important;display:flex!important;align-items:center!important;gap:24px!important;flex-wrap:wrap!important;box-shadow:0 1px 3px rgba(0,0,0,.06)!important}

/* Progress bar */
#swps-fs-page .fs-progress-bg{background:#f1f5f9!important;border-radius:8px!important;height:10px!important;overflow:hidden!important;margin:10px 0 18px!important}
#swps-fs-page .fs-progress-fill{height:100%!important;border-radius:8px!important;background:linear-gradient(90deg,#3b82f6,#6366f1)!important;transition:width .4s ease!important;width:0%}

/* Step grid */
#swps-fs-page .fs-step-grid{display:grid!important;grid-template-columns:repeat(auto-fill,minmax(185px,1fr))!important;gap:8px!important}
#swps-fs-page .fs-step-item{display:flex!important;align-items:center!important;gap:8px!important;padding:9px 12px!important;background:#f8fafc!important;border:1px solid #e2e8f0!important;border-radius:7px!important}
#swps-fs-page .fs-step-item span.label{font-size:12px!important;flex:1!important;color:#475569!important;font-weight:500!important}

/* Issue rows */
#swps-fs-page .fs-issue{display:flex!important;align-items:flex-start!important;gap:12px!important;padding:13px 20px!important;border-bottom:1px solid #f1f5f9!important;background:#fff!important}
#swps-fs-page .fs-issue:last-child{border-bottom:none!important}
#swps-fs-page .fs-badge{display:inline-flex!important;align-items:center!important;gap:4px!important;font-size:11px!important;font-weight:700!important;padding:3px 9px!important;border-radius:4px!important;color:#fff!important;white-space:nowrap!important;flex-shrink:0!important;margin-top:1px!important}
#swps-fs-page .fs-badge-critical{background:#dc2626!important}
#swps-fs-page .fs-badge-warning{background:#d97706!important}
#swps-fs-page .fs-badge-skip{background:#6b7280!important}
#swps-fs-page .fs-badge-wl{background:#64748b!important}
#swps-fs-page .fs-issue-title{font-size:13px!important;font-weight:600!important;color:#1e293b!important;margin-bottom:3px!important}
#swps-fs-page .fs-issue-detail{font-size:11px!important;color:#64748b!important;word-break:break-all!important}

/* Buttons */
#swps-fs-page .fs-btn{display:inline-flex!important;align-items:center!important;gap:5px!important;padding:6px 14px!important;border-radius:6px!important;font-size:12px!important;font-weight:600!important;cursor:pointer!important;border:1px solid transparent!important;line-height:1.4!important;text-decoration:none!important}
#swps-fs-page .fs-btn-primary{background:#2563eb!important;color:#fff!important;border-color:#2563eb!important}
#swps-fs-page .fs-btn-primary:hover{background:#1d4ed8!important}
#swps-fs-page .fs-btn-red{background:#dc2626!important;color:#fff!important;border-color:#dc2626!important}
#swps-fs-page .fs-btn-red:hover{background:#b91c1c!important}
#swps-fs-page .fs-btn-outline{background:#fff!important;color:#374151!important;border-color:#d1d5db!important}
#swps-fs-page .fs-btn-outline:hover{background:#f9fafb!important;color:#1e293b!important}
#swps-fs-page .fs-btn-danger{background:#fff!important;color:#dc2626!important;border-color:#fca5a5!important}
#swps-fs-page .fs-btn-danger:hover{background:#fef2f2!important}
#swps-fs-page .fs-btn-fix{background:#2563eb!important;color:#fff!important;border-color:#2563eb!important;font-size:11px!important;padding:4px 10px!important}
#swps-fs-page .fs-btn-sm{font-size:11px!important;padding:4px 10px!important}

/* Form elements */
#swps-fs-page input[type=checkbox]{width:15px!important;height:15px!important;cursor:pointer!important;margin:0!important}
#swps-fs-page select{width:100%!important;padding:7px 10px!important;border:1px solid #d1d5db!important;border-radius:6px!important;font-size:13px!important;color:#374151!important;background:#fff!important}
#swps-fs-page label{cursor:pointer!important;color:#374151!important}
#swps-fs-page .fs-submit{width:100%!important;margin-top:14px!important;padding:8px!important;font-size:13px!important;background:#f8fafc!important;border:1px solid #e2e8f0!important;border-radius:6px!important;font-weight:600!important;color:#374151!important;cursor:pointer!important}
#swps-fs-page .fs-submit:hover{background:#f1f5f9!important}

/* Table */
#swps-fs-page .fs-table{width:100%!important;border-collapse:collapse!important;font-size:13px!important}
#swps-fs-page .fs-table th{padding:10px 16px!important;text-align:left!important;color:#64748b!important;font-weight:600!important;font-size:11px!important;text-transform:uppercase!important;letter-spacing:.5px!important;border-bottom:2px solid #e2e8f0!important;background:#f8fafc!important}
#swps-fs-page .fs-table td{padding:10px 16px!important;border-bottom:1px solid #f1f5f9!important;color:#374151!important;vertical-align:middle!important}
#swps-fs-page .fs-table tr:last-child td{border-bottom:none!important}
#swps-fs-page .fs-table tr:hover td{background:#fafafa!important}

/* Chips */
#swps-fs-page .fs-chip{display:inline-block!important;padding:2px 8px!important;border-radius:4px!important;font-size:11px!important;font-weight:600!important}
#swps-fs-page .fs-chip-ok{background:#dcfce7!important;color:#166534!important}
#swps-fs-page .fs-chip-err{background:#fef2f2!important;color:#dc2626!important}
#swps-fs-page .fs-chip-gray{background:#f1f5f9!important;color:#64748b!important}

/* Dashicon sizes in plugin context */
#swps-fs-page .dashicons{font-size:16px!important;width:16px!important;height:16px!important;vertical-align:middle!important}
#swps-fs-page .dashicons-lg{font-size:20px!important;width:20px!important;height:20px!important}
#swps-fs-page .dashicons-xl{font-size:28px!important;width:28px!important;height:28px!important}

/* All-clear box */
#swps-fs-page .fs-allclear{background:#f0fdf4!important;border:1px solid #86efac!important;border-radius:10px!important;padding:36px!important;text-align:center!important;margin-bottom:18px!important}

/* Toast */
#swps-toast{position:fixed!important;bottom:28px!important;right:28px!important;padding:12px 18px!important;border-radius:8px!important;font-size:13px!important;font-weight:600!important;color:#fff!important;box-shadow:0 8px 28px rgba(0,0,0,.18)!important;z-index:999999!important;opacity:0!important;transform:translateY(16px)!important;transition:all .3s ease!important;pointer-events:none!important;max-width:340px!important}

/* Modal */
#swps-fixall-modal{display:none;position:fixed;inset:0;background:rgba(15,23,42,.55);z-index:999998;align-items:center;justify-content:center}
#swps-fixall-modal .modal-box{background:#fff;border-radius:12px;width:500px;max-width:90vw;max-height:80vh;overflow:hidden;display:flex;flex-direction:column;box-shadow:0 24px 64px rgba(0,0,0,.2)}

/* Grid layout */
#swps-fs-page .fs-2col{display:grid!important;grid-template-columns:1fr 1fr!important;gap:16px!important;margin-bottom:18px!important}
@media(max-width:700px){#swps-fs-page .fs-2col{grid-template-columns:1fr!important}}

/* Section header color accents */
#swps-fs-page .fs-head-red .fs-card-head{border-left:4px solid #dc2626!important}
#swps-fs-page .fs-head-yellow .fs-card-head{border-left:4px solid #d97706!important}
#swps-fs-page .fs-head-blue .fs-card-head{border-left:4px solid #2563eb!important}
</style>

<div id="swps-fs-page">

<!-- ── PAGE HEADER ── -->
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:10px">
    <div style="display:flex;align-items:center;gap:10px">
        <span class="dashicons dashicons-search dashicons-xl" style="color:#2563eb;font-size:28px;width:28px;height:28px"></span>
        <div>
            <h1 style="font-size:20px;font-weight:800;color:#1e293b;margin:0">Full Site Scan</h1>
            <p style="font-size:12px;color:#64748b;margin:2px 0 0">Deep security audit — malware, core integrity, users, headers &amp; more</p>
        </div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button id="btn-start-scan" class="fs-btn fs-btn-primary">
            <span class="dashicons dashicons-search"></span> Start Full Scan
        </button>
        <?php if ($has_scan): ?>
        <button id="btn-export-report" class="fs-btn fs-btn-outline">
            <span class="dashicons dashicons-download"></span> Export Report
        </button>
        <button id="btn-email-report" class="fs-btn fs-btn-outline">
            <span class="dashicons dashicons-email-alt"></span> Email Report
        </button>
        <button id="btn-clear-scan" class="fs-btn fs-btn-danger">
            <span class="dashicons dashicons-trash"></span> Clear
        </button>
        <?php endif; ?>
    </div>
</div>

<!-- ── SECURITY SCORE ── -->
<?php if ($has_scan):
    $s     = $score_data['score'];
    $color = $score_data['color'];
    $r     = 44; $circ = round(2*M_PI*$r,1);
    $dash  = round($circ * $s / 100, 1);
    $gap   = $circ - $dash;
?>
<div class="fs-score-wrap">
    <!-- SVG gauge -->
    <div style="position:relative;width:100px;height:100px;flex-shrink:0">
        <svg width="100" height="100" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="<?php echo $r; ?>" fill="none" stroke="#f1f5f9" stroke-width="9"/>
            <circle cx="50" cy="50" r="<?php echo $r; ?>" fill="none" stroke="<?php echo $color; ?>" stroke-width="9"
                stroke-dasharray="<?php echo $dash.' '.$gap; ?>"
                stroke-dashoffset="<?php echo round($circ/4,1); ?>"
                stroke-linecap="round"/>
        </svg>
        <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center">
            <span style="font-size:24px;font-weight:800;color:<?php echo $color; ?>;line-height:1"><?php echo $s; ?></span>
            <span style="font-size:10px;color:#94a3b8">/ 100</span>
        </div>
    </div>
    <!-- Info -->
    <div style="flex:1;min-width:160px">
        <div style="font-size:22px;font-weight:800;color:#1e293b;margin-bottom:4px">
            Grade <span style="color:<?php echo $color; ?>"><?php echo $score_data['grade']; ?></span>
        </div>
        <div style="font-size:13px;color:#64748b;display:flex;flex-wrap:wrap;gap:10px">
            <?php if ($summary['critical']): ?><span style="color:#dc2626;font-weight:600"><span class="dashicons dashicons-warning"></span> <?php echo $summary['critical']; ?> critical</span><?php endif; ?>
            <?php if ($summary['warnings']): ?><span style="color:#d97706;font-weight:600"><span class="dashicons dashicons-flag"></span> <?php echo $summary['warnings']; ?> warnings</span><?php endif; ?>
            <?php if (!$summary['critical'] && !$summary['warnings']): ?><span style="color:#16a34a;font-weight:600"><span class="dashicons dashicons-yes-alt"></span> All clear!</span><?php endif; ?>
            <?php if ($summary['skipped']): ?><span style="color:#94a3b8"><?php echo $summary['skipped']; ?> skipped</span><?php endif; ?>
            <?php if ($summary['whitelisted']): ?><span style="color:#94a3b8"><?php echo $summary['whitelisted']; ?> whitelisted</span><?php endif; ?>
        </div>
    </div>
    <!-- Fix buttons -->
    <?php if ($summary['critical'] > 0 || $summary['total'] > 0): ?>
    <div style="display:flex;flex-direction:column;gap:8px;flex-shrink:0">
        <?php if ($summary['critical'] > 0): ?>
        <button id="btn-fix-all-critical" class="fs-btn fs-btn-red">
            <span class="dashicons dashicons-admin-tools"></span>
            Fix All Critical (<?php echo $summary['critical']; ?>)
        </button>
        <?php endif; ?>
        <?php if ($summary['total'] > 0): ?>
        <button id="btn-fix-all" class="fs-btn fs-btn-outline">
            <span class="dashicons dashicons-admin-tools"></span>
            Fix All Issues (<?php echo $summary['total']; ?>)
        </button>
        <?php endif; ?>
    </div>
    <?php endif; ?>
</div>
<?php endif; ?>

<!-- ── SCAN PROGRESS ── -->
<div id="scan-progress-wrap" style="<?php echo $has_scan ? 'display:none;' : ''; ?>background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:20px;margin-bottom:18px;box-shadow:0 1px 3px rgba(0,0,0,.06)">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <span id="scan-status-text" style="font-size:13px;font-weight:600;color:#374151">Ready to scan</span>
        <span id="scan-pct" style="font-size:16px;font-weight:800;color:#2563eb">0%</span>
    </div>
    <div class="fs-progress-bg"><div id="scan-progress-bar" class="fs-progress-fill"></div></div>
    <div class="fs-step-grid">
        <?php
        $step_icons = array(
            'malware'     => 'dashicons-bug',
            'dna'         => 'dashicons-media-code',
            'core'        => 'dashicons-admin-tools',
            'fim'         => 'dashicons-portfolio',
            'vuln'        => 'dashicons-admin-plugins',
            'ssl'         => 'dashicons-lock',
            'blacklist'   => 'dashicons-flag',
            'users'       => 'dashicons-admin-users',
            'headers'     => 'dashicons-shield',
            'permissions' => 'dashicons-admin-network',
        );
        foreach ($steps as $key => $step):
            $icon = $step_icons[$key] ?? 'dashicons-marker';
        ?>
        <div id="step-row-<?php echo $key; ?>" class="fs-step-item">
            <span class="dashicons <?php echo $icon; ?>" style="color:#94a3b8;font-size:15px;width:15px;height:15px"></span>
            <span class="label"><?php echo esc_html($step['label']); ?></span>
            <span id="step-icon-<?php echo $key; ?>" class="dashicons dashicons-clock" style="color:#cbd5e1;font-size:14px;width:14px;height:14px;flex-shrink:0"></span>
        </div>
        <?php endforeach; ?>
    </div>
</div>

<!-- ── ISSUES ── -->
<?php if ($has_scan):
    $criticals = array(); $warnings_list = array(); $skipped_issues = array(); $whitelisted_issues = array();
    foreach ($results as $step => $data) {
        foreach ($data['issues'] ?? array() as $issue) {
            $issue['step'] = $step;
            if (in_array($issue['id'], $whitelist)) { $whitelisted_issues[] = $issue; continue; }
            if (in_array($issue['id'], $skipped))   { $skipped_issues[]    = $issue; continue; }
            if ($issue['severity'] === 'critical') $criticals[]     = $issue;
            else                                   $warnings_list[] = $issue;
        }
    }
?>

<!-- Critical -->
<?php if ($criticals): ?>
<div class="fs-card fs-head-red">
    <div class="fs-card-head">
        <span class="dashicons dashicons-warning" style="color:#dc2626"></span>
        <h2>Critical Issues <span style="font-weight:400;color:#64748b">(<?php echo count($criticals); ?>)</span></h2>
    </div>
    <?php foreach ($criticals as $issue): swps_render_issue_row($issue, false); endforeach; ?>
</div>
<?php endif; ?>

<!-- Warnings -->
<?php if ($warnings_list): ?>
<div class="fs-card fs-head-yellow">
    <div class="fs-card-head">
        <span class="dashicons dashicons-flag" style="color:#d97706"></span>
        <h2>Warnings <span style="font-weight:400;color:#64748b">(<?php echo count($warnings_list); ?>)</span></h2>
    </div>
    <?php foreach ($warnings_list as $issue): swps_render_issue_row($issue, false); endforeach; ?>
</div>
<?php endif; ?>

<!-- All clear -->
<?php if (!$criticals && !$warnings_list): ?>
<div class="fs-allclear">
    <span class="dashicons dashicons-yes-alt" style="font-size:40px;width:40px;height:40px;color:#16a34a;display:block;margin:0 auto 10px"></span>
    <div style="font-size:17px;font-weight:700;color:#166534;margin-bottom:4px">All Clear!</div>
    <div style="color:#15803d;font-size:13px">No active issues found. Your site is well protected.</div>
</div>
<?php endif; ?>

<!-- Skipped -->
<?php if ($skipped_issues): ?>
<div class="fs-card">
    <div class="fs-card-head">
        <span class="dashicons dashicons-controls-skipforward" style="color:#64748b"></span>
        <h2 style="color:#64748b!important;font-size:13px!important">Skipped <span style="font-weight:400">(<?php echo count($skipped_issues); ?>)</span></h2>
    </div>
    <?php foreach ($skipped_issues as $issue): swps_render_issue_row($issue, true); endforeach; ?>
</div>
<?php endif; ?>

<!-- Whitelisted -->
<?php if ($whitelisted_issues): ?>
<div class="fs-card">
    <div class="fs-card-head">
        <span class="dashicons dashicons-shield-alt" style="color:#64748b"></span>
        <h2 style="color:#64748b!important;font-size:13px!important">Whitelisted — Permanently Ignored <span style="font-weight:400">(<?php echo count($whitelisted_issues); ?>)</span></h2>
    </div>
    <?php foreach ($whitelisted_issues as $issue): ?>
    <div class="fs-issue" style="opacity:.55">
        <span class="fs-badge fs-badge-wl"><span class="dashicons dashicons-shield-alt" style="font-size:11px;width:11px;height:11px"></span> WHITELISTED</span>
        <div style="flex:1">
            <div class="fs-issue-title"><?php echo esc_html($issue['title']); ?></div>
            <div class="fs-issue-detail"><?php echo esc_html($issue['detail']); ?></div>
        </div>
        <button class="fs-btn fs-btn-outline fs-btn-sm swps-unwhitelist-btn" data-id="<?php echo esc_attr($issue['id']); ?>">
            <span class="dashicons dashicons-no" style="font-size:12px;width:12px;height:12px"></span> Remove
        </button>
    </div>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<?php endif; /* has_scan */ ?>

<!-- ── SETTINGS + SCHEDULE ── -->
<div class="fs-2col">
    <div class="fs-card" style="margin-bottom:0">
        <div class="fs-card-head fs-head-blue">
            <span class="dashicons dashicons-admin-settings" style="color:#2563eb"></span>
            <h2>Scan Settings</h2>
        </div>
        <div class="fs-card-body">
            <div style="font-size:12px;color:#64748b;margin-bottom:10px">Enable / disable individual checks:</div>
            <form id="swps-scan-settings-form">
                <?php foreach ($steps as $key => $step):
                    $disabled_steps = (array)($settings['full_scan_disabled_steps']??array());
                    $checked = !in_array($key, $disabled_steps);
                    $icon = $step_icons[$key] ?? 'dashicons-marker';
                ?>
                <label style="display:flex;align-items:center;gap:8px;padding:5px 0;font-size:13px">
                    <input type="checkbox" name="full_scan_step[]" value="<?php echo $key; ?>" <?php checked($checked); ?>>
                    <span class="dashicons <?php echo $icon; ?>" style="color:#94a3b8;font-size:14px;width:14px;height:14px"></span>
                    <?php echo esc_html($step['label']); ?>
                </label>
                <?php endforeach; ?>
                <button type="submit" class="fs-submit">
                    <span class="dashicons dashicons-yes" style="font-size:14px;width:14px;height:14px;vertical-align:middle"></span>
                    Save Settings
                </button>
            </form>
        </div>
    </div>
    <div class="fs-card" style="margin-bottom:0">
        <div class="fs-card-head fs-head-blue">
            <span class="dashicons dashicons-clock" style="color:#2563eb"></span>
            <h2>Auto-Scan Schedule</h2>
        </div>
        <div class="fs-card-body">
            <form id="swps-schedule-form">
                <div style="margin-bottom:12px">
                    <label style="display:block;font-size:12px;color:#64748b;margin-bottom:5px;font-weight:600">Frequency</label>
                    <select name="full_scan_schedule">
                        <option value="" <?php selected('',$settings['full_scan_schedule']??''); ?>>— Disabled —</option>
                        <option value="daily" <?php selected('daily',$settings['full_scan_schedule']??''); ?>>Daily</option>
                        <option value="weekly" <?php selected('weekly',$settings['full_scan_schedule']??''); ?>>Weekly</option>
                    </select>
                </div>
                <label style="display:flex;align-items:center;gap:8px;font-size:13px;margin-bottom:10px">
                    <input type="checkbox" name="full_scan_auto_fix" value="1" <?php checked(!empty($settings['full_scan_auto_fix'])); ?>>
                    Auto-fix critical issues on schedule
                </label>
                <label style="display:flex;align-items:center;gap:8px;font-size:13px;margin-bottom:14px">
                    <input type="checkbox" name="full_scan_email_report" value="1" <?php checked(!empty($settings['full_scan_email_report'])); ?>>
                    Email report after each scan
                </label>
                <?php $next = wp_next_scheduled('swps_scheduled_full_scan'); if ($next): ?>
                <div style="font-size:12px;color:#64748b;background:#f8fafc;border:1px solid #e2e8f0;padding:8px 12px;border-radius:6px;margin-bottom:12px">
                    <span class="dashicons dashicons-clock" style="font-size:13px;width:13px;height:13px;color:#2563eb"></span>
                    Next scan: <strong><?php echo date('M j, Y H:i', $next); ?></strong>
                </div>
                <?php endif; ?>
                <button type="submit" class="fs-submit">
                    <span class="dashicons dashicons-yes" style="font-size:14px;width:14px;height:14px;vertical-align:middle"></span>
                    Save Schedule
                </button>
            </form>
        </div>
    </div>
</div>

<!-- ── SCAN HISTORY ── -->
<?php if ($history): ?>
<div class="fs-card">
    <div class="fs-card-head">
        <span class="dashicons dashicons-chart-line" style="color:#2563eb"></span>
        <h2>Scan History <span style="font-weight:400;color:#64748b;font-size:12px">(Last <?php echo count($history); ?> scans)</span></h2>
    </div>
    <div style="overflow-x:auto">
    <table class="fs-table">
        <thead><tr>
            <th>Date</th>
            <th style="text-align:center">Score</th>
            <th style="text-align:center">Grade</th>
            <th style="text-align:center">Critical</th>
            <th style="text-align:center">Warnings</th>
            <th style="text-align:center">Checks</th>
        </tr></thead>
        <tbody>
        <?php foreach ($history as $i => $entry):
            $ecol = $entry['score'] >= 80 ? '#16a34a' : ($entry['score'] >= 50 ? '#d97706' : '#dc2626');
        ?>
        <tr style="<?php echo $i===0?'background:#f0f9ff!important;':'' ?>">
            <td>
                <?php echo date('M j, Y H:i', $entry['date']); ?>
                <?php if ($i===0): ?><span class="fs-chip" style="background:#dbeafe;color:#1d4ed8;margin-left:6px">Latest</span><?php endif; ?>
            </td>
            <td style="text-align:center;font-weight:700;color:<?php echo $ecol; ?>"><?php echo $entry['score']; ?>/100</td>
            <td style="text-align:center;font-weight:700;color:<?php echo $ecol; ?>"><?php echo $entry['grade']; ?></td>
            <td style="text-align:center">
                <?php if ($entry['critical']): ?>
                <span class="fs-chip fs-chip-err"><?php echo $entry['critical']; ?></span>
                <?php else: ?>
                <span class="dashicons dashicons-yes" style="color:#16a34a"></span>
                <?php endif; ?>
            </td>
            <td style="text-align:center">
                <?php if ($entry['warnings']): ?>
                <span class="fs-chip" style="background:#fef9c3;color:#92400e"><?php echo $entry['warnings']; ?></span>
                <?php else: ?>
                <span class="dashicons dashicons-yes" style="color:#16a34a"></span>
                <?php endif; ?>
            </td>
            <td style="text-align:center;color:#64748b"><?php echo $entry['steps_run']; ?></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>
</div>
<?php endif; ?>

<!-- ── STEP DETAILS ── -->
<?php if ($has_scan): ?>
<div class="fs-card">
    <div class="fs-card-head">
        <span class="dashicons dashicons-list-view" style="color:#2563eb"></span>
        <h2>Scan Details by Check</h2>
    </div>
    <table class="fs-table">
        <thead><tr>
            <th>Check</th>
            <th style="text-align:center">Status</th>
            <th style="text-align:center">Issues</th>
            <th style="text-align:right">Scanned At</th>
        </tr></thead>
        <tbody>
        <?php foreach ($steps as $key => $step):
            $data  = $results[$key] ?? null;
            $count = $data ? count($data['issues']??array()) : null;
            $icon  = $step_icons[$key] ?? 'dashicons-marker';
        ?>
        <tr>
            <td>
                <span class="dashicons <?php echo $icon; ?>" style="color:#64748b;font-size:14px;width:14px;height:14px"></span>
                <?php echo esc_html($step['label']); ?>
            </td>
            <td style="text-align:center">
                <?php if ($data === null): ?>
                    <span class="fs-chip fs-chip-gray">Not scanned</span>
                <?php elseif ($count === 0): ?>
                    <span class="fs-chip fs-chip-ok"><span class="dashicons dashicons-yes" style="font-size:11px;width:11px;height:11px"></span> Clean</span>
                <?php else: ?>
                    <span class="fs-chip fs-chip-err"><?php echo $count; ?> found</span>
                <?php endif; ?>
            </td>
            <td style="text-align:center;color:#374151"><?php echo $count ?? '—'; ?></td>
            <td style="text-align:right;color:#94a3b8;font-size:12px">
                <?php echo $data ? date('H:i:s', $data['scanned_at']) : '—'; ?>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php endif; ?>

</div><!-- #swps-fs-page -->

<!-- ── TOAST ── -->
<div id="swps-toast"></div>

<!-- ── FIX-ALL MODAL ── -->
<div id="swps-fixall-modal">
    <div class="modal-box">
        <div style="padding:18px 22px;border-bottom:1px solid #e2e8f0;display:flex;align-items:center;justify-content:space-between">
            <h3 style="margin:0;font-size:15px;font-weight:700;color:#1e293b">
                <span class="dashicons dashicons-admin-tools" style="color:#2563eb"></span> Fix All — Progress
            </h3>
            <button onclick="document.getElementById('swps-fixall-modal').style.display='none'"
                style="background:none;border:none;font-size:22px;cursor:pointer;color:#64748b;line-height:1">&times;</button>
        </div>
        <div id="fixall-log" style="padding:18px 22px;overflow-y:auto;flex:1;font-size:13px;font-family:monospace;line-height:1.8;color:#374151"></div>
        <div style="padding:14px 22px;border-top:1px solid #e2e8f0;display:flex;justify-content:space-between;align-items:center">
            <span id="fixall-summary" style="font-size:13px;color:#64748b"></span>
            <button onclick="location.reload()" class="fs-btn fs-btn-primary">Reload Page</button>
        </div>
    </div>
</div>

<script>
(function($){
    var STEPS = <?php echo wp_json_encode(array_keys($steps)); ?>;
    var NONCE = '<?php echo wp_create_nonce('swps_nonce'); ?>';
    var scanning = false;

    // Toast
    function toast(msg, type) {
        var t = document.getElementById('swps-toast');
        var c = {info:'#2563eb',success:'#16a34a',error:'#dc2626',warning:'#d97706'};
        t.style.background = c[type]||c.info;
        t.innerHTML = '<span class="dashicons dashicons-'+(type==='success'?'yes-alt':type==='error'?'dismiss':'info')+'" style="vertical-align:middle;font-size:14px;width:14px;height:14px;margin-right:6px"></span>'+msg;
        t.style.opacity='1'; t.style.transform='translateY(0)';
        setTimeout(function(){ t.style.opacity='0'; t.style.transform='translateY(16px)'; }, 4000);
    }

    // Start scan
    document.getElementById('btn-start-scan').addEventListener('click', function(){
        if (scanning) return;
        scanning = true;
        this.disabled = true;
        this.innerHTML = '<span class="dashicons dashicons-update" style="font-size:15px;width:15px;height:15px"></span> Scanning...';
        document.getElementById('scan-progress-wrap').style.display = 'block';
        runNextStep(0);
    });

    function runNextStep(idx) {
        if (idx >= STEPS.length) { onScanComplete(); return; }
        var step = STEPS[idx], pct = Math.round((idx/STEPS.length)*100);
        document.getElementById('scan-progress-bar').style.width = pct+'%';
        document.getElementById('scan-pct').textContent = pct+'%';
        document.getElementById('scan-status-text').textContent = 'Scanning: '+step.replace(/_/g,' ')+'...';
        setStepIcon(step, 'dashicons-update', '#2563eb');
        $.post(ajaxurl, {action:'swps_full_scan_run', step:step, nonce:NONCE}, function(res){
            var count = res.success && res.data.issues ? res.data.issues.length : 0;
            if (!res.success) setStepIcon(step, 'dashicons-dismiss', '#dc2626');
            else if (count > 0) setStepIcon(step, 'dashicons-warning', '#d97706');
            else setStepIcon(step, 'dashicons-yes-alt', '#16a34a');
            runNextStep(idx+1);
        }).fail(function(){ setStepIcon(step,'dashicons-dismiss','#dc2626'); runNextStep(idx+1); });
    }

    function setStepIcon(step, icon, color) {
        var el = document.getElementById('step-icon-'+step);
        if (el) { el.className = 'dashicons '+icon; el.style.color = color; el.style.fontSize='14px'; el.style.width='14px'; el.style.height='14px'; }
    }

    function onScanComplete() {
        document.getElementById('scan-progress-bar').style.width = '100%';
        document.getElementById('scan-pct').textContent = '100%';
        document.getElementById('scan-status-text').textContent = 'Scan complete! Reloading...';
        toast('Scan complete!', 'success');
        setTimeout(function(){ location.reload(); }, 1500);
    }

    // Fix single
    $(document).on('click', '.swps-fix-btn', function(){
        var btn=$(this), id=btn.data('id'), fix=btn.data('fix'), fd=btn.data('fix-data');
        btn.prop('disabled',true).html('<span class="dashicons dashicons-update" style="font-size:12px;width:12px;height:12px"></span> Fixing...');
        $.post(ajaxurl,{action:'swps_full_scan_fix',issue_id:id,fix_type:fix,fix_data:fd,nonce:NONCE},function(res){
            if(res.success){toast(res.data.message||'Fixed!','success');btn.closest('.fs-issue').fadeOut(400);}
            else{toast(res.data||'Fix failed','error');btn.prop('disabled',false).html('<span class="dashicons dashicons-admin-tools" style="font-size:12px;width:12px;height:12px"></span> Fix');}
        });
    });

    // Skip
    $(document).on('click', '.swps-skip-btn', function(){
        var btn=$(this), id=btn.data('id');
        $.post(ajaxurl,{action:'swps_full_scan_skip',issue_id:id,nonce:NONCE},function(res){
            if(res.success){toast('Skipped','info');btn.closest('.fs-issue').fadeOut(400);}
        });
    });

    // Unskip
    $(document).on('click', '.swps-unskip-btn', function(){
        $.post(ajaxurl,{action:'swps_full_scan_unskip',issue_id:$(this).data('id'),nonce:NONCE},function(res){
            if(res.success){toast('Unskipped','info');location.reload();}
        });
    });

    // Whitelist
    $(document).on('click', '.swps-whitelist-btn', function(){
        if(!confirm('Permanently whitelist this issue? It will not appear in future scans.')) return;
        $.post(ajaxurl,{action:'swps_full_scan_whitelist',issue_id:$(this).data('id'),wl_action:'add',nonce:NONCE},function(res){
            if(res.success){toast('Whitelisted','info');location.reload();}
        });
    });

    // Un-whitelist
    $(document).on('click', '.swps-unwhitelist-btn', function(){
        $.post(ajaxurl,{action:'swps_full_scan_whitelist',issue_id:$(this).data('id'),wl_action:'remove',nonce:NONCE},function(res){
            if(res.success){toast('Removed from whitelist','success');location.reload();}
        });
    });

    // Fix All
    function doFixAll(severity) {
        var modal=document.getElementById('swps-fixall-modal'), log=document.getElementById('fixall-log'), summ=document.getElementById('fixall-summary');
        log.innerHTML='<div style="color:#64748b"><span class="dashicons dashicons-update"></span> Running fixes...</div>';
        summ.textContent='';
        modal.style.display='flex';
        $.post(ajaxurl,{action:'swps_full_scan_fix_all',severity:severity,nonce:NONCE},function(res){
            if(res.success){
                var d=res.data;
                log.innerHTML=(d.log||[]).map(function(l){return '<div>'+l+'</div>';}).join('');
                summ.textContent='Fixed: '+d.fixed+' | Failed: '+d.failed;
                toast('Fix All done: '+d.fixed+' fixed','success');
            } else {
                log.innerHTML='<div style="color:#dc2626">Error: '+(res.data||'Unknown')+'</div>';
            }
        });
    }
    var bfc=document.getElementById('btn-fix-all-critical');
    if(bfc) bfc.addEventListener('click',function(){ if(confirm('Fix all critical issues now?')) doFixAll('critical'); });
    var bfa=document.getElementById('btn-fix-all');
    if(bfa) bfa.addEventListener('click',function(){ if(confirm('Fix ALL issues (critical + warnings)?')) doFixAll('all'); });

    // Clear
    var bc=document.getElementById('btn-clear-scan');
    if(bc) bc.addEventListener('click',function(){
        if(!confirm('Clear all scan results?')) return;
        $.post(ajaxurl,{action:'swps_full_scan_clear',nonce:NONCE},function(res){ if(res.success) location.reload(); });
    });

    // Export
    var be=document.getElementById('btn-export-report');
    if(be) be.addEventListener('click',function(){
        toast('Generating report...','info');
        var f=document.createElement('form'); f.method='POST'; f.action=ajaxurl;
        [['action','swps_full_scan_report'],['nonce',NONCE]].forEach(function(p){
            var i=document.createElement('input'); i.type='hidden'; i.name=p[0]; i.value=p[1]; f.appendChild(i);
        });
        document.body.appendChild(f); f.submit(); document.body.removeChild(f);
    });

    // Email
    var bem=document.getElementById('btn-email-report');
    if(bem) bem.addEventListener('click',function(){
        bem.disabled=true; bem.innerHTML='<span class="dashicons dashicons-update" style="font-size:14px;width:14px;height:14px"></span> Sending...';
        $.post(ajaxurl,{action:'swps_full_scan_email',nonce:NONCE},function(res){
            bem.disabled=false; bem.innerHTML='<span class="dashicons dashicons-email-alt" style="font-size:14px;width:14px;height:14px"></span> Email Report';
            res.success ? toast('Report emailed!','success') : toast(res.data||'Email failed','error');
        });
    });

    // Scan settings
    document.getElementById('swps-scan-settings-form').addEventListener('submit',function(e){
        e.preventDefault();
        var enabled=Array.from(this.querySelectorAll('input[type=checkbox]:checked')).map(function(x){return x.value;});
        var allSteps=<?php echo wp_json_encode(array_keys($steps)); ?>;
        var disabled=allSteps.filter(function(s){return !enabled.includes(s);});
        $.post(ajaxurl,{action:'swps_save_scan_settings',disabled_steps:disabled,nonce:NONCE},function(res){
            toast(res.success?'Settings saved!':'Failed','info');
        });
    });

    // Schedule
    document.getElementById('swps-schedule-form').addEventListener('submit',function(e){
        e.preventDefault();
        var data={action:'swps_save_scan_schedule',nonce:NONCE};
        (new FormData(this)).forEach(function(v,k){data[k]=v;});
        $.post(ajaxurl,data,function(res){ toast(res.success?'Schedule saved!':'Failed','info'); });
    });

})(jQuery);
</script>

<?php
function swps_render_issue_row($issue, $is_skipped = false) {
    $sev      = $issue['severity'];
    $id       = $issue['id'];
    $has_fix  = !empty($issue['fix']) && $issue['fix'] !== 'none' && !empty($issue['fix_label']);
    $fd_json  = esc_attr(wp_json_encode($issue['fix_data'] ?? array()));
    $badge    = $is_skipped ? 'fs-badge-skip' : ($sev === 'critical' ? 'fs-badge-critical' : 'fs-badge-warning');
    $badge_ic = $is_skipped ? 'dashicons-controls-skipforward' : ($sev === 'critical' ? 'dashicons-warning' : 'dashicons-flag');
    $label    = $is_skipped ? 'SKIPPED' : strtoupper($sev);
    ?>
    <div class="fs-issue swps-issue-row" data-issue-id="<?php echo esc_attr($id); ?>">
        <span class="fs-badge <?php echo $badge; ?>">
            <span class="dashicons <?php echo $badge_ic; ?>" style="font-size:10px;width:10px;height:10px"></span>
            <?php echo $label; ?>
        </span>
        <div style="flex:1;min-width:0">
            <div class="fs-issue-title"><?php echo esc_html($issue['title']); ?></div>
            <div class="fs-issue-detail"><?php echo esc_html($issue['detail']); ?></div>
        </div>
        <div style="display:flex;gap:6px;flex-shrink:0;flex-wrap:wrap;align-items:center">
            <?php if ($is_skipped): ?>
                <button class="fs-btn fs-btn-outline fs-btn-sm swps-unskip-btn" data-id="<?php echo esc_attr($id); ?>">
                    <span class="dashicons dashicons-undo" style="font-size:12px;width:12px;height:12px"></span> Unskip
                </button>
            <?php else: ?>
                <?php if ($has_fix): ?>
                <button class="fs-btn fs-btn-fix swps-fix-btn"
                    data-id="<?php echo esc_attr($id); ?>"
                    data-fix="<?php echo esc_attr($issue['fix']); ?>"
                    data-fix-data="<?php echo $fd_json; ?>">
                    <span class="dashicons dashicons-admin-tools" style="font-size:12px;width:12px;height:12px"></span>
                    <?php echo esc_html($issue['fix_label']); ?>
                </button>
                <?php endif; ?>
                <button class="fs-btn fs-btn-outline fs-btn-sm swps-skip-btn" data-id="<?php echo esc_attr($id); ?>">
                    <span class="dashicons dashicons-controls-skipforward" style="font-size:12px;width:12px;height:12px"></span>
                </button>
                <button class="fs-btn fs-btn-outline fs-btn-sm swps-whitelist-btn" data-id="<?php echo esc_attr($id); ?>" title="Permanently ignore">
                    <span class="dashicons dashicons-shield-alt" style="font-size:12px;width:12px;height:12px"></span>
                </button>
            <?php endif; ?>
        </div>
    </div>
    <?php
}
?>
