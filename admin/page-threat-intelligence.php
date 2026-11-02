<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-warning"></span> Threat Intelligence</h1>
    <p class="description" style="margin:-8px 0 16px;max-width:760px">
        Advanced tools that detect and trap attackers automatically: IP reputation scoring, honeypot
        traps (fake targets), decoy logins, and canary tokens (hidden tripwires). Together they catch
        bad actors before they reach anything important.
    </p>

    <?php
    $hp_stats  = SWPS_Honeypot::get_stats();
    $rl_stats  = SWPS_Rate_Limiter::get_stats();
    $fl_stats  = SWPS_Fake_Login::get_stats();
    $top_reps  = SWPS_IP_Reputation::get_top_threats(10);
    $hp_log    = SWPS_Honeypot::get_log(20);
    $fl_log    = SWPS_Fake_Login::get_log(20);
    $settings  = get_option('swps_settings', array());
    ?>

    <!-- Stats overview -->
    <div class="swps-stats-grid">
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-red"><?php echo $hp_stats['total_hits']; ?></div>
            <div class="swps-stat-label">Honeypot Hits</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-red"><?php echo $fl_stats['cred_attempts']; ?></div>
            <div class="swps-stat-label">Fake Login Attempts</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-orange"><?php echo $rl_stats['total_blocks']; ?></div>
            <div class="swps-stat-label">Rate Limit Blocks</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-red"><?php echo count($top_reps); ?></div>
            <div class="swps-stat-label">High-Risk IPs</div>
        </div>
    </div>

    <div class="swps-tabs">
        <button class="swps-tab swps-tab-active" data-tab="honeypot">Honeypot</button>
        <button class="swps-tab" data-tab="ratelimit">Rate Limiter</button>
        <button class="swps-tab" data-tab="fakelogin">Fake Login</button>
        <button class="swps-tab" data-tab="reputation">IP Reputation</button>
        <button class="swps-tab" data-tab="challenge">Challenge Page</button>
        <button class="swps-tab" data-tab="canary">Canary Tokens</button>
        <button class="swps-tab" data-tab="dna">DNA Scanner</button>
    </div>

    <!-- Honeypot Tab -->
    <div class="swps-tab-content swps-tab-active" id="tab-honeypot">
        <div class="swps-card">
            <div class="swps-card-header">
                <h2>Honeypot Traps (<?php echo $hp_stats['trap_count']; ?> active)</h2>
                <div class="swps-card-actions">
                    <button id="swps-hp-clear" class="button button-link-delete">Clear Log</button>
                </div>
            </div>
            <form method="post" action="options.php" style="margin-bottom:16px">
                <?php settings_fields('swps_settings_group'); ?>
                <table class="form-table swps-form-table">
                    <tr>
                        <th>Enable Honeypot</th>
                        <td><label class="swps-toggle"><input type="checkbox" name="swps_settings[honeypot_enabled]" value="1" <?php checked(!empty($settings['honeypot_enabled'])); ?>><span class="swps-slider"></span></label></td>
                    </tr>
                    <tr>
                        <th>Auto-Block on Hit</th>
                        <td><label class="swps-toggle"><input type="checkbox" name="swps_settings[honeypot_auto_block]" value="1" <?php checked(!empty($settings['honeypot_auto_block'])); ?>><span class="swps-slider"></span></label> Block the IP immediately</td>
                    </tr>
                    <tr>
                        <th>Block Duration (min)</th>
                        <td><input type="number" name="swps_settings[honeypot_block_duration]" value="<?php echo esc_attr($settings['honeypot_block_duration'] ?? 1440); ?>" class="small-text"> minutes (1440 = 24h)</td>
                    </tr>
                    <tr>
                        <th>Response Type</th>
                        <td>
                            <select name="swps_settings[honeypot_response]" class="swps-select">
                                <option value="fake_404" <?php selected($settings['honeypot_response']??'fake_404','fake_404'); ?>>Fake 404</option>
                                <option value="fake_200" <?php selected($settings['honeypot_response']??'','fake_200'); ?>>Fake 200 (empty)</option>
                                <option value="redirect_home" <?php selected($settings['honeypot_response']??'','redirect_home'); ?>>Redirect Home</option>
                            </select>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Save Honeypot Settings', 'secondary', 'submit', false); ?>
            </form>

            <!-- Add trap -->
            <div style="display:flex;gap:8px">
                <input type="text" id="swps-hp-new-trap" placeholder="/secret-backup.zip" class="regular-text">
                <button id="swps-hp-add" class="button button-primary">Add Trap</button>
            </div>
        </div>

        <!-- Side by side (explicit user request) instead of stacked, each
             with its own scroll cap from the shared .swps-card rule. -->
        <div class="swps-two-col">
            <div class="swps-card">
                <h2>Active Traps</h2>
                <div id="swps-hp-trap-list" style="max-height:70vh;overflow-y:auto">
                <?php foreach (SWPS_Honeypot::get_traps() as $trap): ?>
                <div class="swps-hp-trap" style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
                    <code style="flex:1">/<?php echo esc_html($trap); ?></code>
                    <button class="button button-small swps-hp-remove" data-slug="<?php echo esc_attr($trap); ?>">Remove</button>
                </div>
                <?php endforeach; ?>
                </div>
            </div>

            <?php if (!empty($hp_log)): ?>
            <div class="swps-card">
                <h2>Recent Honeypot Hits</h2>
                <table class="swps-table widefat striped">
                    <thead><tr><th>Time</th><th>IP</th><th>Country</th><th>Trap URL</th><th>Method</th></tr></thead>
                    <tbody>
                    <?php foreach ($hp_log as $h): ?>
                    <tr>
                        <td><?php echo human_time_diff($h['time']); ?> ago</td>
                        <td><code><?php echo esc_html($h['ip']); ?></code></td>
                        <td><?php echo esc_html($h['country'] ?: '—'); ?></td>
                        <td><code>/<?php echo esc_html($h['trap']); ?></code></td>
                        <td><span class="swps-badge swps-badge-warning"><?php echo esc_html($h['method']); ?></span></td>
                    </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Rate Limiter Tab -->
    <div class="swps-tab-content" id="tab-ratelimit">
        <div class="swps-card">
            <h2>Rate Limiter Settings</h2>
            <form method="post" action="options.php">
                <?php settings_fields('swps_settings_group'); ?>
                <table class="form-table swps-form-table">
                    <tr>
                        <th>Enable Rate Limiter</th>
                        <td><label class="swps-toggle"><input type="checkbox" name="swps_settings[rate_limiter_enabled]" value="1" <?php checked(!empty($settings['rate_limiter_enabled'])); ?>><span class="swps-slider"></span></label></td>
                    </tr>
                </table>
                <?php submit_button('Save', 'secondary', 'submit', false); ?>
            </form>
            <h3 style="margin-top:16px">Default Rules</h3>
            <table class="swps-table widefat striped">
                <thead><tr><th>Endpoint</th><th>Limit</th><th>Window</th><th>Block Duration</th></tr></thead>
                <tbody>
                <?php foreach (SWPS_Rate_Limiter::get_rules() as $ep => $rule): ?>
                <tr>
                    <td><strong><?php echo esc_html($ep); ?></strong></td>
                    <td><?php echo $rule['limit']; ?> req</td>
                    <td><?php echo $rule['window']; ?>s</td>
                    <td><?php echo round($rule['block']/60); ?> min</td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php if (!empty($rl_stats['recent'])): ?>
        <div class="swps-card">
            <div class="swps-card-header">
                <h2 style="margin:0;border:none;padding:0">Recent Rate Limit Events</h2>
                <button id="swps-rl-clear" class="button button-link-delete" style="margin-left:auto">Clear Log</button>
            </div>
            <table class="swps-table widefat striped">
                <thead><tr><th>Time</th><th>IP</th><th>Endpoint</th><th>Requests</th></tr></thead>
                <tbody>
                <?php foreach ($rl_stats['recent'] as $e): ?>
                <tr>
                    <td><?php echo human_time_diff($e['time']); ?> ago</td>
                    <td><code><?php echo esc_html($e['ip']); ?></code></td>
                    <td><?php echo esc_html($e['endpoint']); ?></td>
                    <td><span class="swps-badge swps-badge-critical"><?php echo $e['count']; ?></span></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>
    </div>

    <!-- Fake Login Tab -->
    <div class="swps-tab-content" id="tab-fakelogin">
        <div class="swps-card">
            <h2>Decoy Login Page</h2>
            <form method="post" action="options.php">
                <?php settings_fields('swps_settings_group'); ?>
                <table class="form-table swps-form-table">
                    <tr>
                        <th>Enable Fake Login</th>
                        <td><label class="swps-toggle"><input type="checkbox" name="swps_settings[fake_login_enabled]" value="1" <?php checked(!empty($settings['fake_login_enabled'])); ?>><span class="swps-slider"></span></label></td>
                    </tr>
                    <tr>
                        <th>Decoy URL Slug</th>
                        <td>
                            <code><?php echo home_url('/'); ?></code>
                            <input type="text" name="swps_settings[fake_login_slug]" value="<?php echo esc_attr($settings['fake_login_slug'] ?? 'admin-login'); ?>" class="regular-text">
                            <p class="description">This URL shows a fake WordPress login. Real login is at your custom URL.</p>
                        </td>
                    </tr>
                    <tr>
                        <th>Auto-Block Credential Attempts</th>
                        <td><label class="swps-toggle"><input type="checkbox" name="swps_settings[fake_login_auto_block]" value="1" <?php checked(!empty($settings['fake_login_auto_block'])); ?>><span class="swps-slider"></span></label></td>
                    </tr>
                </table>
                <?php submit_button('Save', 'secondary', 'submit', false); ?>
            </form>
        </div>
        <?php if (!empty($fl_log)): ?>
        <div class="swps-card">
            <div class="swps-card-header">
                <h2 style="margin:0;border:none;padding:0">Fake Login Log</h2>
                <button id="swps-fl-clear" class="button button-link-delete" style="margin-left:auto">Clear Log</button>
            </div>
            <table class="swps-table widefat striped">
                <thead><tr><th>Time</th><th>IP</th><th>Country</th><th>Type</th><th>Username Tried</th></tr></thead>
                <tbody>
                <?php foreach ($fl_log as $e): ?>
                <tr>
                    <td><?php echo human_time_diff($e['time']); ?> ago</td>
                    <td><code><?php echo esc_html($e['ip']); ?></code></td>
                    <td><?php echo esc_html($e['country'] ?: '—'); ?></td>
                    <td><span class="swps-badge <?php echo $e['type']==='credentials'?'swps-badge-critical':'swps-badge-warning'; ?>"><?php echo esc_html($e['type']); ?></span></td>
                    <td><?php echo esc_html($e['username'] ?: '—'); ?></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>
    </div>

    <!-- IP Reputation Tab -->
    <div class="swps-tab-content" id="tab-reputation">
        <div class="swps-card">
            <h2>Top Threat IPs</h2>
            <div style="display:flex;gap:8px;margin-bottom:16px">
                <input type="text" id="swps-rep-lookup-ip" placeholder="Enter IP to lookup…" class="regular-text">
                <button id="swps-rep-lookup" class="button">Lookup</button>
            </div>
            <div id="swps-rep-result"></div>
            <table class="swps-table widefat striped">
                <thead><tr><th>IP</th><th>Score</th><th>Risk Level</th><th>Last Event</th><th>Action</th></tr></thead>
                <tbody>
                <?php foreach ($top_reps as $record):
                    $label = SWPS_IP_Reputation::get_label($record['score']);
                ?>
                <tr>
                    <td><code><?php echo esc_html($record['ip']); ?></code></td>
                    <td>
                        <div style="display:flex;align-items:center;gap:6px">
                            <div style="width:<?php echo $record['score']; ?>px;max-width:100px;height:6px;background:<?php echo $record['score']>=75?'#e74c3c':($record['score']>=40?'#f39c12':'#2ecc71'); ?>;border-radius:3px"></div>
                            <strong><?php echo $record['score']; ?>/100</strong>
                        </div>
                    </td>
                    <td><span class="swps-badge <?php echo $label['class']; ?>"><?php echo $label['label']; ?></span></td>
                    <td><?php echo $record['last_event'] ? human_time_diff($record['last_event']).' ago' : '—'; ?></td>
                    <td>
                        <button class="button button-small swps-rep-reset" data-ip="<?php echo esc_attr($record['ip']); ?>">Reset</button>
                        <button class="button button-small button-link-delete swps-rep-block" data-ip="<?php echo esc_attr($record['ip']); ?>">Block</button>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Challenge Page Tab -->
    <div class="swps-tab-content" id="tab-challenge">
        <div class="swps-card">
            <h2>Browser Challenge Page</h2>
            <p class="description">Shows a "Checking your browser…" page (like Cloudflare) to suspicious IPs. Bots fail, humans pass automatically. Pass token stored in cookie for <?php echo SWPS_Challenge_Page::COOKIE_HOURS; ?> hours.</p>
            <form method="post" action="options.php">
                <?php settings_fields('swps_settings_group'); ?>
                <table class="form-table swps-form-table">
                    <tr>
                        <th>Enable Challenge Page</th>
                        <td><label class="swps-toggle"><input type="checkbox" name="swps_settings[challenge_page_enabled]" value="1" <?php checked(!empty($settings['challenge_page_enabled'])); ?>><span class="swps-slider"></span></label></td>
                    </tr>
                    <tr>
                        <th>Challenge after failed logins</th>
                        <td><input type="number" name="swps_settings[challenge_after_attempts]" value="<?php echo esc_attr($settings['challenge_after_attempts'] ?? 3); ?>" class="small-text"> failed attempts</td>
                    </tr>
                    <tr>
                        <th>Challenge AbuseIPDB score ≥</th>
                        <td><input type="number" name="swps_settings[challenge_abuse_threshold]" value="<?php echo esc_attr($settings['challenge_abuse_threshold'] ?? 50); ?>" min="0" max="100" class="small-text"> /100</td>
                    </tr>
                    <tr>
                        <th>Active Challenge Sessions</th>
                        <td><strong><?php echo SWPS_Challenge_Page::get_active_count(); ?></strong> IPs currently cleared</td>
                    </tr>
                </table>
                <?php submit_button('Save', 'secondary', 'submit', false); ?>
            </form>
        </div>
    </div>

    <!-- Canary Tokens Tab -->
    <div class="swps-tab-content" id="tab-canary">
        <?php
        $canary_stats = SWPS_Canary_Tokens::get_stats();
        ?>
        <div class="swps-card">
            <div class="swps-card-header">
                <h2>Canary Tokens (<?php echo $canary_stats['token_count']; ?> tokens, <?php echo $canary_stats['total_pings']; ?> pings)</h2>
                <button id="swps-canary-create" class="button button-primary">Create New Token</button>
            </div>
            <p class="description">Canary tokens are invisible tracking URLs. Embed them in content — when someone copies your content and loads it, you get an instant alert.</p>
            <table class="swps-table widefat striped" style="margin-top:12px">
                <thead><tr><th>Name</th><th>Tracking URL</th><th>Hits</th><th>Last Hit</th><th>Action</th></tr></thead>
                <tbody>
                <?php if (empty($canary_stats['tokens'])): ?>
                <tr><td colspan="5" style="text-align:center;padding:16px">No canary tokens yet.</td></tr>
                <?php endif; ?>
                <?php foreach ($canary_stats['tokens'] as $id => $token): ?>
                <tr>
                    <td><strong><?php echo esc_html($token['name']); ?></strong><br><span class="swps-muted"><?php echo esc_html($token['description']); ?></span></td>
                    <td><code style="font-size:11px"><?php echo esc_html($token['url']); ?></code>
                        <button class="button button-small" onclick="navigator.clipboard.writeText('<?php echo esc_js($token['url']); ?>')">Copy</button>
                    </td>
                    <td><strong><?php echo $token['hits']; ?></strong></td>
                    <td><?php echo $token['last_hit'] ? human_time_diff($token['last_hit']).' ago' : 'Never'; ?></td>
                    <td><button class="button button-small button-link-delete swps-canary-delete" data-id="<?php echo esc_attr($id); ?>">Delete</button></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <?php if (!empty($canary_stats['recent_pings'])): ?>
        <div class="swps-card">
            <h2>Recent Canary Pings</h2>
            <table class="swps-table widefat striped">
                <thead><tr><th>Time</th><th>Token</th><th>IP</th><th>Referer</th></tr></thead>
                <tbody>
                <?php foreach ($canary_stats['recent_pings'] as $p): ?>
                <tr>
                    <td><?php echo human_time_diff($p['time']); ?> ago</td>
                    <td><?php echo esc_html($p['token_name']); ?></td>
                    <td><code><?php echo esc_html($p['ip']); ?></code></td>
                    <td class="swps-muted"><?php echo esc_html(substr($p['referer'],0,60)); ?></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>
    </div>

    <!-- DNA Scanner Tab -->
    <div class="swps-tab-content" id="tab-dna">
        <?php $dna = SWPS_Malware_DNA::get_last_result(); ?>
        <div class="swps-card">
            <div class="swps-card-header">
                <h2>Malware DNA Scanner (<?php echo SWPS_Malware_DNA::get_sig_count(); ?> signatures)</h2>
                <button id="swps-dna-scan" class="button button-primary">Scan Now</button>
            </div>
            <div id="swps-dna-result"></div>
            <?php if ($dna): ?>
            <div class="swps-stats-grid" style="margin-top:12px">
                <div class="swps-stat-card"><div class="swps-stat-num"><?php echo $dna['scanned']; ?></div><div class="swps-stat-label">Files Scanned</div></div>
                <div class="swps-stat-card"><div class="swps-stat-num swps-color-red"><?php echo $dna['infected']; ?></div><div class="swps-stat-label">Infected</div></div>
                <div class="swps-stat-card"><div class="swps-stat-num swps-color-green"><?php echo $dna['clean']; ?></div><div class="swps-stat-label">Clean</div></div>
            </div>
            <?php if (!empty($dna['results'])): ?>
            <table class="swps-table widefat striped" style="margin-top:12px">
                <thead><tr><th>File</th><th>Signatures</th><th>Severity</th></tr></thead>
                <tbody>
                <?php foreach ($dna['results'] as $r): ?>
                <tr class="<?php echo $r['critical']?'swps-row-critical':'swps-row-warning'; ?>">
                    <td><code><?php echo esc_html($r['file']); ?></code></td>
                    <td><?php foreach($r['findings'] as $f): ?><span class="swps-badge <?php echo $f['severity']==='critical'?'swps-badge-critical':'swps-badge-warning'; ?>" style="margin-right:3px"><?php echo esc_html($f['sig_id']); ?></span><?php endforeach; ?></td>
                    <td><span class="swps-badge <?php echo $r['critical']?'swps-badge-critical':'swps-badge-warning'; ?>"><?php echo $r['critical']?'CRITICAL':'WARNING'; ?></span></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php else: ?>
            <div class="swps-notice swps-notice-ok" style="margin-top:12px">All scanned files are clean. No malware signatures detected.</div>
            <?php endif; ?>
            <p class="swps-muted" style="margin-top:8px">Last scan: <?php echo human_time_diff($dna['scanned_at']); ?> ago</p>
            <?php endif; ?>
        </div>
    </div>
</div>

<script>
jQuery(document).ready(function($){
    // Tabs
    $('.swps-tab').on('click',function(){$('.swps-tab').removeClass('swps-tab-active');$('.swps-tab-content').removeClass('swps-tab-active');$(this).addClass('swps-tab-active');$('#tab-'+$(this).data('tab')).addClass('swps-tab-active');});

    // Honeypot
    $('#swps-hp-add').on('click',function(){
        var slug=$('#swps-hp-new-trap').val().replace(/^\//,'');if(!slug)return;
        $.post(ajaxurl,{action:'swps_honeypot_add',nonce:swps_vars.nonce,slug:slug},function(r){if(r.success)location.reload();});
    });
    $(document).on('click','.swps-hp-remove',function(){
        var slug=$(this).data('slug');
        $.post(ajaxurl,{action:'swps_honeypot_remove',nonce:swps_vars.nonce,slug:slug},function(r){if(r.success)location.reload();});
    });
    $('#swps-hp-clear').on('click',function(){if(!confirm('Clear honeypot log?'))return;$.post(ajaxurl,{action:'swps_honeypot_clear',nonce:swps_vars.nonce},function(r){if(r.success)location.reload();});});
    $('#swps-fl-clear').on('click',function(){if(!confirm('Clear fake login log?'))return;$.post(ajaxurl,{action:'swps_fake_login_clear',nonce:swps_vars.nonce},function(r){if(r.success)location.reload();});});
    $('#swps-rl-clear').on('click',function(){if(!confirm('Clear rate limit event log?'))return;$.post(ajaxurl,{action:'swps_rate_limit_clear',nonce:swps_vars.nonce},function(r){if(r.success)location.reload();});});

    // Reputation
    $('#swps-rep-lookup').on('click',function(){
        var ip=$('#swps-rep-lookup-ip').val().trim();if(!ip)return;
        $.post(ajaxurl,{action:'swps_rep_lookup',nonce:swps_vars.nonce,ip:ip},function(r){
            if(r.success){var d=r.data;$('#swps-rep-result').html('<div class="swps-notice swps-notice-warning">IP: '+d.ip+' | Score: '+d.score+'/100 | '+JSON.stringify(d.label||d)+'</div>');}
        });
    });
    $(document).on('click','.swps-rep-reset',function(){$.post(ajaxurl,{action:'swps_rep_reset',nonce:swps_vars.nonce,ip:$(this).data('ip')},function(r){if(r.success)location.reload();});});
    $(document).on('click','.swps-rep-block',function(){$.post(ajaxurl,{action:'swps_rep_manual_block',nonce:swps_vars.nonce,ip:$(this).data('ip')},function(r){if(r.success)location.reload();});});

    // Canary
    $('#swps-canary-create').on('click',function(){
        var name=prompt('Token name (e.g. "Homepage content"):');if(!name)return;
        var desc=prompt('Description (optional):');
        $.post(ajaxurl,{action:'swps_canary_create',nonce:swps_vars.nonce,name:name,description:desc||''},function(r){if(r.success)location.reload();});
    });
    $(document).on('click','.swps-canary-delete',function(){if(!confirm('Delete this canary token?'))return;$.post(ajaxurl,{action:'swps_canary_delete',nonce:swps_vars.nonce,id:$(this).data('id')},function(r){if(r.success)location.reload();});});

    // DNA Scanner
    $('#swps-dna-scan').on('click',function(){
        var $btn=$(this).prop('disabled',true).text('Scanning… (this may take a minute)');
        $.post(ajaxurl,{action:'swps_dna_scan',nonce:swps_vars.nonce},function(r){
            $btn.prop('disabled',false).text('Scan Now');
            if(r.success)location.reload();
            else $('#swps-dna-result').html('<div class="swps-notice swps-notice-critical">'+(r.data||'Error')+'</div>');
        });
    });
});
</script>
