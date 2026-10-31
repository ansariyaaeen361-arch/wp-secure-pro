<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-networking"></span> Multi-Site Monitor</h1>
    <p class="description" style="margin:-8px 0 16px;max-width:760px">
        Watch the security of several WordPress sites from one dashboard. Each site reports its status
        here, so you can keep an eye on all of them in one place.
    </p>

    <?php
    $settings  = get_option('swps_settings', array());
    $sites_data= SWPS_Multisite_Monitor::get_sites_data();
    $sites_cfg = get_option(SWPS_Multisite_Monitor::SITES_OPT, array());
    $online    = count(array_filter($sites_data, fn($s) => ($s['status']??'') === 'online'));
    $offline   = count($sites_data) - $online;
    ?>

    <div class="swps-stats-grid">
        <div class="swps-stat-card">
            <div class="swps-stat-num"><?php echo count($sites_data); ?></div>
            <div class="swps-stat-label">Sites Monitored</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-green"><?php echo $online; ?></div>
            <div class="swps-stat-label">Online</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-red"><?php echo $offline; ?></div>
            <div class="swps-stat-label">Offline / No Data</div>
        </div>
    </div>

    <div class="swps-tabs">
        <button class="swps-tab swps-tab-active" data-tab="hub">Hub Mode (Monitor Others)</button>
        <button class="swps-tab" data-tab="agent">Agent Mode (Push to Hub)</button>
        <button class="swps-tab" data-tab="feed">Threat Feed Server</button>
        <button class="swps-tab" data-tab="siem">SIEM Export</button>
    </div>

    <!-- Hub Mode -->
    <div class="swps-tab-content swps-tab-active" id="tab-hub">
        <div class="swps-card">
            <div class="swps-card-header">
                <h2>Monitored Sites</h2>
                <div class="swps-card-actions">
                    <button id="swps-ms-poll-now" class="button button-primary">Poll All Now</button>
                </div>
            </div>
            <form method="post" action="options.php" style="margin-bottom:16px">
                <?php settings_fields('swps_settings_group'); ?>
                <table class="form-table swps-form-table">
                    <tr>
                        <th>Enable Hub Mode</th>
                        <td><label class="swps-toggle"><input type="checkbox" name="swps_settings[ms_hub_enabled]" value="1" <?php checked(!empty($settings['ms_hub_enabled'])); ?>><span class="swps-slider"></span></label> Poll agent sites hourly</td>
                    </tr>
                    <tr>
                        <th>Hub Secret Token</th>
                        <td>
                            <input type="text" name="swps_settings[ms_hub_secret]" value="<?php echo esc_attr($settings['ms_hub_secret'] ?? ''); ?>" class="regular-text" placeholder="Generate a random secret">
                            <p class="description">Agent sites must use this token in X-SWPS-Token header to push data here.</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Save Hub Settings', 'secondary', 'submit', false); ?>
            </form>

            <!-- Add site -->
            <h3>Add Remote Site</h3>
            <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">
                <input type="url" id="swps-ms-url" placeholder="https://site.com" class="regular-text">
                <input type="text" id="swps-ms-token" placeholder="Site token" class="regular-text">
                <input type="text" id="swps-ms-name" placeholder="Site name" style="width:150px">
                <button id="swps-ms-add" class="button button-primary">Add Site</button>
            </div>

            <?php if (!empty($sites_data)): ?>
            <table class="swps-table widefat striped">
                <thead><tr><th>Site</th><th>Status</th><th>Score</th><th>Blocked IPs</th><th>Threats 24h</th><th>SSL</th><th>Last Poll</th><th>Action</th></tr></thead>
                <tbody>
                <?php foreach ($sites_data as $s):
                    $score_color = ($s['score']??100) >= 80 ? 'swps-color-green' : (($s['score']??100) >= 50 ? 'swps-color-orange' : 'swps-color-red');
                ?>
                <tr>
                    <td>
                        <a href="<?php echo esc_url($s['site_url']??''); ?>" target="_blank"><strong><?php echo esc_html($s['site_name'] ?? $s['site_url']); ?></strong></a>
                        <div class="swps-muted" style="font-size:11px"><?php echo esc_html($s['site_url']??''); ?></div>
                    </td>
                    <td><span class="swps-badge <?php echo ($s['status']??'') === 'online' ? 'swps-badge-ok' : 'swps-badge-critical'; ?>"><?php echo strtoupper($s['status']??'unknown'); ?></span></td>
                    <td><span class="<?php echo $score_color; ?>"><strong><?php echo $s['score']??'—'; ?></strong>/100</span></td>
                    <td><?php echo $s['blocked_ips']??'—'; ?></td>
                    <td><?php echo $s['threats_24h']??'—'; ?></td>
                    <td><?php echo isset($s['ssl_days']) ? $s['ssl_days'].'d' : '—'; ?></td>
                    <td class="swps-muted"><?php echo !empty($s['last_poll']) ? human_time_diff($s['last_poll']).' ago' : '—'; ?></td>
                    <td><button class="button button-small button-link-delete swps-ms-remove" data-url="<?php echo esc_attr($s['site_url']??''); ?>">Remove</button></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php else: ?>
            <p class="swps-muted">No sites added yet. Add a site URL and token above to start monitoring.</p>
            <?php endif; ?>
        </div>
    </div>

    <!-- Agent Mode -->
    <div class="swps-tab-content" id="tab-agent">
        <div class="swps-card">
            <h2>Agent Mode — Push Status to Hub</h2>
            <p class="description">Configure this site to push its security status to a central hub running SecureWP Shield.</p>
            <form method="post" action="options.php">
                <?php settings_fields('swps_settings_group'); ?>
                <table class="form-table swps-form-table">
                    <tr>
                        <th>Hub URL</th>
                        <td>
                            <input type="url" name="swps_settings[ms_hub_url]" value="<?php echo esc_attr($settings['ms_hub_url'] ?? ''); ?>" class="regular-text" placeholder="https://hub-site.com">
                            <p class="description">The site running the hub. This site will push status to: <code>[hub]/wp-json/swps/v1/status</code></p>
                        </td>
                    </tr>
                    <tr>
                        <th>Agent Token</th>
                        <td>
                            <input type="text" name="swps_settings[ms_agent_token]" value="<?php echo esc_attr($settings['ms_agent_token'] ?? ''); ?>" class="regular-text">
                            <p class="description">Must match the Hub Secret Token configured on the hub site.</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Save Agent Settings'); ?>
            </form>
            <p>This site's REST endpoint (for hubs to poll): <code><?php echo get_rest_url(null, 'swps/v1/status'); ?></code></p>
        </div>
    </div>

    <!-- Threat Feed Server -->
    <div class="swps-tab-content" id="tab-feed">
        <?php $feed_cache = get_option('swps_threat_feed_cache', array()); ?>
        <div class="swps-card">
            <div class="swps-card-header">
                <h2>Own Threat Feed — <?php echo $feed_cache['count']??0; ?> IPs</h2>
                <button id="swps-feed-rebuild" class="button button-primary">Rebuild Feed</button>
            </div>
            <form method="post" action="options.php" style="margin-bottom:16px">
                <?php settings_fields('swps_settings_group'); ?>
                <table class="form-table swps-form-table">
                    <tr>
                        <th>Enable Threat Feed</th>
                        <td><label class="swps-toggle"><input type="checkbox" name="swps_settings[threat_feed_server_enabled]" value="1" <?php checked(!empty($settings['threat_feed_server_enabled'])); ?>><span class="swps-slider"></span></label> Publish your blocklist publicly</td>
                    </tr>
                    <tr>
                        <th>Minimum Reputation Score</th>
                        <td><input type="number" name="swps_settings[feed_min_score]" value="<?php echo esc_attr($settings['feed_min_score']??75); ?>" min="0" max="100" class="small-text"> Only include IPs with score ≥ this</td>
                    </tr>
                    <tr>
                        <th>Feed Token (optional)</th>
                        <td>
                            <input type="text" name="swps_settings[threat_feed_token]" value="<?php echo esc_attr($settings['threat_feed_token']??''); ?>" class="regular-text" placeholder="Leave empty for public feed">
                            <p class="description">Subscribers pass this in X-Feed-Token header or ?token= param.</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Save Feed Settings', 'secondary', 'submit', false); ?>
            </form>
            <?php if (!empty($settings['threat_feed_server_enabled'])): ?>
            <p><strong>Feed URLs:</strong><br>
            Plain text: <code><?php echo get_rest_url(null,'swps/v1/threat-feed'); ?></code><br>
            JSON: <code><?php echo get_rest_url(null,'swps/v1/threat-feed/json'); ?></code></p>
            <?php endif; ?>

            <h3 style="margin-top:16px">Subscribe to External Feed</h3>
            <div style="display:flex;gap:8px;margin-bottom:8px">
                <input type="url" id="swps-feed-subscribe-url" placeholder="https://otherfeed.com/wp-json/swps/v1/threat-feed" class="large-text">
                <button id="swps-feed-subscribe" class="button">Import Feed</button>
            </div>
            <div id="swps-feed-result"></div>
        </div>
    </div>

    <!-- SIEM -->
    <div class="swps-tab-content" id="tab-siem">
        <div class="swps-card">
            <h2>SIEM Integration</h2>
            <p class="description">Stream security events to Splunk, Elastic, Graylog, or any HTTP endpoint in real-time.</p>
            <form method="post" action="options.php">
                <?php settings_fields('swps_settings_group'); ?>
                <table class="form-table swps-form-table">
                    <tr><th>Enable SIEM</th><td><label class="swps-toggle"><input type="checkbox" name="swps_settings[siem_enabled]" value="1" <?php checked(!empty($settings['siem_enabled'])); ?>><span class="swps-slider"></span></label></td></tr>
                    <tr>
                        <th>HTTP Endpoint URL</th>
                        <td>
                            <input type="url" name="swps_settings[siem_http_url]" value="<?php echo esc_attr($settings['siem_http_url']??''); ?>" class="large-text" placeholder="https://splunk:8088/services/collector/event">
                            <p class="description">Splunk HEC, Elastic Logstash HTTP input, Graylog GELF HTTP, or any endpoint accepting JSON POST.</p>
                        </td>
                    </tr>
                    <tr>
                        <th>Auth Token</th>
                        <td><input type="text" name="swps_settings[siem_http_token]" value="<?php echo esc_attr($settings['siem_http_token']??''); ?>" class="regular-text" placeholder="Splunk HEC token / Bearer token"></td>
                    </tr>
                    <tr>
                        <th>Format</th>
                        <td>
                            <select name="swps_settings[siem_format]" class="swps-select">
                                <option value="json" <?php selected($settings['siem_format']??'json','json'); ?>>JSON (generic)</option>
                                <option value="splunk_hec" <?php selected($settings['siem_format']??'','splunk_hec'); ?>>Splunk HEC</option>
                                <option value="gelf" <?php selected($settings['siem_format']??'','gelf'); ?>>GELF (Graylog)</option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th>Syslog Host</th>
                        <td>
                            <input type="text" name="swps_settings[siem_syslog_host]" value="<?php echo esc_attr($settings['siem_syslog_host']??''); ?>" class="regular-text" placeholder="192.168.1.100">
                            <input type="number" name="swps_settings[siem_syslog_port]" value="<?php echo esc_attr($settings['siem_syslog_port']??514); ?>" class="small-text" placeholder="514"> port
                        </td>
                    </tr>
                    <tr>
                        <th>Local Log File</th>
                        <td>
                            <label class="swps-toggle"><input type="checkbox" name="swps_settings[siem_local_log]" value="1" <?php checked(!empty($settings['siem_local_log'])); ?>><span class="swps-slider"></span></label>
                            Write NDJSON log to <code><?php echo WP_CONTENT_DIR; ?>/swps-siem-logs/YYYY-MM-DD.ndjson</code>
                        </td>
                    </tr>
                </table>
                <div style="display:flex;gap:8px;margin:16px 0 0;flex-wrap:wrap">
                    <?php submit_button('Save SIEM Settings', 'secondary', 'submit', false); ?>
                    <button type="button" id="swps-siem-test" class="button">Send Test Event</button>
                    <a href="<?php echo admin_url('admin-ajax.php?action=swps_siem_export&nonce='.wp_create_nonce('swps_nonce')); ?>" class="button">Export NDJSON</a>
                </div>
            </form>
            <div id="swps-siem-result"></div>
        </div>
    </div>
</div>

<script>
jQuery(document).ready(function($){
    $('.swps-tab').on('click',function(){$('.swps-tab').removeClass('swps-tab-active');$('.swps-tab-content').removeClass('swps-tab-active');$(this).addClass('swps-tab-active');$('#tab-'+$(this).data('tab')).addClass('swps-tab-active');});

    // Multi-site
    $('#swps-ms-add').on('click',function(){
        var url=$('#swps-ms-url').val(),token=$('#swps-ms-token').val(),name=$('#swps-ms-name').val();
        if(!url){alert('Enter URL');return;}
        $.post(ajaxurl,{action:'swps_ms_add_site',nonce:swps_vars.nonce,url:url,token:token,name:name},function(r){if(r.success)location.reload();else alert(r.data);});
    });
    $('#swps-ms-poll-now').on('click',function(){
        var $btn=$(this).prop('disabled',true).text('Polling…');
        $.post(ajaxurl,{action:'swps_ms_poll_now',nonce:swps_vars.nonce},function(r){$btn.prop('disabled',false).text('Poll All Now');if(r.success)location.reload();});
    });
    $(document).on('click','.swps-ms-remove',function(){if(!confirm('Remove this site?'))return;$.post(ajaxurl,{action:'swps_ms_remove_site',nonce:swps_vars.nonce,url:$(this).data('url')},function(r){if(r.success)location.reload();});});

    // Feed
    $('#swps-feed-rebuild').on('click',function(){
        var $btn=$(this).prop('disabled',true).text('Building…');
        $.post(ajaxurl,{action:'swps_feed_rebuild',nonce:swps_vars.nonce},function(r){$btn.prop('disabled',false).text('Rebuild Feed');if(r.success){alert(r.data.count+' IPs in feed.');location.reload();}});
    });
    $('#swps-feed-subscribe').on('click',function(){
        var url=$('#swps-feed-subscribe-url').val();if(!url)return;
        var $btn=$(this).prop('disabled',true).text('Importing…');
        $.post(ajaxurl,{action:'swps_feed_subscribe',nonce:swps_vars.nonce,feed_url:url},function(r){
            $btn.prop('disabled',false).text('Import Feed');
            var cls=r.success?'swps-notice-ok':'swps-notice-critical';
            $('#swps-feed-result').html('<div class="swps-notice '+cls+'">'+(r.data||'Done')+'</div>');
        });
    });

    // SIEM test
    $('#swps-siem-test').on('click',function(){
        var $btn=$(this).prop('disabled',true).text('Sending…');
        $.post(ajaxurl,{action:'swps_siem_test',nonce:swps_vars.nonce},function(r){
            $btn.prop('disabled',false).text('Send Test Event');
            var cls=r.success?'swps-notice-ok':'swps-notice-critical';
            $('#swps-siem-result').html('<div class="swps-notice '+cls+'">'+(r.data||'Done')+'</div>');
        });
    });

    // DNA scan AJAX
    $('#swps-dna-scan').on('click',function(){
        var $btn=$(this).prop('disabled',true).text('Scanning…');
        $.post(ajaxurl,{action:'swps_dna_scan',nonce:swps_vars.nonce},function(r){$btn.prop('disabled',false).text('Scan Now');if(r.success)location.reload();});
    });
});
</script>
