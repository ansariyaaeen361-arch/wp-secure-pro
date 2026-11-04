<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-admin-generic"></span> Advanced Settings</h1>

    <?php
    $settings = get_option('swps_settings', array());
    $wl       = get_option('swps_white_label', array());
    ?>

    <div class="swps-tabs">
        <button class="swps-tab swps-tab-active" data-tab="captcha">CAPTCHA</button>
        <button class="swps-tab" data-tab="geoip">GeoIP Blocking</button>
        <button class="swps-tab" data-tab="away">Away Mode</button>
        <button class="swps-tab" data-tab="blacklist">Blacklist Monitor</button>
        <button class="swps-tab" data-tab="whitelabel">White Label</button>
        <button class="swps-tab" data-tab="export">Export / Import</button>
        <button class="swps-tab" data-tab="updates">Updates</button>
    </div>

    <!-- CAPTCHA -->
    <div class="swps-tab-content swps-tab-active" id="tab-captcha">
        <div class="swps-card">
            <h2>CAPTCHA (Spam & Bot Protection)</h2>
            <p class="description">CAPTCHA quietly checks that the people using your forms (login, sign-up, comments) are real humans, not bots — and blocks spam and automated attacks. This version is invisible: no puzzles or checkboxes for your visitors. <strong>You need free Google reCAPTCHA keys</strong> (get them from the link below) for it to work.</p>
            <form method="post" action="options.php">
                <?php settings_fields('swps_settings_group'); ?>
                <table class="form-table swps-form-table">
                    <tr>
                        <th>Enable CAPTCHA</th>
                        <td>
                            <label class="swps-toggle">
                                <input type="checkbox" name="swps_settings[captcha_enabled]" value="1" <?php checked(!empty($settings['captcha_enabled'])); ?>>
                                <span class="swps-slider"></span>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th>Site Key</th>
                        <td><input type="text" name="swps_settings[recaptcha_site_key]" value="<?php echo esc_attr($settings['recaptcha_site_key'] ?? ''); ?>" class="regular-text" placeholder="6Lc..."></td>
                    </tr>
                    <tr>
                        <th>Secret Key</th>
                        <td><input type="text" name="swps_settings[recaptcha_secret_key]" value="<?php echo esc_attr($settings['recaptcha_secret_key'] ?? ''); ?>" class="regular-text" placeholder="6Lc..."></td>
                    </tr>
                    <tr>
                        <th>Protect</th>
                        <td>
                            <?php
                            $on = (array)($settings['captcha_on'] ?? array());
                            $forms = array('login'=>'Login Form','register'=>'Registration Form','lost_password'=>'Lost Password','comments'=>'Comment Form');
                            foreach ($forms as $k => $label):
                            ?>
                            <label style="display:block;margin-bottom:6px">
                                <input type="checkbox" name="swps_settings[captcha_on][<?php echo $k; ?>]" value="1" <?php checked(!empty($on[$k])); ?>>
                                <?php echo esc_html($label); ?>
                            </label>
                            <?php endforeach; ?>
                        </td>
                    </tr>
                </table>
                <p class="description" style="margin:4px 0 16px">Get your free keys at <a href="https://www.google.com/recaptcha/admin/create" target="_blank">google.com/recaptcha</a> — choose reCAPTCHA v3.</p>
                <?php submit_button('Save CAPTCHA Settings'); ?>
            </form>
        </div>
    </div>

    <!-- GeoIP -->
    <div class="swps-tab-content" id="tab-geoip">
        <div class="swps-card">
            <h2>Country Blocking (GeoIP)</h2>
            <p class="description" style="margin-bottom:12px">Block or allow visitors based on which country they are in. Handy if most attacks come from regions you don't do business with. <strong>⚠️ Use with care</strong> — wrong settings can accidentally block real customers (or even you). Test after enabling.</p>
            <?php $db_status = SWPS_GeoIP::get_db_status(); ?>
            <div class="swps-info-row" style="margin-bottom:16px">
                <strong>Database:</strong>
                <?php if ($db_status['exists']): ?>
                <span class="swps-badge swps-badge-ok">MaxMind mmdb loaded (<?php echo $db_status['size']; ?>)</span>
                Last updated: <?php echo $db_status['last_updated']; ?>
                <?php else: ?>
                <span class="swps-badge swps-badge-warning">Using API fallback (ip-api.com)</span> — optional: upload MaxMind GeoLite2-Country.mmdb for better accuracy
                <?php endif; ?>
            </div>
            <form method="post" action="options.php">
                <?php settings_fields('swps_settings_group'); ?>
                <table class="form-table swps-form-table">
                    <tr>
                        <th>Enable GeoIP Blocking</th>
                        <td>
                            <label class="swps-toggle">
                                <input type="checkbox" name="swps_settings[geoip_enabled]" value="1" <?php checked(!empty($settings['geoip_enabled'])); ?>>
                                <span class="swps-slider"></span>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th>Mode</th>
                        <td>
                            <select name="swps_settings[geoip_mode]" class="swps-select">
                                <option value="block" <?php selected($settings['geoip_mode'] ?? 'block', 'block'); ?>>Block listed countries</option>
                                <option value="allow" <?php selected($settings['geoip_mode'] ?? 'block', 'allow'); ?>>Allow only listed countries</option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th>Countries</th>
                        <td>
                            <select name="swps_settings[geoip_countries][]" multiple class="swps-select-multi" size="8">
                                <?php
                                $selected_countries = array_filter(array_map('trim', explode(',', $settings['geoip_countries'] ?? '')));
                                foreach (SWPS_GeoIP::get_country_list() as $code => $name):
                                ?>
                                <option value="<?php echo $code; ?>" <?php echo in_array($code, $selected_countries) ? 'selected' : ''; ?>><?php echo esc_html("$code — $name"); ?></option>
                                <?php endforeach; ?>
                            </select>
                            <p class="description">Hold Ctrl/Cmd to select multiple countries.</p>
                        </td>
                    </tr>
                    <tr>
                        <th>Login/Admin Only</th>
                        <td>
                            <label class="swps-toggle">
                                <input type="checkbox" name="swps_settings[geoip_login_only]" value="1" <?php checked(!empty($settings['geoip_login_only'])); ?>>
                                <span class="swps-slider"></span>
                            </label> Only block access to wp-admin and wp-login (not full site)
                        </td>
                    </tr>
                    <tr>
                        <th>MaxMind License Key</th>
                        <td>
                            <input type="text" name="swps_settings[maxmind_license_key]" value="<?php echo esc_attr($settings['maxmind_license_key'] ?? ''); ?>" class="regular-text" placeholder="Free key from maxmind.com">
                            <p class="description">Free license key for GeoLite2 database auto-updates. Register at <a href="https://www.maxmind.com/en/geolite2/signup" target="_blank">maxmind.com</a>.</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Save GeoIP Settings'); ?>
            </form>
        </div>
    </div>

    <!-- Away Mode -->
    <div class="swps-tab-content" id="tab-away">
        <div class="swps-card">
            <h2>Away Mode (Lock Login by Time)</h2>
            <p class="description" style="margin-bottom:12px">Completely locks your WordPress login and admin area during hours you're not working (for example overnight), so no one can even attempt to log in then. <strong>⚠️ Set the correct timezone</strong> and hours, or you could lock yourself out.</p>
            <?php $away_status = SWPS_Away_Mode::get_current_status(); ?>
            <?php if ($away_status['enabled']): ?>
            <div class="swps-info-row">
                Current status: <strong><?php echo $away_status['locked'] ? 'LOCKED' : 'OPEN'; ?></strong> |
                Local time: <?php echo $away_status['local_time']; ?> |
                Admin locked: <?php echo $away_status['start']; ?> – <?php echo $away_status['end']; ?>
            </div>
            <?php endif; ?>
            <form method="post" action="options.php">
                <?php settings_fields('swps_settings_group'); ?>
                <table class="form-table swps-form-table">
                    <tr>
                        <th>Enable Away Mode</th>
                        <td>
                            <label class="swps-toggle">
                                <input type="checkbox" name="swps_settings[away_mode_enabled]" value="1" <?php checked(!empty($settings['away_mode_enabled'])); ?>>
                                <span class="swps-slider"></span>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th>Lock Start (hour)</th>
                        <td>
                            <input type="number" name="swps_settings[away_start]" value="<?php echo esc_attr($settings['away_start'] ?? 22); ?>" min="0" max="23" class="small-text"> (24h format, e.g. 22 = 10 PM)
                        </td>
                    </tr>
                    <tr>
                        <th>Lock End (hour)</th>
                        <td>
                            <input type="number" name="swps_settings[away_end]" value="<?php echo esc_attr($settings['away_end'] ?? 6); ?>" min="0" max="23" class="small-text"> (24h format, e.g. 6 = 6 AM)
                        </td>
                    </tr>
                    <tr>
                        <th>Timezone</th>
                        <td>
                            <?php
                            // wp_timezone_choice() returns OPTION tags only.  It must be
                            // enclosed in a SELECT; printing it directly makes every city
                            // render as page text and creates a huge admin-page scroll.
                            $away_timezone = $settings['away_timezone'] ?? get_option('timezone_string');
                            ?>
                            <select id="swps-away-timezone" name="swps_settings[away_timezone]" class="swps-select swps-timezone-select">
                                <?php echo wp_timezone_choice( $away_timezone ); ?>
                            </select>
                            <p class="description">Choose the timezone used for the login lock schedule. You can type a city name while this dropdown is focused to jump to it.</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Save Away Mode Settings'); ?>
            </form>
        </div>
    </div>

    <!-- Blacklist Monitor -->
    <div class="swps-tab-content" id="tab-blacklist">
        <div class="swps-card">
            <h2>Blacklist Monitor</h2>
            <p class="description" style="margin-bottom:12px">Checks whether your site has been flagged as unsafe or spammy by Google and other security services. If you ever get listed, you'll know right away so you can clean up and request removal — before it hurts your traffic.</p>
            <?php
            $bl_results = get_option('swps_blacklist_last_check', array());
            $any_listed = SWPS_Blacklist_Monitor::is_any_blacklisted($bl_results);
            ?>
            <?php if (!empty($bl_results['checked_at'])): ?>
            <p class="swps-muted">Last checked: <?php echo human_time_diff($bl_results['checked_at']); ?> ago</p>
            <?php endif; ?>
            <?php if ($any_listed): ?>
            <div class="swps-notice swps-notice-critical">Your site is listed on one or more blacklists! Take action immediately.</div>
            <?php elseif (!empty($bl_results)): ?>
            <div class="swps-notice swps-notice-ok">Your site is not blacklisted.</div>
            <?php endif; ?>

            <button id="swps-check-blacklist" class="button button-primary" style="margin:12px 0">Check Now</button>

            <?php if (!empty($bl_results) && is_array($bl_results)): ?>
            <table class="swps-table widefat striped" style="margin-top:8px">
                <thead><tr><th>Service</th><th>Status</th><th>Note</th></tr></thead>
                <tbody>
                <?php foreach ($bl_results as $key => $data):
                    if (!is_array($data)) continue;
                ?>
                <tr>
                    <td><?php echo esc_html($data['name'] ?? $key); ?></td>
                    <td>
                        <?php if ($data['listed'] === true): ?>
                        <span class="swps-badge swps-badge-critical">LISTED</span>
                        <?php elseif ($data['listed'] === false): ?>
                        <span class="swps-badge swps-badge-ok">Clean</span>
                        <?php else: ?>
                        <span class="swps-badge swps-badge-warning">Unknown</span>
                        <?php endif; ?>
                    </td>
                    <td><?php echo esc_html($data['note'] ?? ''); ?></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>

            <form method="post" action="options.php" style="margin-top:16px">
                <?php settings_fields('swps_settings_group'); ?>
                <table class="form-table swps-form-table">
                    <tr>
                        <th>Auto-check Daily</th>
                        <td>
                            <label class="swps-toggle">
                                <input type="checkbox" name="swps_settings[blacklist_monitor_enabled]" value="1" <?php checked(!empty($settings['blacklist_monitor_enabled'])); ?>>
                                <span class="swps-slider"></span>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th>Google Safe Browsing API Key</th>
                        <td>
                            <input type="text" name="swps_settings[gsb_api_key]" value="<?php echo esc_attr($settings['gsb_api_key'] ?? ''); ?>" class="regular-text">
                            <p class="description">Optional — free from Google Cloud Console. Enables accurate GSB checks.</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Save Blacklist Settings'); ?>
            </form>
        </div>
    </div>

    <!-- White Label -->
    <div class="swps-tab-content" id="tab-whitelabel">
        <div class="swps-card">
            <h2>White Label / Client Mode</h2>
            <p class="description">Rebrand the plugin for clients. Hide the WP Secure Pro name and use your own agency branding.</p>
            <form method="post" action="">
                <?php wp_nonce_field('swps_save_whitelabel', 'swps_wl_nonce'); ?>
                <table class="form-table swps-form-table">
                    <tr>
                        <th>Enable White Label</th>
                        <td>
                            <label class="swps-toggle">
                                <input type="checkbox" name="swps_white_label[enabled]" value="1" <?php checked(!empty($wl['enabled'])); ?>>
                                <span class="swps-slider"></span>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th>Company/Brand Name</th>
                        <td><input type="text" name="swps_white_label[company_name]" value="<?php echo esc_attr($wl['company_name'] ?? ''); ?>" class="regular-text" placeholder="My Security Suite"></td>
                    </tr>
                    <tr>
                        <th>Admin Menu Name</th>
                        <td><input type="text" name="swps_white_label[menu_name]" value="<?php echo esc_attr($wl['menu_name'] ?? ''); ?>" class="regular-text" placeholder="Site Security"></td>
                    </tr>
                    <tr>
                        <th>Logo URL</th>
                        <td><input type="url" name="swps_white_label[logo_url]" value="<?php echo esc_attr($wl['logo_url'] ?? ''); ?>" class="regular-text" placeholder="https://..."></td>
                    </tr>
                    <tr>
                        <th>Accent Color</th>
                        <td><input type="color" name="swps_white_label[accent_color]" value="<?php echo esc_attr($wl['accent_color'] ?? '#2563eb'); ?>"></td>
                    </tr>
                    <tr>
                        <th>Hide Plugin in List</th>
                        <td>
                            <label class="swps-toggle">
                                <input type="checkbox" name="swps_white_label[hide_plugin]" value="1" <?php checked(!empty($wl['hide_plugin'])); ?>>
                                <span class="swps-slider"></span>
                            </label> Hide from Plugins page (clients won't see the plugin name)
                        </td>
                    </tr>
                </table>
                <?php submit_button('Save White Label Settings'); ?>
            </form>

            <hr style="margin:24px 0">
            <h2>Generate Client Security Report</h2>
            <p>Create a branded PDF-ready security report for your client.</p>
            <a href="<?php echo esc_url(admin_url('admin-ajax.php?action=swps_generate_report&nonce=' . wp_create_nonce('swps_nonce'))); ?>" class="button button-primary" target="_blank">
                Generate Report
            </a>
        </div>
    </div>
    <!-- Export / Import -->
    <div class="swps-tab-content" id="tab-export">
        <div class="swps-card">
            <h2>Export Settings</h2>
            <p class="description">Download all plugin settings as a JSON file. Sensitive API keys are excluded from the export.</p>
            <a href="<?php echo esc_url(admin_url('admin-ajax.php?action=swps_export_settings&nonce=' . wp_create_nonce('swps_nonce'))); ?>" class="button button-primary">
                Download Settings JSON
            </a>
        </div>

        <div class="swps-card">
            <h2>Import Settings</h2>
            <p class="description">Restore settings from a previously exported JSON file. This will overwrite your current settings (except API keys).</p>
            <form id="swps-import-form" enctype="multipart/form-data">
                <div style="display:flex;gap:10px;align-items:center">
                    <input type="file" id="swps-import-file" accept=".json" class="regular-text">
                    <button type="button" id="swps-import-btn" class="button button-primary">Import Settings</button>
                </div>
                <div id="swps-import-result" style="margin-top:10px"></div>
            </form>
        </div>

        <div class="swps-card">
            <h2>Reset Settings</h2>
            <div class="swps-notice swps-notice-warning">
                <strong>Warning:</strong> This will delete ALL plugin settings and return to defaults. This cannot be undone.
            </div>
            <button id="swps-reset-settings" class="button button-link-delete" style="margin-top:12px">Reset All Settings to Default</button>
        </div>
    </div>

    <!-- Updates -->
    <div class="swps-tab-content" id="tab-updates">
        <div class="swps-card">
            <h2>Plugin Updates (Self-Hosted via GitHub)</h2>
            <p class="description">
                This plugin checks the public GitHub repository for signed releases and shows an
                "Update available" notice on the normal Plugins page — same one-click update
                as a WordPress.org plugin, just pointed at your own repo instead.
                Repo: <code>github.com/<?php echo esc_html( SWPS_GitHub_Updater::GITHUB_USER ); ?>/<?php echo esc_html( SWPS_GitHub_Updater::GITHUB_REPO ); ?></code>
                (public; no access token is required).
            </p>
            <form method="post" action="options.php">
                <?php settings_fields('swps_settings_group'); ?>
                <table class="form-table swps-form-table">
                    <tr>
                        <th>Trusted Proxy IPs</th>
                        <td>
                            <input type="text" name="swps_settings[trusted_proxy_ips]" value="<?php echo esc_attr($settings['trusted_proxy_ips'] ?? ''); ?>" class="regular-text" autocomplete="off" placeholder="203.0.113.10, 203.0.113.11">
                            <p class="description">Only add exact IPs of your reverse proxy or CDN. Forwarded visitor-IP headers are ignored unless the immediate connection comes from one of these IPs.</p>
                        </td>
                    </tr>
                    <tr>
                        <th>Check for Update Now</th>
                        <td>
                            <button type="button" id="swps-check-update-btn" class="button">Check Now</button>
                            <span id="swps-check-update-result" style="margin-left:8px"></span>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Save Update Settings'); ?>
            </form>
        </div>
    </div>
</div>

<script>
jQuery(document).ready(function($) {
    // Tab switching
    $('.swps-tab').on('click', function() {
        $('.swps-tab').removeClass('swps-tab-active');
        $('.swps-tab-content').removeClass('swps-tab-active');
        $(this).addClass('swps-tab-active');
        $('#tab-' + $(this).data('tab')).addClass('swps-tab-active');
    });

    // Blacklist check
    $('#swps-check-blacklist').on('click', function() {
        var $btn = $(this).prop('disabled', true).text('Checking...');
        $.post(ajaxurl, { action: 'swps_check_blacklist', nonce: swps_vars.nonce }, function(res) {
            $btn.prop('disabled', false).text('Check Now');
            if (res.success) location.reload();
        });
    });

    // Import
    $('#swps-import-btn').on('click', function() {
        var file = $('#swps-import-file')[0].files[0];
        if (!file) { alert('Please select a JSON file.'); return; }
        if (!confirm('Import will overwrite your current settings. Continue?')) return;
        var form = new FormData();
        form.append('action', 'swps_import_settings');
        form.append('nonce', swps_vars.nonce);
        form.append('import_file', file);
        $.ajax({url:ajaxurl, type:'POST', data:form, processData:false, contentType:false, success:function(res) {
            var cls = res.success ? 'swps-notice-ok' : 'swps-notice-critical';
            $('#swps-import-result').html('<div class="swps-notice '+cls+'">'+(res.data||'Done')+'</div>');
        }});
    });

    // Reset
    $('#swps-reset-settings').on('click', function() {
        if (!confirm('RESET ALL SETTINGS? This cannot be undone.')) return;
        if (!confirm('Are you absolutely sure?')) return;
        $.post(ajaxurl, {action:'swps_reset_settings', nonce:swps_vars.nonce}, function(res) {
            if (res.success) { alert(res.data); location.reload(); }
            else alert('Error: ' + res.data);
        });
    });

    // Check for update now
    $('#swps-check-update-btn').on('click', function() {
        var $btn = $(this).prop('disabled', true).text('Checking…');
        var $result = $('#swps-check-update-result');
        $.post(ajaxurl, { action: 'swps_check_github_update', nonce: swps_vars.nonce }, function(res) {
            $btn.prop('disabled', false).text('Check Now');
            $result.text(res.success ? res.data : ('Error: ' + res.data)).css('color', res.success ? '#16a34a' : '#dc2626');
        }).fail(function() {
            $btn.prop('disabled', false).text('Check Now');
            $result.text('Request failed.').css('color', '#dc2626');
        });
    });

    // GeoIP multi-select → convert to comma-separated hidden field
    $('form').on('submit', function() {
        var $select = $(this).find('select[name="swps_settings[geoip_countries][]"]');
        if ($select.length) {
            var values = $select.val() ? $select.val().join(',') : '';
            $(this).append('<input type="hidden" name="swps_settings[geoip_countries]" value="' + values + '">');
            $select.prop('disabled', true);
        }
    });

});
</script>

<?php
// Handle white label save
if (isset($_POST['swps_wl_nonce']) && wp_verify_nonce($_POST['swps_wl_nonce'], 'swps_save_whitelabel')) {
    $wl_new = array(
        'enabled'      => ! empty($_POST['swps_white_label']['enabled']) ? 1 : 0,
        'company_name' => sanitize_text_field($_POST['swps_white_label']['company_name'] ?? ''),
        'menu_name'    => sanitize_text_field($_POST['swps_white_label']['menu_name'] ?? ''),
        'logo_url'     => esc_url_raw($_POST['swps_white_label']['logo_url'] ?? ''),
        'accent_color' => sanitize_hex_color($_POST['swps_white_label']['accent_color'] ?? '#2563eb'),
        'hide_plugin'  => ! empty($_POST['swps_white_label']['hide_plugin']) ? 1 : 0,
    );
    update_option('swps_white_label', $wl_new);
    echo '<div class="notice notice-success is-dismissible"><p>White label settings saved.</p></div>';
}

// AJAX report generation
add_action('wp_ajax_swps_generate_report', function() {
    check_ajax_referer('swps_nonce', 'nonce');
    if (! current_user_can('manage_options')) wp_die('Unauthorized');
    echo SWPS_White_Label::generate_report();
    exit;
});
?>
