<?php if ( ! defined('ABSPATH') ) exit; ?>
<?php
if ( isset($_POST['swps_save_settings']) && check_admin_referer('swps_settings_nonce') ) {
    // Merge into existing settings — do NOT overwrite the whole array,
    // otherwise WAF / 2FA / Captcha / Headers etc. config gets wiped.
    $existing = get_option('swps_settings', array());
    $settings = array_merge( $existing, array(
        'max_login_attempts'   => intval($_POST['max_login_attempts'] ?? 5),
        'lockout_duration'     => intval($_POST['lockout_duration'] ?? 30),
        'alert_email'          => sanitize_email($_POST['alert_email'] ?? ''),
        'email_alerts'         => isset($_POST['email_alerts']) ? 1 : 0,
        'alert_new_admin'      => isset($_POST['alert_new_admin']) ? 1 : 0,
        'alert_login_fail'     => isset($_POST['alert_login_fail']) ? 1 : 0,
        'alert_file_change'    => isset($_POST['alert_file_change']) ? 1 : 0,
        'file_monitor_enabled' => isset($_POST['file_monitor_enabled']) ? 1 : 0,
    ) );
    update_option('swps_settings', $settings);
    echo '<div class="notice notice-success"><p>✓ Settings saved successfully.</p></div>';
}

// Test email
if ( isset($_POST['swps_test_email']) && check_admin_referer('swps_settings_nonce') ) {
    SWPS_Email_Alerts::send_alert(
        'Test Alert - WP Secure Pro',
        "This is a test email from WP Secure Pro.\n\nIf you received this, email alerts are working correctly.\n\nSite: " . get_site_url()
    );
    echo '<div class="notice notice-success"><p>Test email sent to ' . esc_html(get_option('admin_email')) . '</p></div>';
}

$settings = get_option('swps_settings', array());
$defaults = array('max_login_attempts'=>5,'lockout_duration'=>30,'alert_email'=>get_option('admin_email'),'email_alerts'=>1,'alert_new_admin'=>1,'alert_login_fail'=>1,'alert_file_change'=>1,'file_monitor_enabled'=>1);
$settings = wp_parse_args($settings, $defaults);
?>
<div class="wrap swps-wrap">
    <div class="swps-header">
        <span class="dashicons dashicons-admin-settings swps-logo-icon"></span>
        <h1>Settings</h1>
    </div>

    <form method="post">
        <?php wp_nonce_field('swps_settings_nonce'); ?>

        <div class="swps-grid-2col">
            <!-- Login Protection Settings -->
            <div class="swps-card">
                <div class="swps-card-header"><span class="dashicons dashicons-lock"></span> Login Protection</div>
                <div class="swps-card-body">
                    <table class="form-table">
                        <tr>
                            <th>Max Login Attempts</th>
                            <td>
                                <input type="number" name="max_login_attempts" value="<?php echo intval($settings['max_login_attempts']); ?>" min="1" max="20" class="small-text">
                                <p class="description">Number of failed attempts before IP is blocked. (Default: 5)</p>
                            </td>
                        </tr>
                        <tr>
                            <th>Lockout Duration</th>
                            <td>
                                <input type="number" name="lockout_duration" value="<?php echo intval($settings['lockout_duration']); ?>" min="5" max="1440" class="small-text"> minutes
                                <p class="description">How long to block the IP after failed attempts. (Default: 30 min)</p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Email Alert Settings -->
            <div class="swps-card">
                <div class="swps-card-header"><span class="dashicons dashicons-email"></span> Email Alerts</div>
                <div class="swps-card-body">
                    <table class="form-table">
                        <tr>
                            <th>Email Alerts</th>
                            <td>
                                <label><input type="checkbox" name="email_alerts" <?php checked($settings['email_alerts'],1); ?>> Enable email security alerts</label>
                            </td>
                        </tr>
                        <tr>
                            <th>Alert Email</th>
                            <td>
                                <input type="email" name="alert_email" value="<?php echo esc_attr($settings['alert_email']); ?>" class="regular-text">
                                <p class="description">Email address to receive security alerts.</p>
                            </td>
                        </tr>
                        <tr>
                            <th>Alert Types</th>
                            <td>
                                <label><input type="checkbox" name="alert_new_admin" <?php checked($settings['alert_new_admin'],1); ?>> New/Unknown admin user created</label><br>
                                <label><input type="checkbox" name="alert_login_fail" <?php checked($settings['alert_login_fail'],1); ?>> Too many failed logins / IP blocked</label><br>
                                <label><input type="checkbox" name="alert_file_change" <?php checked($settings['alert_file_change'],1); ?>> Malware/threats detected in scan</label>
                            </td>
                        </tr>
                    </table>
                    <button type="submit" name="swps_test_email" class="swps-btn" style="margin-top:10px">Send Test Email</button>
                </div>
            </div>

            <!-- Scanner Settings -->
            <div class="swps-card">
                <div class="swps-card-header"><span class="dashicons dashicons-search"></span> File Monitor</div>
                <div class="swps-card-body">
                    <table class="form-table">
                        <tr>
                            <th>File Monitor</th>
                            <td>
                                <label><input type="checkbox" name="file_monitor_enabled" <?php checked($settings['file_monitor_enabled'],1); ?>> Enable file integrity monitoring</label>
                                <p class="description">Monitors wp-content for suspicious PHP files.</p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Admin Monitor Info -->
            <div class="swps-card">
                <div class="swps-card-header"><span class="dashicons dashicons-admin-users"></span> Admin Monitor</div>
                <div class="swps-card-body">
                    <p>✅ Admin user monitoring is <strong>always active</strong>.</p>
                    <p>You will be alerted immediately when:</p>
                    <ul class="swps-list">
                        <li>A new administrator account is created</li>
                        <li>A user is promoted to administrator</li>
                        <li>An unknown admin is detected (database injection)</li>
                    </ul>
                    <?php $known = get_option('swps_known_admins', array()); ?>
                    <p><strong>Known admins registered:</strong> <?php echo count($known); ?></p>
                    <button type="button" id="swps-reset-admins" class="swps-btn-sm">Reset Known Admins List</button>
                </div>
            </div>
        </div>

        <div style="margin-top:20px">
            <input type="hidden" name="swps_save_settings" value="1">
            <button type="submit" class="swps-btn swps-btn-primary" style="font-size:16px;padding:10px 30px">
                💾 Save All Settings
            </button>
        </div>
    </form>
</div>

<script>
document.getElementById('swps-reset-admins') && document.getElementById('swps-reset-admins').addEventListener('click', function() {
    if (!confirm('Reset known admins list? All current admins will be re-learned on next page load.')) return;
    jQuery.post(swps_vars.url, {action:'swps_reset_known_admins', nonce: swps_vars.nonce}, function(res) {
        alert((res && res.data && res.data.message) ? res.data.message : 'Known admins list reset.');
        location.reload();
    });
});
</script>
