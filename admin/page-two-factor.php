<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-lock"></span> Two-Factor Authentication (2FA)</h1>
    <p class="description" style="margin:-8px 0 16px;max-width:760px">
        2FA adds a second lock to your logins. After entering the password, the user must also
        type a one-time code — sent to their email, or from a free app like Google Authenticator.
        So even if someone steals a password, they still can't get in without the code.
        <strong>Tip:</strong> the app (TOTP) method is the most reliable; email codes need your site to be able to send mail.
    </p>

    <?php
    $settings  = get_option('swps_settings', array());
    $enabled   = ! empty($settings['two_factor_enabled']);
    $require   = $settings['2fa_require_for'] ?? array();
    $admins    = get_users(array('role' => 'administrator'));
    ?>

    <div class="swps-status-bar <?php echo $enabled ? 'swps-status-active' : 'swps-status-inactive'; ?>">
        <span class="dashicons dashicons-lock"></span>
        Two-Factor Authentication is <strong><?php echo $enabled ? 'ENABLED' : 'DISABLED'; ?></strong>
    </div>

    <!-- Global 2FA Settings -->
    <div class="swps-card">
        <h2>2FA Settings</h2>
        <form method="post" action="options.php">
            <?php settings_fields('swps_settings_group'); ?>
            <table class="form-table swps-form-table">
                <tr>
                    <th>Enable 2FA</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_settings[two_factor_enabled]" value="1" <?php checked($enabled); ?>>
                            <span class="swps-slider"></span>
                        </label>
                        Require two-factor authentication for WordPress logins
                    </td>
                </tr>
                <tr>
                    <th>Require 2FA For</th>
                    <td>
                        <?php
                        $roles = array('administrator'=>'Administrators','editor'=>'Editors','author'=>'Authors','contributor'=>'Contributors','subscriber'=>'Subscribers');
                        foreach ($roles as $role => $label):
                            $chk = in_array($role, (array)$require);
                        ?>
                        <label style="display:block;margin-bottom:6px">
                            <input type="checkbox" name="swps_settings[2fa_require_for][]" value="<?php echo $role; ?>" <?php checked($chk); ?>>
                            <?php echo esc_html($label); ?><?php if ( $role === 'administrator' ): ?> <strong>(enabled by default)</strong><?php endif; ?>
                        </label>
                        <?php endforeach; ?>
                        <p class="description">Users in these roles MUST set up 2FA before accessing admin.</p>
                    </td>
                </tr>
                <tr>
                    <th>Default Method</th>
                    <td>
                        <select name="swps_settings[2fa_default_method]" class="swps-select">
                            <option value="email" <?php selected($settings['2fa_default_method'] ?? 'email', 'email'); ?>>Email OTP (6-digit code)</option>
                            <option value="totp"  <?php selected($settings['2fa_default_method'] ?? 'email', 'totp'); ?>>TOTP App (Google Authenticator, Authy)</option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <th>Remember Device</th>
                    <td>
                        <input type="number" name="swps_settings[2fa_remember_days]" value="<?php echo esc_attr($settings['2fa_remember_days'] ?? 30); ?>" min="0" max="365" class="small-text"> days
                        <p class="description">0 = never remember. Trusted devices skip 2FA for this many days.</p>
                    </td>
                </tr>
            </table>
            <?php submit_button('Save 2FA Settings'); ?>
        </form>
    </div>

    <!-- Admin Users 2FA Status -->
    <div class="swps-card">
        <h2>Admin Users — 2FA Status</h2>
        <table class="swps-table widefat striped">
            <thead>
                <tr><th>User</th><th>Email</th><th>2FA Enabled</th><th>Method</th><th>Setup</th></tr>
            </thead>
            <tbody>
            <?php foreach ($admins as $user):
                $fa_enabled = SWPS_Two_Factor::is_enabled_for_user($user->ID);
                $fa_method  = get_user_meta($user->ID, '_swps_2fa_method', true) ?: 'email';
                $edit_url   = get_edit_user_link($user->ID);
            ?>
            <tr>
                <td><strong><?php echo esc_html($user->display_name); ?></strong> <code><?php echo esc_html($user->user_login); ?></code></td>
                <td><?php echo esc_html($user->user_email); ?></td>
                <td>
                    <?php if ($fa_enabled): ?>
                    <span class="swps-badge swps-badge-ok">Enabled</span>
                    <?php else: ?>
                    <span class="swps-badge swps-badge-critical">Not Set Up</span>
                    <?php endif; ?>
                </td>
                <td><?php echo $fa_enabled ? esc_html(strtoupper($fa_method)) : '—'; ?></td>
                <td><a href="<?php echo esc_url($edit_url . '#swps-2fa-section'); ?>" class="button button-small">Configure</a></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <p class="description" style="margin-top:12px">Users configure their 2FA method from their own profile page (Users → Your Profile → Two-Factor Authentication section).</p>
    </div>

    <!-- How It Works -->
    <div class="swps-card swps-card-info">
        <h2>How 2FA Works</h2>
        <div class="swps-two-col">
            <div>
                <h3>Email OTP</h3>
                <p>After entering their password, the user receives a 6-digit code by email. The code expires in 5 minutes.</p>
            </div>
            <div>
                <h3>TOTP App (Google Authenticator)</h3>
                <p>User scans a QR code in their profile once. Afterwards they enter a 6-digit time-based code from their phone app. Works offline.</p>
            </div>
        </div>
    </div>
</div>
