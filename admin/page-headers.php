<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-admin-network"></span> Security Headers</h1>
    <p class="description" style="margin:-8px 0 16px;max-width:760px">
        Security headers are extra safety instructions your site sends to each visitor's browser.
        They help stop common tricks like clickjacking, script injection and file-type abuse.
        The defaults below are safe for most sites — just keep them ON.
    </p>

    <?php
    $saved    = get_option('swps_headers', array());
    $defaults = SWPS_Security_Headers::get_defaults();
    $headers  = wp_parse_args($saved, $defaults);
    $test     = get_transient('swps_header_test');
    $score    = $test ? SWPS_Security_Headers::get_score($test) : null;
    $settings = get_option('swps_settings', array());
    $enabled  = ! empty($settings['security_headers_enabled']);
    ?>

    <div class="swps-status-bar <?php echo $enabled ? 'swps-status-active' : 'swps-status-inactive'; ?>">
        <span class="dashicons dashicons-admin-network"></span>
        Security Headers are <strong><?php echo $enabled ? 'ENABLED' : 'DISABLED'; ?></strong>
        <?php if ($score !== null): ?>
        &nbsp;|&nbsp; Header Score: <strong><?php echo $score; ?>%</strong>
        <?php endif; ?>
    </div>

    <!-- Test Results -->
    <?php if ($test): ?>
    <div class="swps-card">
        <h2>Live Header Test Results</h2>
        <table class="swps-table widefat striped">
            <thead><tr><th>Header</th><th>Status</th><th>Value</th></tr></thead>
            <tbody>
            <?php foreach ($test as $row): ?>
            <tr>
                <td><strong><?php echo esc_html($row['header']); ?></strong></td>
                <td>
                    <?php if ($row['present']): ?>
                    <span class="swps-badge swps-badge-ok">Present</span>
                    <?php else: ?>
                    <span class="swps-badge swps-badge-critical">Missing</span>
                    <?php endif; ?>
                </td>
                <td><code><?php echo esc_html(substr($row['value'], 0, 80)); ?></code></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <button id="swps-test-headers-btn" class="button" style="margin-top:12px">Re-test Headers</button>
    </div>
    <?php else: ?>
    <div class="swps-card">
        <h2>Test Your Headers</h2>
        <p>Run a live check to see which security headers your site is currently sending.</p>
        <button id="swps-test-headers-btn" class="button button-primary">Test Headers Now</button>
    </div>
    <?php endif; ?>

    <!-- Header Settings Form -->
    <div class="swps-card">
        <h2>Header Configuration</h2>
        <form method="post" action="">
            <?php wp_nonce_field('swps_save_headers', 'swps_headers_nonce'); ?>
            <table class="form-table swps-form-table">
                <tr>
                    <th>Security Headers</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_settings[security_headers_enabled]" value="1" <?php checked($enabled); ?>>
                            <span class="swps-slider"></span>
                        </label> Enable security headers output
                    </td>
                </tr>
                <tr>
                    <th>X-Frame-Options</th>
                    <td>
                        <select name="swps_headers[x_frame_options]" class="swps-select">
                            <option value="SAMEORIGIN" <?php selected($headers['x_frame_options'], 'SAMEORIGIN'); ?>>SAMEORIGIN (recommended)</option>
                            <option value="DENY"       <?php selected($headers['x_frame_options'], 'DENY'); ?>>DENY (strictest)</option>
                            <option value=""           <?php selected($headers['x_frame_options'], ''); ?>>Disabled</option>
                        </select>
                        <p class="description">Stops other websites from secretly loading your site inside theirs to trick your visitors (clickjacking). "SAMEORIGIN" is safe for most sites.</p>
                    </td>
                </tr>
                <tr>
                    <th>X-Content-Type-Options</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_headers[x_content_type]" value="1" <?php checked(!empty($headers['x_content_type'])); ?>>
                            <span class="swps-slider"></span>
                        </label> Stops browsers from guessing file types, which hackers can abuse to run malicious files. Keep on.
                    </td>
                </tr>
                <tr>
                    <th>X-XSS-Protection</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_headers[x_xss_protection]" value="1" <?php checked(!empty($headers['x_xss_protection'])); ?>>
                            <span class="swps-slider"></span>
                        </label> An older browser filter against malicious scripts. Modern browsers ignore it, but it is harmless to leave on.
                    </td>
                </tr>
                <tr>
                    <th>Referrer-Policy</th>
                    <td>
                        <select name="swps_headers[referrer_policy]" class="swps-select">
                            <?php
                            $policies = array(
                                'no-referrer'                     => 'no-referrer',
                                'no-referrer-when-downgrade'      => 'no-referrer-when-downgrade',
                                'origin'                          => 'origin',
                                'origin-when-cross-origin'        => 'origin-when-cross-origin',
                                'same-origin'                     => 'same-origin',
                                'strict-origin'                   => 'strict-origin',
                                'strict-origin-when-cross-origin' => 'strict-origin-when-cross-origin (recommended)',
                                'unsafe-url'                      => 'unsafe-url',
                            );
                            foreach ($policies as $val => $label):
                            ?>
                            <option value="<?php echo $val; ?>" <?php selected($headers['referrer_policy'], $val); ?>><?php echo esc_html($label); ?></option>
                            <?php endforeach; ?>
                        </select>
                        <p class="description">Controls how much address info your site shares when a visitor clicks a link to another website. The recommended option is a safe balance of privacy and compatibility.</p>
                    </td>
                </tr>
                <tr>
                    <th>Force HTTPS (HSTS)</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_headers[hsts]" value="1" <?php checked(!empty($headers['hsts'])); ?>>
                            <span class="swps-slider"></span>
                        </label> Forces browsers to always use the secure (HTTPS) version of your site for one year. Only turn on if your SSL certificate is installed and working.
                    </td>
                </tr>
                <tr>
                    <th>Permissions-Policy</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_headers[permissions_policy]" value="1" <?php checked(!empty($headers['permissions_policy'])); ?>>
                            <span class="swps-slider"></span>
                        </label> Blocks web features like camera, microphone and location on your site unless you actually need them.
                    </td>
                </tr>
                <tr>
                    <th>Remove Server Headers</th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_headers[remove_server_header]" value="1" <?php checked(!empty($headers['remove_server_header'])); ?>>
                            <span class="swps-slider"></span>
                        </label> Hides your server and PHP version from visitors, so hackers can't target weaknesses known for that version.
                    </td>
                </tr>
                <tr>
                    <th>Content Security Policy</th>
                    <td>
                        <label class="swps-toggle" style="margin-bottom:8px;display:block">
                            <input type="checkbox" name="swps_headers[csp]" value="1" <?php checked(!empty($headers['csp'])); ?>>
                            <span class="swps-slider"></span>
                        </label>
                        <textarea name="swps_headers[csp_value]" rows="3" class="large-text code"><?php echo esc_textarea($headers['csp_value']); ?></textarea>
                        <p class="description"><strong>Advanced:</strong> controls exactly which scripts, styles and images are allowed to load on your site. Very powerful, but a wrong value can break your site's look or features. Leave OFF unless you understand Content-Security-Policy.</p>
                    </td>
                </tr>
            </table>
            <?php submit_button('Save Header Settings'); ?>
        </form>
    </div>
</div>

<script>
jQuery(document).ready(function($) {
    $('#swps-test-headers-btn').on('click', function() {
        var $btn = $(this).prop('disabled', true).text('Testing...');
        $.post(ajaxurl, { action: 'swps_test_headers', nonce: swps_vars.nonce }, function(res) {
            if (res.success) location.reload();
            else $btn.prop('disabled', false).text('Test Headers Now');
        });
    });
});
</script>

<?php
// Handle form save
if (isset($_POST['swps_headers_nonce']) && wp_verify_nonce($_POST['swps_headers_nonce'], 'swps_save_headers')) {
    $new = array(
        'x_frame_options'     => sanitize_text_field($_POST['swps_headers']['x_frame_options'] ?? 'SAMEORIGIN'),
        'x_content_type'      => ! empty($_POST['swps_headers']['x_content_type']) ? 1 : 0,
        'x_xss_protection'    => ! empty($_POST['swps_headers']['x_xss_protection']) ? 1 : 0,
        'referrer_policy'     => sanitize_text_field($_POST['swps_headers']['referrer_policy'] ?? 'strict-origin-when-cross-origin'),
        'hsts'                => ! empty($_POST['swps_headers']['hsts']) ? 1 : 0,
        'permissions_policy'  => ! empty($_POST['swps_headers']['permissions_policy']) ? 1 : 0,
        'remove_server_header'=> ! empty($_POST['swps_headers']['remove_server_header']) ? 1 : 0,
        'csp'                 => ! empty($_POST['swps_headers']['csp']) ? 1 : 0,
        'csp_value'           => sanitize_textarea_field($_POST['swps_headers']['csp_value'] ?? ''),
    );
    update_option('swps_headers', $new);

    $settings_new = get_option('swps_settings', array());
    $settings_new['security_headers_enabled'] = ! empty($_POST['swps_settings']['security_headers_enabled']) ? 1 : 0;
    update_option('swps_settings', $settings_new);

    echo '<div class="notice notice-success is-dismissible"><p>Header settings saved.</p></div>';
}
// AJAX handler for test
add_action('wp_ajax_swps_test_headers', function() {
    check_ajax_referer('swps_nonce', 'nonce');
    $results = SWPS_Security_Headers::test_headers();
    set_transient('swps_header_test', $results, HOUR_IN_SECONDS);
    wp_send_json_success($results);
});
?>
