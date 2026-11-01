<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-hammer"></span> WordPress Hardening</h1>

    <?php
    $saved    = get_option('swps_hardening', array());
    $defaults = SWPS_Hardening::get_defaults();
    $options  = wp_parse_args($saved, $defaults);
    $checks   = SWPS_Hardening::get_security_check_list();
    $passed   = count(array_filter($checks, fn($c) => $c['status']));
    $total    = count($checks);
    $score    = round(($passed / $total) * 100);
    ?>

    <!-- Score Bar -->
    <div class="swps-card swps-score-card">
        <div class="swps-score-row">
            <div>
                <div class="swps-big-score <?php echo $score >= 70 ? 'swps-score-good' : ($score >= 40 ? 'swps-score-warn' : 'swps-score-bad'); ?>"><?php echo $score; ?>%</div>
                <div class="swps-score-label">Hardening Score</div>
            </div>
            <div class="swps-score-bar-wrap">
                <div class="swps-score-bar"><div class="swps-score-fill" style="width:<?php echo $score; ?>%"></div></div>
                <p><?php echo $passed; ?> of <?php echo $total; ?> hardening checks passing</p>
            </div>
        </div>
    </div>

    <!-- Checklist -->
    <div class="swps-card">
        <h2>Security Checklist</h2>
        <table class="swps-table widefat">
            <thead><tr><th>Check</th><th>Status</th><th>Action</th></tr></thead>
            <tbody>
            <?php foreach ($checks as $check): ?>
            <tr>
                <td><?php echo esc_html($check['label']); ?></td>
                <td>
                    <?php if ($check['status']): ?>
                    <span class="swps-badge swps-badge-ok">Pass</span>
                    <?php else: ?>
                    <span class="swps-badge swps-badge-critical">Fail</span>
                    <?php endif; ?>
                </td>
                <td class="swps-muted"><?php echo $check['status'] ? '' : esc_html($check['fix']); ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- Hardening Options -->
    <div class="swps-card">
        <h2>Hardening Options</h2>
        <form method="post" action="">
            <?php wp_nonce_field('swps_save_hardening', 'swps_hardening_nonce'); ?>
            <table class="form-table swps-form-table">
                <?php
                $items = array(
                    'remove_wp_version'        => array('label'=>'Hide WordPress Version','desc'=>'Hides which WordPress version your site runs. Hackers use the version to look up known weaknesses, so hiding it makes you a harder target. Safe to keep on.'),
                    'disable_xmlrpc'           => array('label'=>'Turn Off XML-RPC','desc'=>'XML-RPC is an old feature that hackers often abuse for password-guessing attacks. Most sites don\'t need it. (Turn off only if you use the WordPress mobile app or Jetpack.)'),
                    'disable_file_edit'        => array('label'=>'Block Code Editing in Admin','desc'=>'Stops anyone from editing your theme/plugin code inside the WordPress dashboard. So even if an admin account is hacked, they can\'t paste malicious code there.'),
                    'disable_rest_anon'        => array('label'=>'Hide Site Data from Strangers','desc'=>'Blocks visitors who are not logged in from reading your site data (like your usernames) through WordPress\'s built-in data feed. Logged-in users are not affected.'),
                    'remove_rsd_link'          => array('label'=>'Remove Unused "RSD" Link','desc'=>'Removes a leftover link in your page code that only old blogging tools used. Harmless to remove and keeps your code clean.'),
                    'remove_wlw_link'          => array('label'=>'Remove Unused "Live Writer" Link','desc'=>'Removes another old, unused link from your page code (added for a discontinued Microsoft blog tool).'),
                    'remove_shortlink'         => array('label'=>'Remove Shortlink Tag','desc'=>'Removes the extra "shortlink" tag WordPress adds to your page code. Not needed by most sites.'),
                    'remove_adjacent_links'    => array('label'=>'Remove Prev/Next Post Links','desc'=>'Hides the hidden "previous/next post" links in your page code. A small privacy and cleanliness improvement.'),
                    'remove_emoji'             => array('label'=>'Turn Off Extra Emoji Code','desc'=>'Stops WordPress from loading extra emoji scripts on every page. This makes your pages load a little faster.'),
                    'disable_author_scan'      => array('label'=>'Stop Username Guessing','desc'=>'Blocks a common trick hackers use to discover your usernames (by visiting author links). Knowing the username is half of a password attack.'),
                    'strong_passwords'         => array('label'=>'Require Strong Passwords','desc'=>'Makes every user choose a strong password — at least 8 characters, one capital letter, and one number.'),
                    'disable_pingback'         => array('label'=>'Turn Off Pingbacks','desc'=>'Disables an old "pingback" feature that attackers can misuse to launch attacks on other websites through yours.'),
                    'disable_directory_listing'=> array('label'=>'Hide Folder Contents','desc'=>'Stops people from seeing the list of files inside your folders when there is no index page. Prevents snooping.'),
                    'comment_nofollow'         => array('label'=>'Hold Spammy Comments','desc'=>'Automatically holds any comment that contains more than 2 links for your review. Most such comments are spam.'),
                    'limit_login_page_access'  => array('label'=>'Allow Login Only From Your IPs','desc'=>'Only the IP addresses you list (in Settings) can open the login page. Powerful, but use with care — a wrong IP can lock you out.'),
                    'block_php_in_uploads'     => array('label'=>'Block Code From Running in Uploads','desc'=>'Your uploads folder should only ever hold images/files, never code — hackers love hiding there since file scanners often skip it. This makes any PHP file placed there unable to run at all, even if one sneaks in. Safe to keep on unless an old plugin specifically needs to run code from uploads (rare).'),
                );
                foreach ($items as $key => $info):
                ?>
                <tr>
                    <th><?php echo esc_html($info['label']); ?></th>
                    <td>
                        <label class="swps-toggle">
                            <input type="checkbox" name="swps_hardening[<?php echo $key; ?>]" value="1" <?php checked(!empty($options[$key])); ?>>
                            <span class="swps-slider"></span>
                        </label>
                        <span class="description"><?php echo esc_html($info['desc']); ?></span>
                    </td>
                </tr>
                <?php endforeach; ?>
            </table>
            <?php submit_button('Save Hardening Settings'); ?>
        </form>
    </div>

    <!-- wp-config.php Recommendations -->
    <div class="swps-card">
        <h2>Recommended wp-config.php Additions</h2>
        <p class="description">Add these defines to your <code>wp-config.php</code> file above the <code>/* That's all, stop editing! */</code> line:</p>
        <pre class="swps-code-block"><?php
        $recommends = SWPS_Hardening::apply_wp_config_hardening();
        foreach ($recommends as $code => $desc) {
            echo esc_html("// $desc\n$code\n\n");
        }
        ?></pre>
    </div>
</div>

<?php
// Handle form save
if (isset($_POST['swps_hardening_nonce']) && wp_verify_nonce($_POST['swps_hardening_nonce'], 'swps_save_hardening')) {
    $new = array();
    foreach (array_keys($items ?? SWPS_Hardening::get_defaults()) as $key) {
        $new[$key] = ! empty($_POST['swps_hardening'][$key]) ? 1 : 0;
    }
    update_option('swps_hardening', $new);
    echo '<div class="notice notice-success is-dismissible"><p>Hardening settings saved.</p></div>';
}
?>
