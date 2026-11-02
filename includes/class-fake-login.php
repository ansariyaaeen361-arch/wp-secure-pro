<?php
if ( ! defined('ABSPATH') ) exit;

class SWPS_Fake_Login {

    const LOG_OPT = 'swps_fake_login_log';

    public static function init() {
        $settings = get_option('swps_settings', array());
        if (empty($settings['fake_login_enabled'])) return;

        $decoy_slug = trim($settings['fake_login_slug'] ?? 'admin-login');
        if (!$decoy_slug) return;

        add_action('init', array(__CLASS__, 'intercept_decoy'), 1);
        add_action('wp_ajax_nopriv_swps_fake_login_submit', array(__CLASS__, 'ajax_submit'));
        add_action('wp_ajax_swps_fake_login_clear', array(__CLASS__, 'ajax_clear_log'));
    }

    public static function ajax_clear_log() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        delete_option(self::LOG_OPT);
        wp_send_json_success('Log cleared.');
    }

    /* ── Intercept requests to the decoy URL ── */
    public static function intercept_decoy() {
        $settings   = get_option('swps_settings', array());
        $decoy_slug = trim($settings['fake_login_slug'] ?? 'admin-login');
        $uri        = ltrim(parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?: '', '/');

        if ($uri !== $decoy_slug) return;

        $ip = SWPS_IP_Blocker::get_ip();

        // Log the visit
        self::log_visit($ip, 'visit', '');

        // Render fake login form
        self::render_fake_login($ip);
    }

    /* ── Render a convincing-looking fake login form ── */
    public static function render_fake_login($ip) {
        $settings  = get_option('swps_settings', array());
        $site_name = get_bloginfo('name');
        $nonce     = wp_create_nonce('swps_fake_' . $ip);

        status_header(200);
        header('Content-Type: text/html; charset=UTF-8');
        ?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Log In — <?php echo esc_html($site_name); ?></title>
    <style>
        body{background:#f1f1f1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;padding:0}
        #login{width:320px;margin:80px auto}
        #login h1{text-align:center;margin-bottom:24px}
        #login h1 a{background:url(<?php echo esc_url(admin_url('images/wordpress-logo.svg')); ?>) center/84px no-repeat;display:block;height:84px;text-indent:-9999px}
        .login-form{background:#fff;padding:24px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.13)}
        .login-form p{margin:0 0 16px}
        label{display:block;font-size:14px;font-weight:600;margin-bottom:4px}
        input[type="text"],input[type="password"]{width:100%;padding:8px;border:1px solid #8d96a0;border-radius:3px;font-size:15px;box-sizing:border-box}
        .wp-submit{background:#2271b1;border:none;color:#fff;padding:10px 16px;width:100%;cursor:pointer;font-size:14px;border-radius:3px;margin-top:8px}
        .wp-submit:hover{background:#135e96}
        #login-error{border-left:4px solid #dc3232;background:#fff;padding:12px;margin:12px 0;font-size:13px;display:none}
        .loading{display:none;text-align:center;color:#646970;font-size:13px;margin-top:8px}
    </style>
</head>
<body class="login">
<div id="login">
    <h1><a href="https://wordpress.org" title="Powered by WordPress">WordPress</a></h1>
    <div id="login-error"></div>
    <form class="login-form" id="loginform" method="post">
        <p>
            <label for="user_login">Username or Email Address</label>
            <input type="text" name="log" id="user_login" autocomplete="username" size="20">
        </p>
        <p>
            <label for="user_pass">Password</label>
            <input type="password" name="pwd" id="user_pass" autocomplete="current-password" size="20">
        </p>
        <p class="submit">
            <input type="submit" class="wp-submit" value="Log In">
        </p>
    </form>
    <div class="loading" id="loading">Please wait…</div>
    <p style="text-align:center;font-size:13px;margin-top:12px"><a href="<?php echo esc_url(wp_lostpassword_url()); ?>">Lost your password?</a></p>
</div>

<script>
document.getElementById('loginform').addEventListener('submit', function(e){
    e.preventDefault();
    var username = document.getElementById('user_login').value;
    var password = document.getElementById('user_pass').value;
    document.getElementById('loading').style.display = 'block';

    var fd = new FormData();
    fd.append('action',   'swps_fake_login_submit');
    fd.append('nonce',    <?php echo json_encode($nonce); ?>);
    fd.append('username', username);
    fd.append('password', password);

    fetch(<?php echo json_encode(admin_url('admin-ajax.php')); ?>, {method:'POST',body:fd,credentials:'same-origin'})
    .then(function(r){ return r.json(); })
    .then(function(res){
        document.getElementById('loading').style.display = 'none';
        var err = document.getElementById('login-error');
        err.style.display = 'block';
        err.textContent = res.data || 'Unknown error.';
    });
});
</script>
</body>
</html><?php
        exit;
    }

    /* ── AJAX: capture submitted credentials ── */
    public static function ajax_submit() {
        $ip       = SWPS_IP_Blocker::get_ip();
        $nonce    = sanitize_text_field($_POST['nonce'] ?? '');
        $username = sanitize_text_field($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if (!wp_verify_nonce($nonce, 'swps_fake_' . $ip)) {
            wp_send_json_error('Invalid request.');
        }

        self::log_visit($ip, 'credentials', $username);

        $settings = get_option('swps_settings', array());

        // Auto-block
        if (!empty($settings['fake_login_auto_block'])) {
            SWPS_IP_Blocker::block_ip($ip, 'Attempted login on decoy page', 10080);
        }

        // Notify with captured username (never log password)
        if (class_exists('SWPS_Notifications')) {
            $notify = SWPS_Notifications::get_instance();
            $notify->send(
                'fake_login_attempt',
                'Decoy Login Attempt',
                "**IP:** $ip\n**Username tried:** " . esc_html($username) . "\n**Password length:** " . strlen($password),
                'critical'
            );
        }

        SWPS_Audit_Trail::log('fake_login_attempt', 'security', '', 'Decoy Login', "IP: $ip | Username: $username | Pass length: " . strlen($password));

        // Believable error message
        wp_send_json_error('The password you entered for the username <strong>' . esc_html($username) . '</strong> is incorrect. <a href="' . wp_lostpassword_url() . '">Lost your password?</a>');
    }

    /* ── Log visits ── */
    private static function log_visit($ip, $type, $username) {
        $log = get_option(self::LOG_OPT, array());
        array_push($log, array(
            'time'     => time(),
            'ip'       => $ip,
            'type'     => $type,
            'username' => $username,
            'ua'       => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 200),
            'country'  => class_exists('SWPS_GeoIP') ? SWPS_GeoIP::get_country($ip) : '',
        ));
        if (count($log) > 300) $log = array_slice($log, -300);
        update_option(self::LOG_OPT, $log, false);
    }

    public static function get_log($limit = 50) {
        return array_slice(array_reverse(get_option(self::LOG_OPT, array())), 0, $limit);
    }

    public static function get_stats() {
        $log  = get_option(self::LOG_OPT, array());
        $cred = array_filter($log, fn($e) => $e['type'] === 'credentials');
        return array(
            'total_visits'   => count($log),
            'cred_attempts'  => count($cred),
            'unique_ips'     => count(array_unique(array_column($log, 'ip'))),
        );
    }
}
