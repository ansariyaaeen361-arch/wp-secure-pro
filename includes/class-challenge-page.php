<?php
if ( ! defined('ABSPATH') ) exit;

class SWPS_Challenge_Page {

    const COOKIE_NAME    = 'swps_challenge_pass';
    const COOKIE_HOURS   = 6;
    const SESSION_OPT    = 'swps_challenge_sessions';

    public static function init() {
        $settings = get_option('swps_settings', array());
        if (empty($settings['challenge_page_enabled'])) return;

        add_action('init', array(__CLASS__, 'check_challenge'), 1);
        add_action('wp_ajax_nopriv_swps_challenge_verify', array(__CLASS__, 'ajax_verify'));
        add_action('wp_ajax_swps_challenge_verify',        array(__CLASS__, 'ajax_verify'));
    }

    /* ── Decide whether to show challenge ── */
    public static function check_challenge() {
        // Skip admin, AJAX, REST, cron
        if (is_admin() || wp_doing_ajax() || wp_doing_cron()) return;
        if (defined('REST_REQUEST') && REST_REQUEST) return;

        $ip = SWPS_IP_Blocker::get_ip();

        // Already passed challenge?
        if (self::has_valid_cookie($ip)) return;

        // Check if challenge is required
        if (!self::should_challenge($ip)) return;

        self::render_challenge($ip);
    }

    /* ── Conditions that trigger the challenge ── */
    public static function should_challenge($ip) {
        $settings = get_option('swps_settings', array());

        // AbuseIPDB score — if available
        $abuse_data = get_transient('swps_abuse_' . md5($ip));
        if ($abuse_data && isset($abuse_data['abuseConfidenceScore'])) {
            $threshold = intval($settings['challenge_abuse_threshold'] ?? 50);
            if ($abuse_data['abuseConfidenceScore'] >= $threshold) return true;
        }

        // Failed login attempts > threshold
        $attempts = intval(get_transient('swps_attempts_' . md5($ip)) ?: 0);
        if ($attempts >= intval($settings['challenge_after_attempts'] ?? 3)) return true;

        // WAF triggered
        if (get_transient('swps_waf_triggered_' . md5($ip))) return true;

        // Reputation score — own engine
        if (class_exists('SWPS_IP_Reputation')) {
            $score = SWPS_IP_Reputation::get_score($ip);
            if ($score >= intval($settings['challenge_rep_threshold'] ?? 60)) return true;
        }

        return false;
    }

    /* ── Check valid cookie ── */
    public static function has_valid_cookie($ip) {
        $token = $_COOKIE[self::COOKIE_NAME] ?? '';
        if (!$token) return false;

        $sessions = get_option(self::SESSION_OPT, array());
        $key      = md5($ip . $token);

        if (!isset($sessions[$key])) return false;
        if ($sessions[$key]['expires'] < time()) {
            unset($sessions[$key]);
            update_option(self::SESSION_OPT, $sessions, false);
            return false;
        }

        return true;
    }

    /* ── Generate and set a valid pass cookie ── */
    public static function issue_cookie($ip) {
        $token    = bin2hex(random_bytes(16));
        $sessions = get_option(self::SESSION_OPT, array());
        $key      = md5($ip . $token);

        $sessions[$key] = array('ip' => $ip, 'expires' => time() + self::COOKIE_HOURS * 3600, 'issued' => time());

        // Prune expired
        $sessions = array_filter($sessions, fn($s) => $s['expires'] > time());
        update_option(self::SESSION_OPT, $sessions, false);

        setcookie(self::COOKIE_NAME, $token, time() + self::COOKIE_HOURS * 3600, '/', '', is_ssl(), true);
        return $token;
    }

    /* ── Render the challenge HTML page ── */
    public static function render_challenge($ip) {
        $nonce     = wp_create_nonce('swps_challenge_' . $ip);
        $site_name = get_bloginfo('name');
        $site_url  = home_url();
        $redirect  = esc_url($_SERVER['REQUEST_URI'] ?? '/');

        status_header(403);
        header('Content-Type: text/html; charset=UTF-8');
        header('Cache-Control: no-store, no-cache, must-revalidate');
        ?><!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Security Check — <?php echo esc_html($site_name); ?></title>
    <style>
        *{box-sizing:border-box;margin:0;padding:0}
        body{background:#0f1923;color:#ecf0f1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
        .box{background:#1e2a3b;border:1px solid #2c3e50;border-radius:12px;padding:48px 40px;max-width:480px;width:100%;text-align:center;box-shadow:0 8px 40px rgba(0,0,0,.4)}
        .shield{font-size:56px;margin-bottom:16px;animation:pulse 2s infinite}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
        h1{font-size:22px;margin-bottom:8px;color:#fff}
        p{color:#95a5a6;font-size:14px;line-height:1.6;margin-bottom:24px}
        .spinner{width:40px;height:40px;border:3px solid #2c3e50;border-top-color:#3498db;border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 20px}
        @keyframes spin{to{transform:rotate(360deg)}}
        .status{font-size:13px;color:#7f8c8d;margin-top:12px}
        .success{color:#2ecc71}
        .error-msg{color:#e74c3c;font-size:13px;margin-top:12px}
        .site-link{color:#3498db;text-decoration:none;font-size:12px;margin-top:20px;display:block}
    </style>
</head>
<body>
    <div class="box">
        <div class="shield">🛡️</div>
        <h1>Checking your browser…</h1>
        <p>This site is protected by SecureWP Shield. We're verifying your browser before proceeding. This usually takes just a moment.</p>
        <div class="spinner" id="spinner"></div>
        <div class="status" id="status">Verifying…</div>
        <div class="error-msg" id="error" style="display:none"></div>
        <a href="<?php echo esc_url($site_url); ?>" class="site-link"><?php echo esc_html($site_name); ?></a>
    </div>

    <script>
    (function(){
        var ip    = <?php echo json_encode($ip); ?>;
        var nonce = <?php echo json_encode($nonce); ?>;
        var redir = <?php echo json_encode($redirect); ?>;
        var ajax  = <?php echo json_encode(admin_url('admin-ajax.php')); ?>;

        // Simple JS challenge: prove execution, solve math puzzle
        var a = Math.floor(Math.random() * 100);
        var b = Math.floor(Math.random() * 100);
        var answer = a + b;

        setTimeout(function(){
            var fd = new FormData();
            fd.append('action',   'swps_challenge_verify');
            fd.append('nonce',    nonce);
            fd.append('answer',   answer);
            fd.append('puzzle_a', a);
            fd.append('puzzle_b', b);
            fd.append('ts',       Date.now());

            fetch(ajax, {method:'POST', body:fd, credentials:'same-origin'})
            .then(function(r){ return r.json(); })
            .then(function(res){
                if(res.success){
                    document.getElementById('status').innerHTML = '<span class="success">✓ Verified! Redirecting…</span>';
                    document.getElementById('spinner').style.display = 'none';
                    setTimeout(function(){ window.location.href = redir; }, 600);
                } else {
                    document.getElementById('error').style.display = 'block';
                    document.getElementById('error').textContent = 'Verification failed. Please refresh the page.';
                    document.getElementById('spinner').style.display = 'none';
                }
            })
            .catch(function(){
                document.getElementById('error').style.display = 'block';
                document.getElementById('error').textContent = 'Network error. Please refresh.';
            });
        }, 1500);
    })();
    </script>
</body>
</html><?php
        exit;
    }

    /* ── AJAX: verify challenge response ── */
    public static function ajax_verify() {
        $ip      = SWPS_IP_Blocker::get_ip();
        $nonce   = sanitize_text_field($_POST['nonce'] ?? '');
        $answer  = intval($_POST['answer'] ?? -1);
        $a       = intval($_POST['puzzle_a'] ?? -999);
        $b       = intval($_POST['puzzle_b'] ?? -999);

        if (!wp_verify_nonce($nonce, 'swps_challenge_' . $ip)) {
            wp_send_json_error('Invalid nonce.');
        }

        // Verify math answer
        if ($answer !== ($a + $b) || $a < 0 || $b < 0 || $a > 100 || $b > 100) {
            wp_send_json_error('Challenge failed.');
        }

        // Issue cookie
        self::issue_cookie($ip);
        wp_send_json_success('Verified.');
    }

    public static function get_active_count() {
        $sessions = get_option(self::SESSION_OPT, array());
        return count(array_filter($sessions, fn($s) => $s['expires'] > time()));
    }
}
