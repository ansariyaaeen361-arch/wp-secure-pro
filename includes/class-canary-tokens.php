<?php
if ( ! defined('ABSPATH') ) exit;

class SWPS_Canary_Tokens {

    const TOKENS_OPT = 'swps_canary_tokens';
    const LOG_OPT    = 'swps_canary_log';

    public static function init() {
        $settings = get_option('swps_settings', array());
        if (empty($settings['canary_enabled'])) return;

        // Intercept canary token pings
        add_action('init', array(__CLASS__, 'intercept'), 1);

        // Inject hidden canary into page content
        add_filter('the_content', array(__CLASS__, 'inject_canary'));

        // AJAX management
        add_action('wp_ajax_swps_canary_create',  array(__CLASS__, 'ajax_create'));
        add_action('wp_ajax_swps_canary_delete',  array(__CLASS__, 'ajax_delete'));
        add_action('wp_ajax_swps_canary_clear_log', array(__CLASS__, 'ajax_clear_log'));
    }

    /* ── Intercept a canary ping ── */
    public static function intercept() {
        $uri = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?: '';
        if (strpos($uri, '/swps-track/') === false) return;

        preg_match('#/swps-track/([a-f0-9]{32})#', $uri, $m);
        if (empty($m[1])) return;

        $token_id = $m[1];
        $tokens   = get_option(self::TOKENS_OPT, array());

        if (!isset($tokens[$token_id])) {
            status_header(404); exit;
        }

        $ip      = SWPS_IP_Blocker::get_ip();
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $ua      = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 300);

        self::log_ping($token_id, $tokens[$token_id], $ip, $referer, $ua);

        // Respond with 1×1 transparent pixel
        header('Content-Type: image/gif');
        header('Cache-Control: no-cache, no-store');
        echo base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7');
        exit;
    }

    /* ── Log canary ping and send alert ── */
    public static function log_ping($token_id, $token, $ip, $referer, $ua) {
        $log = get_option(self::LOG_OPT, array());

        $entry = array(
            'time'       => time(),
            'token_id'   => $token_id,
            'token_name' => $token['name'] ?? 'Unknown',
            'ip'         => $ip,
            'referer'    => $referer,
            'ua'         => $ua,
            'country'    => class_exists('SWPS_GeoIP') ? SWPS_GeoIP::get_country($ip) : '',
        );

        array_push($log, $entry);
        if (count($log) > 300) $log = array_slice($log, -300);
        update_option(self::LOG_OPT, $log, false);

        // Increment token hit count
        $tokens = get_option(self::TOKENS_OPT, array());
        if (isset($tokens[$token_id])) {
            $tokens[$token_id]['hits'] = ($tokens[$token_id]['hits'] ?? 0) + 1;
            $tokens[$token_id]['last_hit'] = time();
            update_option(self::TOKENS_OPT, $tokens, false);
        }

        SWPS_Audit_Trail::log('canary_pinged', 'canary', $token_id, $token['name'] ?? '', "IP: $ip | Referer: $referer");

        if (class_exists('SWPS_Notifications')) {
            $notify = SWPS_Notifications::get_instance();
            $notify->send(
                'canary_triggered',
                'Canary Token Triggered: ' . ($token['name'] ?? $token_id),
                "**IP:** $ip\n**Referer:** $referer\n**Token:** {$token['name']}\n**Description:** {$token['description']}",
                'critical'
            );
        }
    }

    /* ── Inject invisible canary pixel into post content ── */
    public static function inject_canary($content) {
        $settings = get_option('swps_settings', array());
        if (empty($settings['canary_auto_inject'])) return $content;

        $tokens = get_option(self::TOKENS_OPT, array());
        if (empty($tokens)) return $content;

        // Pick random active token
        $active = array_filter($tokens, fn($t) => !empty($t['auto_inject']));
        if (empty($active)) return $content;

        $token_id = array_rand($active);
        $url      = home_url("/swps-track/{$token_id}");

        $pixel = "\n<!-- wp:html --><img src=\"" . esc_url($url) . "\" width=\"1\" height=\"1\" style=\"position:absolute;opacity:0;pointer-events:none\" loading=\"lazy\" alt=\"\"><!-- /wp:html -->\n";
        return $content . $pixel;
    }

    /* ── Create a new canary token ── */
    public static function create($name, $description = '', $auto_inject = false) {
        $token_id = md5(uniqid('swps_canary_', true));
        $tokens   = get_option(self::TOKENS_OPT, array());

        $tokens[$token_id] = array(
            'name'        => sanitize_text_field($name),
            'description' => sanitize_text_field($description),
            'auto_inject' => (bool) $auto_inject,
            'created'     => time(),
            'hits'        => 0,
            'last_hit'    => null,
            'url'         => home_url("/swps-track/{$token_id}"),
        );

        update_option(self::TOKENS_OPT, $tokens);
        return $token_id;
    }

    /* ── AJAX handlers ── */
    public static function ajax_create() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $name   = sanitize_text_field($_POST['name'] ?? 'Token ' . date('Y-m-d'));
        $desc   = sanitize_text_field($_POST['description'] ?? '');
        $inject = !empty($_POST['auto_inject']);
        $id     = self::create($name, $desc, $inject);
        $tokens = get_option(self::TOKENS_OPT, array());
        wp_send_json_success(array('id' => $id, 'token' => $tokens[$id]));
    }

    public static function ajax_delete() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $id     = sanitize_text_field($_POST['id'] ?? '');
        $tokens = get_option(self::TOKENS_OPT, array());
        unset($tokens[$id]);
        update_option(self::TOKENS_OPT, $tokens);
        wp_send_json_success('Deleted.');
    }

    public static function ajax_clear_log() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        delete_option(self::LOG_OPT);
        wp_send_json_success('Log cleared.');
    }

    public static function get_stats() {
        $tokens = get_option(self::TOKENS_OPT, array());
        $log    = get_option(self::LOG_OPT, array());
        return array(
            'token_count' => count($tokens),
            'total_pings' => count($log),
            'tokens'      => $tokens,
            'recent_pings'=> array_slice(array_reverse($log), 0, 20),
        );
    }
}
