<?php
if ( ! defined('ABSPATH') ) exit;

class SWPS_IP_Reputation {

    const SCORES_OPT = 'swps_ip_reputation_scores';

    /* Event weights: event_type => score added */
    const EVENT_WEIGHTS = array(
        'failed_login'    => 5,
        'waf_blocked'     => 15,
        'honeypot'        => 40,
        'rate_limit'      => 10,
        'fake_login'      => 50,
        'canary'          => 30,
        'sqli_attempt'    => 25,
        'xss_attempt'     => 20,
        'scanner_detected'=> 15,
        'country_blocked' => 20,
        'abuseipdb_high'  => 35,
        'manual'          => 100,
    );

    /* Score thresholds */
    const THRESHOLD_WARN  = 40;
    const THRESHOLD_BLOCK = 75;

    public static function init() {
        add_action('wp_ajax_swps_rep_lookup',       array(__CLASS__, 'ajax_lookup'));
        add_action('wp_ajax_swps_rep_reset',        array(__CLASS__, 'ajax_reset'));
        add_action('wp_ajax_swps_rep_manual_block', array(__CLASS__, 'ajax_manual_block'));
        add_action('swps_daily_cron',               array(__CLASS__, 'decay_scores'));
    }

    /* ── Record an event for an IP ── */
    public static function record_event($ip, $event_type, $override_score = null) {
        $scores = get_option(self::SCORES_OPT, array());
        $key    = md5($ip);
        $weight = $override_score ?? (self::EVENT_WEIGHTS[$event_type] ?? 5);

        if (!isset($scores[$key])) {
            $scores[$key] = array(
                'ip'      => $ip,
                'score'   => 0,
                'events'  => array(),
                'created' => time(),
            );
        }

        $scores[$key]['score']      = min(100, $scores[$key]['score'] + $weight);
        $scores[$key]['last_event'] = time();
        $scores[$key]['events'][]   = array('type' => $event_type, 'weight' => $weight, 'time' => time());

        // Keep only last 20 events per IP
        if (count($scores[$key]['events']) > 20) {
            $scores[$key]['events'] = array_slice($scores[$key]['events'], -20);
        }

        update_option(self::SCORES_OPT, $scores, false);

        // Auto-block if threshold crossed
        if ($scores[$key]['score'] >= self::THRESHOLD_BLOCK) {
            if (!SWPS_IP_Blocker::is_blocked($ip)) {
                SWPS_IP_Blocker::block_ip($ip, "Reputation score: {$scores[$key]['score']}/100", 1440);
                SWPS_Audit_Trail::log('rep_auto_block', 'reputation', '', $ip, "Score: {$scores[$key]['score']}/100 after $event_type");

                if (class_exists('SWPS_Notifications')) {
                    $notify = SWPS_Notifications::get_instance();
                    $notify->send('ip_reputation_block', 'IP Auto-Blocked by Reputation',
                        "**IP:** $ip\n**Score:** {$scores[$key]['score']}/100\n**Trigger:** $event_type", 'warning');
                }
            }
        }

        return $scores[$key]['score'];
    }

    /* ── Get score for an IP ── */
    public static function get_score($ip) {
        $scores = get_option(self::SCORES_OPT, array());
        $key    = md5($ip);
        return $scores[$key]['score'] ?? 0;
    }

    /* ── Get full record for an IP ── */
    public static function get_record($ip) {
        $scores = get_option(self::SCORES_OPT, array());
        return $scores[md5($ip)] ?? null;
    }

    /* ── Get reputation label ── */
    public static function get_label($score) {
        if ($score >= 75) return array('label' => 'Malicious',  'class' => 'swps-badge-critical');
        if ($score >= 40) return array('label' => 'Suspicious', 'class' => 'swps-badge-warning');
        if ($score >= 10) return array('label' => 'Watch',      'class' => 'swps-badge-ok');
        return array('label' => 'Clean', 'class' => '');
    }

    /* ── Daily decay: reduce scores by 5 to allow recovery ── */
    public static function decay_scores() {
        $scores = get_option(self::SCORES_OPT, array());
        foreach ($scores as $key => $data) {
            $scores[$key]['score'] = max(0, $data['score'] - 5);
            // Remove records with 0 score after 30 days
            if ($scores[$key]['score'] === 0 && (time() - ($data['last_event'] ?? 0)) > 30 * DAY_IN_SECONDS) {
                unset($scores[$key]);
            }
        }
        update_option(self::SCORES_OPT, $scores, false);
    }

    /* ── Get top threats ── */
    public static function get_top_threats($limit = 20) {
        $scores = get_option(self::SCORES_OPT, array());
        uasort($scores, fn($a, $b) => $b['score'] <=> $a['score']);
        return array_slice($scores, 0, $limit, true);
    }

    /* ── AJAX handlers ── */
    public static function ajax_lookup() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $ip = sanitize_text_field($_POST['ip'] ?? '');
        if (!filter_var($ip, FILTER_VALIDATE_IP)) wp_send_json_error('Invalid IP.');
        $record = self::get_record($ip);
        if (!$record) wp_send_json_success(array('ip' => $ip, 'score' => 0, 'events' => array(), 'label' => 'No history'));
        wp_send_json_success(array_merge($record, array('label' => self::get_label($record['score']))));
    }

    public static function ajax_reset() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $ip     = sanitize_text_field($_POST['ip'] ?? '');
        $scores = get_option(self::SCORES_OPT, array());
        unset($scores[md5($ip)]);
        update_option(self::SCORES_OPT, $scores, false);
        wp_send_json_success('Score reset.');
    }

    public static function ajax_manual_block() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $ip = sanitize_text_field($_POST['ip'] ?? '');
        self::record_event($ip, 'manual', 100);
        wp_send_json_success("IP $ip blocked via reputation.");
    }
}
