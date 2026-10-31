<?php
if ( ! defined('ABSPATH') ) exit;

class SWPS_SIEM_Export {

    public static function init() {
        add_action('swps_daily_cron',            array(__CLASS__, 'maybe_stream'));
        add_action('wp_ajax_swps_siem_test',     array(__CLASS__, 'ajax_test'));
        add_action('wp_ajax_swps_siem_export',   array(__CLASS__, 'ajax_export_file'));

        // Hook into audit trail to stream in real-time
        add_action('swps_audit_event', array(__CLASS__, 'stream_event'), 10, 2);
    }

    /* ── Build a normalized CEF/JSON event from audit log entry ── */
    public static function build_event($log_entry) {
        return array(
            '@timestamp'    => date('c', $log_entry['time'] ?? time()),
            'version'       => '1.0',
            'source'        => array(
                'site_url'   => get_site_url(),
                'site_name'  => get_bloginfo('name'),
                'plugin'     => 'SecureWP Shield v4.0',
            ),
            'event'         => array(
                'action'     => $log_entry['action'] ?? '',
                'category'   => $log_entry['object_type'] ?? 'wordpress',
                'severity'   => $log_entry['severity'] ?? 'info',
                'outcome'    => 'success',
            ),
            'user'          => array(
                'id'         => $log_entry['user_id'] ?? 0,
                'name'       => $log_entry['user_login'] ?? 'system',
            ),
            'source_ip'     => $log_entry['ip'] ?? '',
            'object'        => array(
                'type'       => $log_entry['object_type'] ?? '',
                'id'         => $log_entry['object_id'] ?? '',
                'name'       => $log_entry['object_name'] ?? '',
            ),
            'message'       => $log_entry['details'] ?? '',
        );
    }

    /* ── Stream a single event to all configured SIEM endpoints ── */
    public static function stream_event($action, $details) {
        $settings = get_option('swps_settings', array());
        if (empty($settings['siem_enabled'])) return;

        $event = self::build_event(array(
            'time'        => time(),
            'action'      => $action,
            'details'     => $details,
            'ip'          => SWPS_IP_Blocker::get_ip(),
            'user_id'     => get_current_user_id(),
            'user_login'  => wp_get_current_user()->user_login ?? 'system',
        ));

        self::dispatch($event, $settings);
    }

    /* ── Dispatch to all configured endpoints ── */
    public static function dispatch($event, $settings = null) {
        if (!$settings) $settings = get_option('swps_settings', array());
        $json = json_encode($event);

        // HTTP endpoint (Splunk HEC, Elastic Logstash, custom)
        if (!empty($settings['siem_http_url'])) {
            self::send_http($json, $settings['siem_http_url'], $settings['siem_http_token'] ?? '', $settings['siem_format'] ?? 'json');
        }

        // Syslog UDP
        if (!empty($settings['siem_syslog_host'])) {
            self::send_syslog($event, $settings['siem_syslog_host'], intval($settings['siem_syslog_port'] ?? 514));
        }

        // Write to local log file
        if (!empty($settings['siem_local_log'])) {
            self::write_local($json);
        }
    }

    /* ── HTTP/S delivery (Splunk HEC, Elastic, Graylog GELF HTTP) ── */
    private static function send_http($json, $url, $token, $format) {
        $body    = $json;
        $headers = array('Content-Type' => 'application/json');

        if ($format === 'splunk_hec') {
            $body    = json_encode(array('event' => json_decode($json, true), 'sourcetype' => 'securewp_shield'));
            $headers['Authorization'] = 'Splunk ' . $token;
        } elseif ($format === 'gelf') {
            $data             = json_decode($json, true);
            $gelf             = array(
                'version'       => '1.1',
                'host'          => parse_url(get_site_url(), PHP_URL_HOST),
                'short_message' => $data['event']['action'] ?? 'event',
                'full_message'  => $data['message'] ?? '',
                'timestamp'     => time(),
                'level'         => 6,
                '_site_url'     => $data['source']['site_url'] ?? '',
                '_user'         => $data['user']['name'] ?? '',
                '_source_ip'    => $data['source_ip'] ?? '',
            );
            $body = json_encode($gelf);
        } elseif ($token) {
            $headers['Authorization'] = 'Bearer ' . $token;
        }

        wp_remote_post($url, array(
            'headers'   => $headers,
            'body'      => $body,
            'timeout'   => 5,
            'blocking'  => false,
            'sslverify' => true,
        ));
    }

    /* ── UDP Syslog (RFC 5424) ── */
    private static function send_syslog($event, $host, $port) {
        $priority  = 134; // facility=16 (local0), severity=6 (info)
        $timestamp = date('Y-m-d\TH:i:s\Z');
        $hostname  = parse_url(get_site_url(), PHP_URL_HOST) ?: 'wordpress';
        $app_name  = 'securewp-shield';
        $msg_id    = $event['event']['action'] ?? '-';
        $message   = $event['message'] ?? '-';

        $syslog = sprintf("<%d>1 %s %s %s - %s - %s", $priority, $timestamp, $hostname, $app_name, $msg_id, $message);

        $socket = @fsockopen("udp://$host", $port, $errno, $errstr, 2);
        if ($socket) {
            fwrite($socket, $syslog);
            fclose($socket);
        }
    }

    /* ── Write to local NDJSON log file ── */
    private static function write_local($json) {
        $dir  = WP_CONTENT_DIR . '/swps-siem-logs/';
        $file = $dir . date('Y-m-d') . '.ndjson';
        if (!file_exists($dir)) {
            wp_mkdir_p($dir);
            // .htaccess access-control isn't honored on every host (confirmed
            // on at least one OpenLiteSpeed setup) — an index.php that halts
            // execution is a host-independent second layer for a directory
            // that can contain IPs, usernames and event details.
            file_put_contents($dir . '.htaccess', "Order Allow,Deny\nDeny from all\nRequire all denied\n");
            file_put_contents($dir . 'index.php', "<?php\n// Silence is golden.\nexit;\n");
        }
        file_put_contents($file, $json . "\n", FILE_APPEND | LOCK_EX);
    }

    /* ── Batch export last N audit events ── */
    public static function export_batch($limit = 1000) {
        global $wpdb;
        $table = $wpdb->prefix . 'swps_audit_trail';
        $rows  = $wpdb->get_results("SELECT * FROM $table ORDER BY created_at DESC LIMIT $limit", ARRAY_A); // phpcs:ignore
        $lines = array();
        foreach ((array)$rows as $row) {
            $event   = self::build_event(array(
                'time'        => strtotime($row['created_at']),
                'action'      => $row['action'],
                'object_type' => $row['object_type'],
                'object_id'   => $row['object_id'],
                'object_name' => $row['object_name'],
                'details'     => $row['details'],
                'ip'          => $row['ip'],
                'user_id'     => $row['user_id'],
                'user_login'  => $row['user_login'],
            ));
            $lines[] = json_encode($event);
        }
        return implode("\n", $lines);
    }

    public static function maybe_stream() {
        $settings = get_option('swps_settings', array());
        if (empty($settings['siem_enabled'])) return;
        // Send a daily heartbeat
        self::dispatch(array('@timestamp'=>date('c'), 'event'=>array('action'=>'heartbeat'), 'source'=>array('site_url'=>get_site_url()), 'message'=>'Daily SIEM heartbeat from SecureWP Shield'));
    }

    public static function ajax_test() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $event = self::build_event(array(
            'time' => time(), 'action' => 'siem_test', 'details' => 'Test event from SecureWP Shield admin', 'ip' => SWPS_IP_Blocker::get_ip(), 'user_login' => wp_get_current_user()->user_login
        ));
        self::dispatch($event);
        wp_send_json_success('Test event dispatched to all configured SIEM endpoints.');
    }

    public static function ajax_export_file() {
        check_ajax_referer('swps_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        $data = self::export_batch(2000);
        header('Content-Type: application/x-ndjson');
        header('Content-Disposition: attachment; filename="swps-siem-export-' . date('Y-m-d') . '.ndjson"');
        echo $data;
        exit;
    }
}
