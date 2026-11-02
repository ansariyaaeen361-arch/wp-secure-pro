<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_SSL_Monitor {

    public static function init() {
        add_action( 'swps_daily_cron',          array( __CLASS__, 'check_ssl' ) );
        add_action( 'wp_ajax_swps_check_ssl',   array( __CLASS__, 'ajax_check' ) );
    }

    public static function check_ssl( $force = false ) {
        $settings = get_option( 'swps_settings', array() );
        if ( empty($settings['ssl_monitor_enabled']) && ! $force ) return null;

        $host   = parse_url( get_site_url(), PHP_URL_HOST );
        $port   = 443;
        $result = self::get_ssl_info( $host, $port );

        update_option( 'swps_ssl_last_check', array_merge($result, array('checked_at' => time())) );

        if ( isset($result['days_remaining']) ) {
            $days = $result['days_remaining'];
            $alerts = intval($settings['ssl_alert_days'] ?? 30);

            if ( $days <= 0 ) {
                SWPS_Activity_Log::add( 'ssl_expired', 'critical', "SSL certificate has EXPIRED on $host!" );
                SWPS_Notifications::send( 'ssl_expired', 'WP Secure Pro: SSL Certificate EXPIRED', "Your SSL certificate on $host has expired! Visitors will see security warnings.", 'critical' );
            } elseif ( $days <= $alerts ) {
                SWPS_Activity_Log::add( 'ssl_expiring', 'warning', "SSL certificate expiring in $days days on $host" );
                SWPS_Notifications::send( 'ssl_expiring', "WP Secure Pro: SSL Expiring in $days Days", "Your SSL certificate on $host will expire in $days days. Renew it now.", 'warning' );
            }
        }

        return $result;
    }

    public static function get_ssl_info( $host, $port = 443 ) {
        $result = array(
            'host'           => $host,
            'valid'          => false,
            'issuer'         => '',
            'subject'        => '',
            'expires'        => '',
            'days_remaining' => null,
            'grade'          => 'F',
            'error'          => '',
        );

        $context = stream_context_create( array(
            'ssl' => array(
                'capture_peer_cert' => true,
                'verify_peer'       => true,
                'verify_peer_name'  => true,
            )
        ) );

        $stream = @stream_socket_client(
            "ssl://{$host}:{$port}",
            $errno, $errstr, 10,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ( ! $stream ) {
            $result['error'] = $errstr ?: "Connection failed to $host:$port";
            return $result;
        }

        $params = stream_context_get_params($stream);
        $cert   = $params['options']['ssl']['peer_certificate'] ?? null;
        fclose($stream);

        if ( ! $cert ) {
            $result['error'] = 'Could not retrieve certificate';
            return $result;
        }

        $cert_data  = openssl_x509_parse($cert);
        $valid_to   = $cert_data['validTo_time_t'] ?? 0;
        $valid_from = $cert_data['validFrom_time_t'] ?? 0;
        $now        = time();

        $issuer_cn  = $cert_data['issuer']['CN']  ?? $cert_data['issuer']['O'] ?? 'Unknown';
        $subject_cn = $cert_data['subject']['CN'] ?? $host;
        $days       = intval( ($valid_to - $now) / DAY_IN_SECONDS );

        // Basic grade
        $grade = 'A';
        if ( $days <= 0 )   $grade = 'F';
        elseif ( $days < 7 ) $grade = 'C';
        elseif ( $days < 30) $grade = 'B';

        $result = array(
            'host'           => $host,
            'valid'          => $now >= $valid_from && $now <= $valid_to,
            'issuer'         => $issuer_cn,
            'subject'        => $subject_cn,
            'expires'        => date_i18n( get_option('date_format'), $valid_to ),
            'issued'         => date_i18n( get_option('date_format'), $valid_from ),
            'days_remaining' => $days,
            'grade'          => $grade,
            'error'          => '',
            'san'            => $cert_data['extensions']['subjectAltName'] ?? '',
        );

        return $result;
    }

    public static function ajax_check() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');
        $result = self::check_ssl(true);
        wp_send_json_success($result);
    }

    public static function get_last_check() {
        return get_option( 'swps_ssl_last_check', array() );
    }
}
