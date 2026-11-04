<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/** Sends security alerts to a Slack Incoming Webhook. */
class SWPS_Slack_Alerts {
    const OPTION = 'swps_slack_webhook_encrypted';

    private static function key() {
        return hash( 'sha256', wp_salt( 'auth' ), true );
    }

    /** Only accept Slack's official Incoming Webhook endpoint; no SSRF. */
    private static function valid_url( $url ) {
        $parts = wp_parse_url( trim( (string) $url ) );
        return is_array( $parts )
            && ( $parts['scheme'] ?? '' ) === 'https'
            && ( $parts['host'] ?? '' ) === 'hooks.slack.com'
            && isset( $parts['path'] )
            && (bool) preg_match( '#^/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+$#', $parts['path'] );
    }

    public static function configured() {
        return (bool) get_option( self::OPTION, '' );
    }

    public static function save( $url ) {
        $url = trim( (string) $url );
        if ( ! self::valid_url( $url ) ) return new WP_Error( 'swps_invalid_slack_webhook', 'Enter a valid Slack Incoming Webhook URL.' );
        if ( ! function_exists( 'openssl_encrypt' ) || ! function_exists( 'openssl_decrypt' ) ) return new WP_Error( 'swps_openssl_missing', 'OpenSSL is required to store the Slack webhook securely.' );

        $iv = random_bytes( 12 );
        $tag = '';
        $ciphertext = openssl_encrypt( $url, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $iv, $tag );
        if ( $ciphertext === false || strlen( $tag ) !== 16 ) return new WP_Error( 'swps_slack_encrypt_failed', 'Could not encrypt the Slack webhook.' );
        update_option( self::OPTION, base64_encode( $iv . $tag . $ciphertext ), false );
        return true;
    }

    /** Remove this site's encrypted webhook without affecting other sites. */
    public static function remove() {
        return delete_option( self::OPTION );
    }

    private static function webhook() {
        $stored = base64_decode( (string) get_option( self::OPTION, '' ), true );
        if ( $stored === false || strlen( $stored ) <= 28 || ! function_exists( 'openssl_decrypt' ) ) return '';
        $iv = substr( $stored, 0, 12 );
        $tag = substr( $stored, 12, 16 );
        $url = openssl_decrypt( substr( $stored, 28 ), 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $iv, $tag );
        return is_string( $url ) && self::valid_url( $url ) ? $url : '';
    }

    public static function send( $subject, $body ) {
        $url = self::webhook();
        if ( ! $url ) return false;
        $payload = array(
            'username' => 'WP Secure Pro',
            'icon_emoji' => ':shield:',
            'text' => '*WP Secure Pro Security Alert*\n*' . wp_strip_all_tags( (string) $subject ) . "*\n" . wp_strip_all_tags( (string) $body ) . "\nSite: " . home_url(),
        );
        $response = wp_safe_remote_post( $url, array(
            'timeout' => 10,
            'redirection' => 0,
            'sslverify' => true,
            'headers' => array( 'Content-Type' => 'application/json; charset=utf-8' ),
            'body' => wp_json_encode( $payload ),
        ) );
        if ( is_wp_error( $response ) || (int) wp_remote_retrieve_response_code( $response ) < 200 || (int) wp_remote_retrieve_response_code( $response ) >= 300 ) {
            if ( class_exists( 'SWPS_Activity_Log' ) ) SWPS_Activity_Log::add( 'slack_send_failed', 'warning', 'Slack security-alert delivery failed. Check the saved webhook URL.' );
            return false;
        }
        return true;
    }
}
