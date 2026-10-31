<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Email_Alerts {

    public static function send_alert( $subject, $body ) {
        $settings = get_option( 'swps_settings', array() );
        if ( empty( $settings['email_alerts'] ) ) return;

        $to = sanitize_email( $settings['alert_email'] ?? get_option('admin_email') );
        if ( ! $to ) return;

        $headers = array(
            'Content-Type: text/plain; charset=UTF-8',
            'From: SecureWP Shield <' . get_option('admin_email') . '>',
        );

        $full_body = "=== SecureWP Shield Security Alert ===\n\n" .
                     $body .
                     "\n\n---\nSecureWP Shield - " . get_bloginfo('name') . "\n" . get_site_url() .
                     "\nAlert sent: " . current_time('mysql');

        wp_mail( $to, '[SecureWP] ' . $subject, $full_body, $headers );
    }
}
