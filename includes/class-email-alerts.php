<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Email_Alerts {

    public static function init() {
        // wp_mail() fails silently by default — if the server has no working
        // mail transport (common on a bare VPS without SMTP configured), every
        // alert below would simply vanish with no trace. Surface it instead.
        add_action( 'wp_mail_failed', array( __CLASS__, 'on_mail_failed' ) );
    }

    public static function on_mail_failed( $wp_error ) {
        if ( ! class_exists('SWPS_Activity_Log') ) return;
        SWPS_Activity_Log::add(
            'email_send_failed',
            'warning',
            'wp_mail() failed: ' . $wp_error->get_error_message() .
            ' — check that your server/host has a working mail transport (SMTP).'
        );
    }

    public static function send_alert( $subject, $body ) {
        $settings = get_option( 'swps_settings', array() );
        if ( empty( $settings['email_alerts'] ) ) return;

        $to = sanitize_email( $settings['alert_email'] ?? get_option('admin_email') );
        if ( ! $to ) return;

        $headers = array(
            'Content-Type: text/plain; charset=UTF-8',
            'From: WP Secure Pro <' . get_option('admin_email') . '>',
        );

        $full_body = "=== WP Secure Pro Security Alert ===\n\n" .
                     $body .
                     "\n\n---\nWP Secure Pro - " . get_bloginfo('name') . "\n" . get_site_url() .
                     "\nAlert sent: " . current_time('mysql');

        wp_mail( $to, '[WP Secure Pro] ' . $subject, $full_body, $headers );
    }
}
