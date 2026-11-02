<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Notifications {

    public static function init() {
        // Notifications are triggered by other classes via send()
    }

    /**
     * Back-compat accessor. Several classes call
     * SWPS_Notifications::get_instance()->send(...). send() is static,
     * so returning any instance lets those calls resolve correctly.
     */
    public static function get_instance() {
        static $instance = null;
        if ( $instance === null ) $instance = new self();
        return $instance;
    }

    /**
     * Main dispatcher — routes to enabled channels.
     */
    public static function send( $event_type, $title, $message, $severity = 'warning' ) {
        $settings = get_option( 'swps_settings', array() );

        // Email (existing system)
        if ( ! empty($settings['email_alerts']) ) {
            SWPS_Email_Alerts::send_alert($title, $message);
        }

        // Slack
        if ( ! empty($settings['slack_enabled']) && ! empty($settings['slack_webhook_url']) ) {
            self::send_slack($title, $message, $severity, $settings['slack_webhook_url']);
        }

        // Telegram
        if ( ! empty($settings['telegram_enabled']) && ! empty($settings['telegram_bot_token']) && ! empty($settings['telegram_chat_id']) ) {
            self::send_telegram($title, $message, $settings['telegram_bot_token'], $settings['telegram_chat_id']);
        }

        // Discord
        if ( ! empty($settings['discord_enabled']) && ! empty($settings['discord_webhook_url']) ) {
            self::send_discord($title, $message, $severity, $settings['discord_webhook_url']);
        }
    }

    /* ── Slack ───────────────────────────────────────────────────────────── */

    public static function send_slack( $title, $message, $severity, $webhook_url ) {
        $color = array('critical'=>'#e74c3c','warning'=>'#f39c12','info'=>'#2980b9')[$severity] ?? '#7f8c8d';
        $site  = get_site_url();

        $payload = array(
            'username'    => 'WP Secure Pro',
            'icon_emoji'  => ':shield:',
            'attachments' => array( array(
                'color'      => $color,
                'title'      => $title,
                'text'       => $message,
                'footer'     => $site,
                'ts'         => time(),
                'fields'     => array(
                    array( 'title' => 'Site',     'value' => $site,            'short' => true ),
                    array( 'title' => 'Severity', 'value' => strtoupper($severity), 'short' => true ),
                ),
            ) ),
        );

        wp_remote_post( $webhook_url, array(
            'body'        => json_encode($payload),
            'headers'     => array('Content-Type' => 'application/json'),
            'timeout'     => 5,
            'blocking'    => false, // Fire and forget
        ) );
    }

    /* ── Telegram ────────────────────────────────────────────────────────── */

    public static function send_telegram( $title, $message, $bot_token, $chat_id ) {
        $site = get_site_url();
        $text = "🛡 *WP Secure Pro*\n\n*$title*\n\n$message\n\nSite: $site";

        wp_remote_post( "https://api.telegram.org/bot{$bot_token}/sendMessage", array(
            'body'     => array(
                'chat_id'    => $chat_id,
                'text'       => $text,
                'parse_mode' => 'Markdown',
            ),
            'timeout'  => 5,
            'blocking' => false,
        ) );
    }

    /* ── Discord ─────────────────────────────────────────────────────────── */

    public static function send_discord( $title, $message, $severity, $webhook_url ) {
        $colors = array('critical'=>16007990,'warning'=>16027661,'info'=>2777049);
        $color  = $colors[$severity] ?? 8421504;

        $payload = array(
            'username' => 'WP Secure Pro',
            'embeds'   => array( array(
                'title'       => $title,
                'description' => $message,
                'color'       => $color,
                'timestamp'   => date('c'),
                'footer'      => array( 'text' => get_site_url() ),
            ) ),
        );

        wp_remote_post( $webhook_url, array(
            'body'     => json_encode($payload),
            'headers'  => array('Content-Type' => 'application/json'),
            'timeout'  => 5,
            'blocking' => false,
        ) );
    }

    /* ── Test notifications ──────────────────────────────────────────────── */

    public static function test( $channel ) {
        $title   = 'WP Secure Pro — Test Notification';
        $message = 'This is a test notification from WP Secure Pro. If you received this, your ' . ucfirst($channel) . ' integration is working correctly.';
        $settings = get_option( 'swps_settings', array() );

        switch ($channel) {
            case 'slack':
                if ( empty($settings['slack_webhook_url']) ) return false;
                self::send_slack($title, $message, 'info', $settings['slack_webhook_url']);
                return true;

            case 'telegram':
                if ( empty($settings['telegram_bot_token']) || empty($settings['telegram_chat_id']) ) return false;
                self::send_telegram($title, $message, $settings['telegram_bot_token'], $settings['telegram_chat_id']);
                return true;

            case 'discord':
                if ( empty($settings['discord_webhook_url']) ) return false;
                self::send_discord($title, $message, 'info', $settings['discord_webhook_url']);
                return true;
        }
        return false;
    }

    // AJAX test handler
    public static function ajax_test() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $channel = sanitize_key( $_POST['channel'] ?? '' );
        $result  = self::test($channel);
        $result ? wp_send_json_success("Test sent to $channel.") : wp_send_json_error("Failed — check settings.");
    }
}

add_action( 'wp_ajax_swps_test_notification', array('SWPS_Notifications','ajax_test') );
