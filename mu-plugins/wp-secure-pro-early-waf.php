<?php
/**
 * WP Secure Pro Early WAF
 *
 * Copy this file to wp-content/mu-plugins/ (not the normal plugins folder).
 * It intentionally has no dependency on WordPress, so it runs before normal
 * plugins and reduces exposure from vulnerable plugin bootstrap code.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

/*
 * Self-protection watchdog. This MU-plugin loads before normal plugins, so a
 * WordPress administrator cannot make WP Secure Pro stay deactivated from the
 * Plugins screen. It is deliberately narrow: it protects only this security
 * plugin and never interferes with installing, updating, or managing other
 * plugins. A server/root attacker can remove this file, therefore it is an
 * additional WP-admin safeguard rather than a replacement for server security.
 */
if ( ! function_exists( 'swps_mu_guard_activate' ) ) {
    function swps_mu_guard_activate() {
        $plugin = 'wp-secure-pro/wp-secure-pro.php';
        $file   = WP_PLUGIN_DIR . '/wp-secure-pro/wp-secure-pro.php';
        if ( ! is_readable( $file ) ) return;

        $active = (array) get_option( 'active_plugins', array() );
        if ( ! in_array( $plugin, $active, true ) ) {
            $active[] = $plugin;
            update_option( 'active_plugins', array_values( array_unique( $active ) ) );
            update_option( 'swps_guard_reactivated_at', time(), false );
        }
    }

    function swps_mu_guard_block_deactivation() {
        if ( ! is_admin() || wp_doing_ajax() ) return;
        $action  = sanitize_key( wp_unslash( $_REQUEST['action'] ?? '' ) );
        $targets = array();
        if ( isset( $_REQUEST['plugin'] ) ) $targets[] = sanitize_text_field( wp_unslash( $_REQUEST['plugin'] ) );
        if ( isset( $_REQUEST['checked'] ) && is_array( $_REQUEST['checked'] ) ) {
            foreach ( $_REQUEST['checked'] as $checked ) $targets[] = sanitize_text_field( wp_unslash( $checked ) );
        }
        if ( ! in_array( 'wp-secure-pro/wp-secure-pro.php', $targets, true ) ) return;
        if ( in_array( $action, array( 'deactivate', 'deactivate-selected', 'delete', 'delete-selected' ), true ) ) {
            wp_die( 'WP Secure Pro self-protection blocked this action. Keep the MU guard installed; use a server administrator only for an emergency removal.', 'Security Plugin Protected', array( 'response' => 403 ) );
        }
    }

    add_action( 'muplugins_loaded', 'swps_mu_guard_activate', 1 );
    add_action( 'admin_init', 'swps_mu_guard_block_deactivation', 0 );
}

if ( ! function_exists( 'swps_early_waf_block' ) ) {
    function swps_early_waf_block() {
        if ( ! headers_sent() ) {
            status_header( 403 );
            header( 'X-Content-Type-Options: nosniff' );
            header( 'Cache-Control: no-store' );
        }
        exit( 'Request blocked by WP Secure Pro.' );
    }

    function swps_early_waf_normalize( $value ) {
        $value = is_scalar( $value ) ? (string) $value : '';
        for ( $i = 0; $i < 3; $i++ ) $value = rawurldecode( $value );
        return strtolower( $value );
    }

    $swps_early_input = (string) ( $_SERVER['REQUEST_URI'] ?? '' ) . "\n" . (string) ( $_SERVER['QUERY_STRING'] ?? '' );
    foreach ( $_POST as $swps_early_value ) {
        if ( is_scalar( $swps_early_value ) ) $swps_early_input .= "\n" . $swps_early_value;
    }
    $swps_early_input = swps_early_waf_normalize( $swps_early_input );
    $swps_early_patterns = array(
        '/\x00/', '/\.\.\//', '/\.\.\\\\/', '/php:\/\//', '/data:\/\//',
        '/union\s+(all\s+)?select/', '/(?:sleep|benchmark)\s*\(/',
        '/(?:<script|javascript\s*:|onerror\s*=|onload\s*=)/',
        '/(?:base64_decode|eval|assert)\s*\(/',
    );
    foreach ( $swps_early_patterns as $swps_early_pattern ) {
        if ( preg_match( $swps_early_pattern, $swps_early_input ) ) swps_early_waf_block();
    }
}
