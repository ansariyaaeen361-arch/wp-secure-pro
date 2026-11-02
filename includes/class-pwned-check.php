<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Pwned_Check {

    const API_BASE  = 'https://api.pwnedpasswords.com/range/';
    const CACHE_TTL = 24 * HOUR_IN_SECONDS;

    public static function init() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty($settings['pwned_check_enabled']) ) return;

        add_action( 'user_profile_update_errors', array( __CLASS__, 'check_on_save' ), 10, 3 );
        add_action( 'validate_password_reset',    array( __CLASS__, 'check_on_reset' ), 10, 2 );
        add_action( 'wp_ajax_swps_check_pwned',   array( __CLASS__, 'ajax_check' ) );
    }

    /**
     * Check password against HaveIBeenPwned k-anonymity API.
     * Password is never sent — only first 5 chars of SHA1 hash.
     */
    public static function is_pwned( $password ) {
        $hash    = strtoupper( sha1($password) );
        $prefix  = substr( $hash, 0, 5 );
        $suffix  = substr( $hash, 5 );

        $cache_key = 'swps_pwned_' . $prefix;
        $cached    = get_transient($cache_key);

        if ( $cached === false ) {
            $response = wp_remote_get( self::API_BASE . $prefix, array(
                'timeout'     => 5,
                'user-agent'  => 'WP-Secure-Pro/' . SWPS_VERSION,
            ) );
            if ( is_wp_error($response) ) return null; // API unavailable — don't block
            $cached = wp_remote_retrieve_body($response);
            set_transient($cache_key, $cached, self::CACHE_TTL);
        }

        // Parse response: HASH_SUFFIX:COUNT per line
        foreach ( explode("\n", $cached) as $line ) {
            $parts = explode(':', trim($line));
            if ( count($parts) === 2 && strtoupper($parts[0]) === $suffix ) {
                return intval($parts[1]); // Returns breach count
            }
        }
        return 0; // Not found in breach database
    }

    public static function check_on_save( $errors, $update, $user ) {
        $pass = $user->user_pass ?? '';
        if ( empty($pass) ) return;

        $count = self::is_pwned($pass);
        if ( $count === null ) return; // API failed — skip

        if ( $count > 0 ) {
            $errors->add( 'pwned_password',
                sprintf(
                    'This password has appeared in <strong>%s data breach(es)</strong>. Please choose a different, unique password.',
                    number_format($count)
                )
            );
            SWPS_Activity_Log::add( 'pwned_password_blocked', 'warning',
                "User #{$user->ID} tried to set a breached password (found {$count} times in HaveIBeenPwned)"
            );
        }
    }

    public static function check_on_reset( $errors, $user ) {
        $pass = $_POST['pass1'] ?? '';
        if ( empty($pass) ) return;

        $count = self::is_pwned($pass);
        if ( $count === null ) return;

        if ( $count > 0 ) {
            $errors->add( 'pwned_password',
                sprintf(
                    'This password has appeared in %s known data breach(es). Please choose a unique password.',
                    number_format($count)
                )
            );
        }
    }

    /**
     * AJAX: Check a password from the admin UI (security audit).
     */
    public static function ajax_check() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');

        $pass  = $_POST['password'] ?? '';
        if ( ! $pass ) wp_send_json_error('No password provided.');

        $count = self::is_pwned($pass);

        if ( $count === null ) {
            wp_send_json_success( array( 'status' => 'api_error', 'message' => 'API unavailable — try again later.' ) );
        } elseif ( $count > 0 ) {
            wp_send_json_success( array(
                'status'  => 'pwned',
                'count'   => $count,
                'message' => "This password was found $count time(s) in known data breaches.",
            ) );
        } else {
            wp_send_json_success( array( 'status' => 'safe', 'message' => 'Password not found in any known breach.' ) );
        }
    }

    /**
     * Bulk check all admin users' passwords (uses stored hash — cannot check in plain text).
     * Instead, we check if admin emails are in HaveIBeenPwned account breach.
     */
    public static function check_admin_emails() {
        $settings = get_option( 'swps_settings', array() );
        $api_key  = $settings['hibp_api_key'] ?? '';
        if ( ! $api_key ) return array();

        $admins  = get_users( array('role' => 'administrator') );
        $results = array();

        foreach ( $admins as $user ) {
            $email    = $user->user_email;
            $cache_key = 'swps_hibp_' . md5($email);
            $cached    = get_transient($cache_key);

            if ( $cached === false ) {
                $response = wp_remote_get(
                    'https://haveibeenpwned.com/api/v3/breachedaccount/' . urlencode($email) . '?truncateResponse=true',
                    array(
                        'headers' => array(
                            'hibp-api-key'  => $api_key,
                            'user-agent'    => 'WP-Secure-Pro/' . SWPS_VERSION,
                        ),
                        'timeout' => 5,
                    )
                );

                $code = wp_remote_retrieve_response_code($response);
                if ( $code === 404 ) {
                    $cached = array(); // Not breached
                } elseif ( $code === 200 ) {
                    $cached = json_decode( wp_remote_retrieve_body($response), true ) ?: array();
                } else {
                    $cached = null; // Error
                }

                if ( $cached !== null ) {
                    set_transient($cache_key, $cached, self::CACHE_TTL);
                }
            }

            $results[] = array(
                'user_id'    => $user->ID,
                'user_login' => $user->user_login,
                'email'      => $email,
                'breaches'   => is_array($cached) ? $cached : array(),
                'count'      => is_array($cached) ? count($cached) : 0,
                'status'     => $cached === null ? 'error' : (count((array)$cached) > 0 ? 'breached' : 'safe'),
            );
        }

        return $results;
    }
}
