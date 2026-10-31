<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Progressive_Brute_Force {

    const DELAY_KEY   = 'swps_pbf_delay_';
    const ATTEMPT_KEY = 'swps_pbf_attempts_';

    public static function init() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty($settings['progressive_bf_enabled']) ) return;

        // Runs AFTER core login check (priority 30)
        add_filter( 'authenticate',       array( __CLASS__, 'apply_delay' ), 30, 3 );
        add_action( 'wp_login_failed',    array( __CLASS__, 'on_failed' ) );
        add_action( 'wp_login',           array( __CLASS__, 'on_success' ), 10, 2 );
    }

    /**
     * Apply progressive delay before authentication proceeds.
     */
    public static function apply_delay( $user, $username, $password ) {
        if ( empty($username) ) return $user;

        $ip       = SWPS_Login_Protection::get_client_ip();
        $key      = self::DELAY_KEY . md5($ip . $username);
        $attempts = intval( get_transient($key) );

        if ( $attempts >= 2 ) {
            // Exponential delay: 2^(attempts-2) seconds, max 32s
            $delay = min( pow(2, $attempts - 2), 32 );
            sleep( intval($delay) );
        }

        return $user;
    }

    public static function on_failed( $username ) {
        $ip       = SWPS_Login_Protection::get_client_ip();
        $key      = self::ATTEMPT_KEY . md5($ip . $username);
        $delay_key= self::DELAY_KEY   . md5($ip . $username);

        $attempts = intval( get_transient($key) ) + 1;
        set_transient( $key,       $attempts, 30 * MINUTE_IN_SECONDS );
        set_transient( $delay_key, $attempts, 30 * MINUTE_IN_SECONDS );

        $settings  = get_option( 'swps_settings', array() );
        $threshold = intval( $settings['captcha_trigger_after'] ?? 3 );

        // Trigger CAPTCHA enforcement after N fails (log event)
        if ( $attempts >= $threshold ) {
            SWPS_Activity_Log::add( 'progressive_bf', 'warning',
                "Progressive brute force: $attempts failed attempts for '$username' from $ip — increased delay active"
            );
        }

        // Hard block after extreme attempts
        $hard_limit = intval( $settings['max_login_attempts'] ?? 5 );
        if ( $attempts >= $hard_limit * 2 ) {
            SWPS_IP_Blocker::block_ip( $ip, "Progressive brute force — $attempts attempts for '$username'", 120 );
        }
    }

    public static function on_success( $user_login, $user ) {
        $ip       = SWPS_Login_Protection::get_client_ip();
        $key      = self::ATTEMPT_KEY . md5($ip . $user_login);
        $delay_key= self::DELAY_KEY   . md5($ip . $user_login);
        delete_transient($key);
        delete_transient($delay_key);
    }

    /**
     * Get current delay level for an IP+username combo.
     */
    public static function get_delay_info( $ip, $username ) {
        $key      = self::ATTEMPT_KEY . md5($ip . $username);
        $attempts = intval( get_transient($key) );
        $delay    = $attempts >= 2 ? min( pow(2, $attempts - 2), 32 ) : 0;
        return array(
            'attempts' => $attempts,
            'delay_s'  => $delay,
            'level'    => $attempts === 0 ? 'clean' : ( $delay >= 16 ? 'high' : ( $delay >= 4 ? 'medium' : 'low' ) ),
        );
    }
}
