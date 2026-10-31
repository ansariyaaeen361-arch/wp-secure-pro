<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Captcha {

    public static function init() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty( $settings['captcha_enabled'] ) || empty( $settings['recaptcha_site_key'] ) ) return;

        $on = $settings['captcha_on'] ?? array();

        if ( ! empty( $on['login'] ) ) {
            add_action( 'login_enqueue_scripts', array( __CLASS__, 'enqueue_script' ) );
            add_action( 'login_form',            array( __CLASS__, 'add_captcha_field' ) );
            add_filter( 'authenticate',          array( __CLASS__, 'verify_login' ), 21, 3 );
        }
        if ( ! empty( $on['register'] ) ) {
            add_action( 'register_form',         array( __CLASS__, 'add_captcha_field' ) );
            add_filter( 'registration_errors',   array( __CLASS__, 'verify_registration' ), 10, 3 );
        }
        if ( ! empty( $on['comments'] ) ) {
            add_action( 'comment_form_after_fields', array( __CLASS__, 'add_captcha_field' ) );
            add_filter( 'pre_comment_approved',  array( __CLASS__, 'verify_comment' ), 10, 2 );
        }
        if ( ! empty( $on['lost_password'] ) ) {
            add_action( 'lostpassword_form',     array( __CLASS__, 'add_captcha_field' ) );
            add_action( 'lostpassword_post',     array( __CLASS__, 'verify_lost_password' ) );
        }
    }

    public static function enqueue_script() {
        $settings = get_option( 'swps_settings', array() );
        $key      = $settings['recaptcha_site_key'] ?? '';
        wp_enqueue_script( 'recaptcha-v3', "https://www.google.com/recaptcha/api.js?render={$key}", array(), null, true );
        wp_add_inline_script( 'recaptcha-v3',
            "grecaptcha.ready(function(){
                grecaptcha.execute('{$key}', {action:'submit'}).then(function(token){
                    var fields = document.querySelectorAll('.swps-recaptcha-token');
                    fields.forEach(function(f){ f.value = token; });
                });
            });"
        );
    }

    public static function add_captcha_field() {
        echo '<input type="hidden" name="swps_recaptcha_token" class="swps-recaptcha-token" value="">';
    }

    private static function verify_token( $token ) {
        $settings = get_option( 'swps_settings', array() );
        $secret   = $settings['recaptcha_secret_key'] ?? '';
        if ( ! $secret || ! $token ) return false;

        $response = wp_remote_post( 'https://www.google.com/recaptcha/api/siteverify', array(
            'body' => array( 'secret' => $secret, 'response' => $token, 'remoteip' => SWPS_Login_Protection::get_client_ip() ),
        ) );
        if ( is_wp_error($response) ) return false;
        $body  = json_decode( wp_remote_retrieve_body($response), true );
        $score = $body['score'] ?? 0;
        return ! empty( $body['success'] ) && $score >= 0.5;
    }

    public static function verify_login( $user, $username, $password ) {
        if ( is_wp_error($user) || empty($username) ) return $user;
        $token = sanitize_text_field( $_POST['swps_recaptcha_token'] ?? '' );
        if ( ! self::verify_token($token) ) {
            SWPS_Activity_Log::add( 'captcha_fail_login', 'warning', "reCAPTCHA failed on login for user: $username" );
            return new WP_Error( 'captcha_failed', 'reCAPTCHA verification failed. Please try again.' );
        }
        return $user;
    }

    public static function verify_registration( $errors, $sanitized_user_login, $user_email ) {
        $token = sanitize_text_field( $_POST['swps_recaptcha_token'] ?? '' );
        if ( ! self::verify_token($token) ) {
            $errors->add( 'captcha_failed', 'reCAPTCHA verification failed. Please try again.' );
        }
        return $errors;
    }

    public static function verify_comment( $approved, $commentdata ) {
        $token = sanitize_text_field( $_POST['swps_recaptcha_token'] ?? '' );
        if ( ! self::verify_token($token) ) return 'spam';
        return $approved;
    }

    public static function verify_lost_password( $errors ) {
        $token = sanitize_text_field( $_POST['swps_recaptcha_token'] ?? '' );
        if ( ! self::verify_token($token) ) {
            wp_die( 'reCAPTCHA verification failed. Please go back and try again.' );
        }
    }
}
