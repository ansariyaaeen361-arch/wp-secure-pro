<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Login_URL {

    public static function init() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty( $settings['login_url'] ) ) return;

        add_action( 'init',                   array( __CLASS__, 'intercept' ), 1 );
        add_filter( 'login_url',              array( __CLASS__, 'filter_login_url' ), 10, 3 );
        add_filter( 'logout_url',             array( __CLASS__, 'filter_logout_url' ) );
        add_filter( 'network_site_url',       array( __CLASS__, 'filter_network_url' ), 10, 3 );
        add_filter( 'site_url',               array( __CLASS__, 'filter_site_url' ), 10, 4 );
        add_filter( 'wp_redirect',            array( __CLASS__, 'filter_redirect' ) );
    }

    private static function slug() {
        $settings = get_option( 'swps_settings', array() );
        return sanitize_title( $settings['login_url'] ?? '' );
    }

    public static function intercept() {
        $slug    = self::slug();
        $request = trim( parse_url( $_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH ), '/' );

        // Allow the custom login slug
        if ( $request === $slug ) {
            // Serve wp-login.php content under custom URL
            $_SERVER['REQUEST_URI'] = '/wp-login.php' . ( isset( $_SERVER['QUERY_STRING'] ) && $_SERVER['QUERY_STRING'] ? '?' . $_SERVER['QUERY_STRING'] : '' );
            require_once ABSPATH . 'wp-login.php';
            exit;
        }

        // Block direct access to wp-login.php
        if ( strpos( $request, 'wp-login' ) !== false ) {
            $ip = SWPS_Login_Protection::get_client_ip();
            SWPS_Activity_Log::add( 'login_url_probe', 'warning', "Direct wp-login.php access attempt from $ip — blocked" );
            SWPS_IP_Blocker::block_ip( $ip, 'Probed hidden login URL', 30 );
            status_header( 404 );
            nocache_headers();
            include( get_404_template() );
            exit;
        }

        // Block wp-admin access for non-logged-in users
        if ( strpos( $request, 'wp-admin' ) !== false && ! is_user_logged_in() && ! ( defined('DOING_AJAX') && DOING_AJAX ) ) {
            $ip = SWPS_Login_Protection::get_client_ip();
            SWPS_Activity_Log::add( 'wp_admin_probe', 'warning', "Unauthenticated wp-admin access attempt from $ip" );
            status_header( 404 );
            nocache_headers();
            include( get_404_template() );
            exit;
        }
    }

    public static function filter_login_url( $url, $redirect, $force_reauth ) {
        $slug = self::slug();
        if ( ! $slug ) return $url;
        $new_url = home_url( '/' . $slug . '/' );
        if ( $redirect ) $new_url = add_query_arg( 'redirect_to', urlencode($redirect), $new_url );
        if ( $force_reauth ) $new_url = add_query_arg( 'reauth', '1', $new_url );
        return $new_url;
    }

    public static function filter_logout_url( $url ) {
        $slug = self::slug();
        if ( ! $slug ) return $url;
        return str_replace( site_url( 'wp-login.php', 'login' ), home_url( '/' . $slug . '/' ), $url );
    }

    public static function filter_network_url( $url, $path, $scheme ) {
        $slug = self::slug();
        if ( ! $slug ) return $url;
        if ( strpos( $url, 'wp-login.php' ) !== false ) {
            $url = str_replace( 'wp-login.php', $slug, $url );
        }
        return $url;
    }

    public static function filter_site_url( $url, $path, $scheme, $blog_id ) {
        $slug = self::slug();
        if ( ! $slug ) return $url;
        if ( strpos( $url, 'wp-login.php' ) !== false ) {
            $url = str_replace( 'wp-login.php', $slug, $url );
        }
        return $url;
    }

    public static function filter_redirect( $location ) {
        $slug = self::slug();
        if ( ! $slug ) return $location;
        if ( strpos( $location, 'wp-login.php' ) !== false ) {
            $location = str_replace( 'wp-login.php', $slug, $location );
        }
        return $location;
    }

    public static function get_custom_login_url() {
        $slug = self::slug();
        return $slug ? home_url( '/' . $slug . '/' ) : wp_login_url();
    }
}
