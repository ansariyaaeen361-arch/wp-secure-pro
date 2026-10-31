<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Activity_Log {

    public static function init() {
        // Track plugin activation/deactivation
        add_action( 'activated_plugin',    array( __CLASS__, 'on_plugin_activated' ), 10, 1 );
        add_action( 'deactivated_plugin',  array( __CLASS__, 'on_plugin_deactivated' ), 10, 1 );
        // Track WordPress updates
        add_action( 'upgrader_process_complete', array( __CLASS__, 'on_update' ), 10, 2 );
        // Track option changes
        add_action( 'update_option_siteurl', array( __CLASS__, 'on_siteurl_change' ), 10, 2 );
        // Track user deletion
        add_action( 'delete_user', array( __CLASS__, 'on_user_deleted' ), 10, 1 );
        // Track post publish
        add_action( 'publish_post', array( __CLASS__, 'on_post_published' ), 10, 1 );
        // Track logout
        add_action( 'wp_logout', array( __CLASS__, 'on_logout' ) );
        // Track password change
        add_action( 'password_reset', array( __CLASS__, 'on_password_reset' ), 10, 1 );
    }

    public static function add( $event_type, $severity = 'info', $description = '', $extra = array() ) {
        global $wpdb;

        $current = wp_get_current_user();
        $ip      = SWPS_Login_Protection::get_client_ip();

        $wpdb->insert(
            $wpdb->prefix . SWPS_TABLE_LOG,
            array(
                'event_type'  => $event_type,
                'severity'    => $severity,
                'user_id'     => $current->ID ?? 0,
                'username'    => $current->user_login ?? '',
                'ip_address'  => $ip,
                'description' => $description,
                'extra_data'  => is_array($extra) ? json_encode($extra) : $extra,
                'created_at'  => current_time('mysql'),
            ),
            array('%s','%s','%d','%s','%s','%s','%s','%s')
        );
    }

    public static function on_plugin_activated( $plugin ) {
        self::add( 'plugin_activated', 'info', "Plugin activated: $plugin" );
    }

    public static function on_plugin_deactivated( $plugin ) {
        self::add( 'plugin_deactivated', 'info', "Plugin deactivated: $plugin" );
    }

    public static function on_update( $upgrader, $data ) {
        $type = $data['type'] ?? 'unknown';
        self::add( 'update_installed', 'info', "Update installed: type=$type" );
    }

    public static function on_siteurl_change( $old, $new ) {
        self::add( 'siteurl_changed', 'warning', "Site URL changed from '$old' to '$new'" );
    }

    public static function on_user_deleted( $user_id ) {
        $user = get_userdata( $user_id );
        $name = $user ? $user->user_login : "ID:$user_id";
        self::add( 'user_deleted', 'warning', "User deleted: $name" );
    }

    public static function on_post_published( $post_id ) {
        $post = get_post( $post_id );
        self::add( 'post_published', 'info', "Post published: '{$post->post_title}' (ID: $post_id)" );
    }

    public static function on_logout() {
        $user = wp_get_current_user();
        self::add( 'logout', 'info', "User logged out: {$user->user_login}" );
    }

    public static function on_password_reset( $user ) {
        self::add( 'password_reset', 'warning', "Password reset for: {$user->user_login}", array('user_id' => $user->ID) );
    }

    public static function get_logs( $args = array() ) {
        global $wpdb;
        $defaults = array(
            'limit'    => 50,
            'offset'   => 0,
            'severity' => '',
            'event'    => '',
        );
        $args = wp_parse_args( $args, $defaults );

        $where = 'WHERE 1=1';
        $params = array();

        if ( $args['severity'] ) {
            $where   .= ' AND severity = %s';
            $params[] = $args['severity'];
        }
        if ( $args['event'] ) {
            $where   .= ' AND event_type = %s';
            $params[] = $args['event'];
        }

        $sql = "SELECT * FROM {$wpdb->prefix}swps_activity_log $where ORDER BY created_at DESC LIMIT %d OFFSET %d";
        $params[] = $args['limit'];
        $params[] = $args['offset'];

        if ( ! empty( $params ) ) {
            return $wpdb->get_results( $wpdb->prepare( $sql, $params ) );
        }
        return $wpdb->get_results( $sql );
    }

    public static function get_counts_by_severity() {
        global $wpdb;
        $rows = $wpdb->get_results( "SELECT severity, COUNT(*) as cnt FROM {$wpdb->prefix}swps_activity_log GROUP BY severity" );
        $out = array( 'critical' => 0, 'warning' => 0, 'info' => 0 );
        foreach ( $rows as $row ) $out[ $row->severity ] = (int) $row->cnt;
        return $out;
    }
}
