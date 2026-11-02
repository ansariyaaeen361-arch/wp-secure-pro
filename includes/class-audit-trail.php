<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Audit_Trail {

    const TABLE = 'swps_audit_trail';

    public static function init() {
        // WordPress admin actions
        add_action( 'profile_update',           array( __CLASS__, 'on_profile_update' ), 10, 2 );
        add_action( 'deleted_user',             array( __CLASS__, 'on_user_delete' ), 10, 2 );
        add_action( 'set_user_role',            array( __CLASS__, 'on_role_change' ), 10, 3 );
        add_action( 'wp_login',                 array( __CLASS__, 'on_login' ), 10, 2 );
        add_action( 'wp_logout',               array( __CLASS__, 'on_logout' ) );
        add_action( 'switch_theme',            array( __CLASS__, 'on_theme_switch' ), 10, 2 );
        add_action( 'activated_plugin',        array( __CLASS__, 'on_plugin_activate' ) );
        add_action( 'deactivated_plugin',      array( __CLASS__, 'on_plugin_deactivate' ) );
        add_action( 'update_option',           array( __CLASS__, 'on_option_update' ), 10, 3 );
        add_action( 'save_post',               array( __CLASS__, 'on_post_save' ), 10, 3 );
        add_action( 'before_delete_post',      array( __CLASS__, 'on_post_delete' ) );
        add_action( 'add_attachment',          array( __CLASS__, 'on_media_upload' ) );
        add_action( 'wp_ajax_swps_audit_export', array( __CLASS__, 'ajax_export' ) );
        add_action( 'wp_ajax_swps_audit_clear',  array( __CLASS__, 'ajax_clear' ) );
    }

    public static function ajax_clear() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_send_json_error('Unauthorized');
        global $wpdb;
        // DELETE, not TRUNCATE — TRUNCATE needs the DROP privilege, which
        // isn't universally granted on shared hosting; DELETE only needs
        // DELETE, and the result is actually checked instead of assuming
        // success (see the same fix on Activity Log's clear earlier).
        $result = $wpdb->query( "DELETE FROM {$wpdb->prefix}" . self::TABLE );
        if ( $result === false ) {
            wp_send_json_error( 'Could not clear the audit trail: ' . $wpdb->last_error );
        }
        wp_send_json_success( array( 'message' => 'Audit trail cleared.' ) );
    }

    public static function create_table() {
        global $wpdb;
        $table  = $wpdb->prefix . self::TABLE;
        $charset = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE IF NOT EXISTS $table (
            id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id     BIGINT UNSIGNED NOT NULL DEFAULT 0,
            user_login  VARCHAR(60) NOT NULL DEFAULT '',
            action      VARCHAR(100) NOT NULL,
            object_type VARCHAR(50) NOT NULL DEFAULT '',
            object_id   VARCHAR(100) NOT NULL DEFAULT '',
            object_name VARCHAR(255) NOT NULL DEFAULT '',
            details     TEXT,
            ip          VARCHAR(45) NOT NULL DEFAULT '',
            created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_user  (user_id),
            KEY idx_action(action),
            KEY idx_time  (created_at)
        ) $charset;";
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    public static function log( $action, $object_type = '', $object_id = '', $object_name = '', $details = '' ) {
        global $wpdb;
        $user       = wp_get_current_user();
        $user_id    = $user->ID ?? 0;
        $user_login = $user->user_login ?? 'system';

        $wpdb->insert( $wpdb->prefix . self::TABLE, array(
            'user_id'     => $user_id,
            'user_login'  => $user_login,
            'action'      => sanitize_text_field($action),
            'object_type' => sanitize_text_field($object_type),
            'object_id'   => sanitize_text_field($object_id),
            'object_name' => sanitize_text_field($object_name),
            'details'     => sanitize_textarea_field($details),
            'ip'          => SWPS_Login_Protection::get_client_ip(),
            'created_at'  => current_time('mysql'),
        ) );

        // Allow real-time consumers (e.g. SIEM streaming) to react.
        do_action( 'swps_audit_event', $action, $details );
    }

    /* ── Hook handlers ───────────────────────────────────────────────────── */

    public static function on_login( $user_login, $user ) {
        self::log( 'user_login', 'user', $user->ID, $user_login );
    }
    public static function on_logout() {
        $user = wp_get_current_user();
        self::log( 'user_logout', 'user', $user->ID, $user->user_login );
    }
    public static function on_profile_update( $user_id, $old_data ) {
        $new  = get_userdata($user_id);
        $diff = array();
        if ( $old_data->user_email !== $new->user_email ) $diff[] = "email changed";
        if ( $old_data->display_name !== $new->display_name ) $diff[] = "display name changed";
        self::log( 'profile_updated', 'user', $user_id, $new->user_login, implode(', ', $diff) );
    }
    public static function on_user_delete( $user_id, $reassign ) {
        $user = get_userdata($user_id);
        self::log( 'user_deleted', 'user', $user_id, $user ? $user->user_login : "#$user_id" );
    }
    public static function on_role_change( $user_id, $role, $old_roles ) {
        $user = get_userdata($user_id);
        self::log( 'role_changed', 'user', $user_id, $user->user_login ?? "#$user_id",
            'From: ' . implode(',', $old_roles) . ' → To: ' . $role );
    }
    public static function on_theme_switch( $new_name, $new_theme ) {
        self::log( 'theme_activated', 'theme', '', $new_name );
    }
    public static function on_plugin_activate( $plugin ) {
        self::log( 'plugin_activated', 'plugin', '', $plugin );
    }
    public static function on_plugin_deactivate( $plugin ) {
        self::log( 'plugin_deactivated', 'plugin', '', $plugin );
    }
    public static function on_option_update( $option, $old, $new ) {
        // Only log security-relevant options
        $watch = array('siteurl','blogname','admin_email','users_can_register','default_role','blogdescription');
        if ( ! in_array($option, $watch) ) return;
        self::log( 'option_updated', 'option', '', $option, "Old: $old → New: $new" );
    }
    public static function on_post_save( $post_id, $post, $update ) {
        if ( defined('DOING_AUTOSAVE') && DOING_AUTOSAVE ) return;
        if ( wp_is_post_revision($post_id) ) return;
        $action = $update ? 'post_updated' : 'post_created';
        self::log( $action, 'post', $post_id, $post->post_title, 'Status: ' . $post->post_status );
    }
    public static function on_post_delete( $post_id ) {
        $post = get_post($post_id);
        if ( $post ) self::log( 'post_deleted', 'post', $post_id, $post->post_title );
    }
    public static function on_media_upload( $attachment_id ) {
        $file = get_attached_file($attachment_id);
        self::log( 'media_uploaded', 'media', $attachment_id, basename($file ?: '') );
    }

    /* ── Query & Export ─────────────────────────────────────────────────── */

    public static function get_logs( $args = array() ) {
        global $wpdb;
        $table   = $wpdb->prefix . self::TABLE;
        $limit   = intval($args['limit'] ?? 50);
        $offset  = intval($args['offset'] ?? 0);
        $user_id = intval($args['user_id'] ?? 0);
        $action  = sanitize_text_field($args['action'] ?? '');

        $where = array('1=1');
        if ($user_id) $where[] = $wpdb->prepare("user_id = %d", $user_id);
        if ($action)  $where[] = $wpdb->prepare("action = %s", $action);

        $where_sql = implode(' AND ', $where);
        return $wpdb->get_results(
            "SELECT * FROM $table WHERE $where_sql ORDER BY created_at DESC LIMIT $limit OFFSET $offset",
            ARRAY_A
        );
    }

    public static function ajax_export() {
        check_ajax_referer( 'swps_nonce', 'nonce' );
        if ( ! current_user_can('manage_options') ) wp_die('Unauthorized');

        $logs = self::get_logs(array('limit' => 10000));
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="audit-trail-' . date('Y-m-d') . '.csv"');

        $out = fopen('php://output', 'w');
        fputcsv($out, array('Date','User','Action','Object Type','Object','Details','IP'));
        foreach ($logs as $row) {
            fputcsv($out, array($row['created_at'],$row['user_login'],$row['action'],$row['object_type'],$row['object_name'],$row['details'],$row['ip']));
        }
        fclose($out);
        exit;
    }
}
