<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Monitors admin user creation - detects content_operator type attacks
 * Fires alert when a new admin is created, especially outside of WordPress UI
 */
class SWPS_Admin_Monitor {

    public static function init() {
        // Trigger when user role is set to administrator
        add_action( 'set_user_role',        array( __CLASS__, 'on_role_change' ), 10, 3 );
        // Trigger on new user registration
        add_action( 'user_register',        array( __CLASS__, 'on_user_register' ), 10, 1 );
        // Check for rogue admins on every admin page load
        add_action( 'admin_init',           array( __CLASS__, 'check_rogue_admins' ) );
        // Also check via WP-Cron every hour
        add_action( 'swps_hourly_check',    array( __CLASS__, 'check_rogue_admins' ) );
        if ( ! wp_next_scheduled( 'swps_hourly_check' ) ) {
            wp_schedule_event( time(), 'hourly', 'swps_hourly_check' );
        }
    }

    /** Save the administrator baseline immediately on a clean activation. */
    public static function establish_baseline() {
        $known = get_option( 'swps_known_admins', array() );
        if ( ! empty( $known ) ) return;
        $admins = get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) );
        update_option( 'swps_known_admins', array_map( 'intval', (array) $admins ), false );
    }

    public static function on_user_register( $user_id ) {
        $user = get_userdata( $user_id );
        if ( ! $user ) return;

        if ( in_array( 'administrator', (array) $user->roles ) ) {
            if ( self::creation_locked( $user_id ) ) {
                self::quarantine_admin( $user_id, 'New administrator creation was blocked.' );
                return;
            }
            $current = wp_get_current_user();
            $via     = $current->ID ? "by user #{$current->ID} ({$current->user_login})" : 'OUTSIDE WordPress (direct DB or API)';

            SWPS_Activity_Log::add(
                'new_admin_user',
                'critical',
                "New admin user created: {$user->user_login} (ID: {$user_id}) - Created {$via}",
                array( 'user_id' => $user_id, 'username' => $user->user_login )
            );

            $settings = get_option( 'swps_settings', array() );
            if ( ! empty( $settings['alert_new_admin'] ) ) {
                SWPS_Email_Alerts::send_alert(
                    'ALERT: New Admin User Created - ' . get_bloginfo('name'),
                    "A new WordPress administrator was just created on your site.\n\n" .
                    "Username  : {$user->user_login}\n" .
                    "Email     : {$user->user_email}\n" .
                    "User ID   : {$user_id}\n" .
                    "Created   : {$via}\n" .
                    "Time      : " . current_time('mysql') . "\n" .
                    "Site URL  : " . get_site_url() . "\n\n" .
                    "If you did NOT create this user, delete it immediately:\n" .
                    admin_url('users.php') . "\n\n" .
                    "This alert was sent by WP Secure Pro."
                );
            }
        }
    }

    public static function on_role_change( $user_id, $new_role, $old_roles ) {
        if ( $new_role !== 'administrator' ) return;
        if ( in_array( 'administrator', (array) $old_roles ) ) return;

        if ( self::creation_locked( $user_id ) ) {
            self::quarantine_admin( $user_id, 'Administrator role assignment was blocked.' );
            return;
        }

        $user    = get_userdata( $user_id );
        $current = wp_get_current_user();

        SWPS_Activity_Log::add(
            'admin_role_granted',
            'critical',
            "User '{$user->user_login}' (ID: {$user_id}) was promoted to Administrator by '{$current->user_login}'",
            array( 'target_user_id' => $user_id )
        );

        $settings = get_option( 'swps_settings', array() );
        if ( ! empty( $settings['alert_new_admin'] ) ) {
            SWPS_Email_Alerts::send_alert(
                'ALERT: User Promoted to Admin - ' . get_bloginfo('name'),
                "A WordPress user was promoted to Administrator.\n\n" .
                "Username    : {$user->user_login}\n" .
                "Promoted by : {$current->user_login}\n" .
                "Time        : " . current_time('mysql') . "\n" .
                "Site URL    : " . get_site_url() . "\n\n" .
                "If you did NOT do this, review immediately:\n" .
                admin_url('users.php')
            );
        }
    }

    public static function check_rogue_admins() {
        global $wpdb;

        $known_admins = get_option( 'swps_known_admins', array() );

        $admins = get_users( array( 'role' => 'administrator', 'fields' => array('ID','user_login','user_email','user_registered') ) );
        $current_ids = array_map( fn($u) => $u->ID, $admins );

        // First run - store known admins
        if ( empty( $known_admins ) ) {
            $known_admins = $current_ids;
            update_option( 'swps_known_admins', $known_admins, false );
            return;
        }

        // Find new admins not in known list
        $new_admins = array_diff( $current_ids, $known_admins );
        foreach ( $new_admins as $uid ) {
            $user = get_userdata( $uid );
            if ( ! $user ) continue;

            $settings = get_option( 'swps_settings', array() );
            if ( ! empty( $settings['admin_creation_lock'] ) ) {
                self::quarantine_admin( $uid, 'Unknown administrator detected by the integrity check.' );
                continue;
            }

            SWPS_Activity_Log::add(
                'rogue_admin_detected',
                'critical',
                "ROGUE ADMIN DETECTED: '{$user->user_login}' (ID: {$uid}) - not in known admins list. Possible direct DB injection!",
                array( 'user_id' => $uid, 'username' => $user->user_login )
            );

            SWPS_Email_Alerts::send_alert(
                'CRITICAL: Unknown Admin User Found - ' . get_bloginfo('name'),
                "WP Secure Pro detected an UNKNOWN ADMINISTRATOR on your site!\n\n" .
                "This user was NOT created through the normal WordPress process.\n" .
                "This is a sign of a hack or database injection attack.\n\n" .
                "Username  : {$user->user_login}\n" .
                "Email     : {$user->user_email}\n" .
                "Registered: {$user->user_registered}\n" .
                "Site URL  : " . get_site_url() . "\n\n" .
                "ACTION REQUIRED: Delete this user immediately:\n" .
                admin_url('user-edit.php?user_id=' . $uid) . "\n\n" .
                "Also change your database and cPanel passwords immediately!"
            );
        }

        // Re-read after quarantine. The prior implementation saved the
        // attacker's ID into the trusted baseline even after demoting it,
        // allowing a later promotion to be accepted as known.
        $remaining = get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) );
        update_option( 'swps_known_admins', array_map( 'intval', (array) $remaining ), false );
    }

    private static function creation_locked( $user_id ) {
        $settings = get_option( 'swps_settings', array() );
        if ( empty( $settings['admin_creation_lock'] ) ) return false;
        $known = array_map( 'intval', (array) get_option( 'swps_known_admins', array() ) );
        // user_register and set_user_role are creation/promotion events; they
        // are never needed for an already-existing administrator. Fail closed
        // even if the first scheduled integrity baseline has not run yet.
        return ! in_array( (int) $user_id, $known, true );
    }

    private static function quarantine_admin( $user_id, $reason ) {
        $user = get_userdata( $user_id );
        if ( ! $user ) return;
        // Preserve the account for evidence, but remove all privileged
        // capabilities immediately. This is safer than irreversible deletion.
        $user->set_role( 'subscriber' );
        update_user_meta( $user_id, 'swps_quarantined_admin', time() );
        SWPS_Activity_Log::add( 'admin_quarantined', 'critical', "$reason User: {$user->user_login} (#$user_id)" );
        SWPS_Email_Alerts::send_alert( 'WP Secure Pro: Unauthorized Admin Blocked', "$reason\nUser: {$user->user_login}\nSite: " . get_site_url() );
    }

    public static function get_all_admins() {
        return get_users( array( 'role' => 'administrator' ) );
    }
}
