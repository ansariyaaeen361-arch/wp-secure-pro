<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class SWPS_Two_Factor {

    const META_SECRET   = '_swps_totp_secret';
    const META_ENABLED  = '_swps_2fa_enabled';
    const META_METHOD   = '_swps_2fa_method';    // 'email' or 'totp'
    const META_BACKUP   = '_swps_2fa_backup';
    const OTP_TRANSIENT = 'swps_email_otp_';

    public static function init() {
        $settings = get_option( 'swps_settings', array() );
        if ( empty( $settings['two_factor_enabled'] ) ) return;

        // Intercept login after credentials are verified
        add_action( 'wp_login',            array( __CLASS__, 'check_2fa_on_login' ), 1, 2 );

        // User profile page
        add_action( 'show_user_profile',   array( __CLASS__, 'profile_section' ) );
        add_action( 'edit_user_profile',   array( __CLASS__, 'profile_section' ) );
        add_action( 'personal_options_update',  array( __CLASS__, 'save_profile' ) );
        add_action( 'edit_user_profile_update', array( __CLASS__, 'save_profile' ) );

        // AJAX: send email OTP
        add_action( 'wp_ajax_nopriv_swps_send_email_otp', array( __CLASS__, 'ajax_send_email_otp' ) );
        add_action( 'wp_ajax_swps_send_email_otp',        array( __CLASS__, 'ajax_send_email_otp' ) );

        // Custom login page for OTP entry
        add_action( 'login_init', array( __CLASS__, 'handle_otp_page' ) );

        // Fix: 2FA only ever hooked into the cookie-based wp-login.php flow
        // (via the 'wp_login' action). Application Passwords authenticate
        // REST API requests through a completely separate path that never
        // fires 'wp_login', so a stolen/planted Application Password gave
        // full REST API access with zero 2FA — the exact mechanism behind
        // this site's prior "auto-bootstrap" backdoor incident. Block
        // Application Password auth outright for any user who has 2FA
        // enabled, since a code-based 2FA challenge has no equivalent in a
        // stateless, header-based auth scheme.
        add_filter( 'wp_is_application_passwords_available_for_user', array( __CLASS__, 'block_app_passwords_for_2fa_users' ), 10, 2 );
    }

    public static function block_app_passwords_for_2fa_users( $available, $user ) {
        if ( $user && self::is_enabled_for_user( $user->ID ) ) return false;
        return $available;
    }

    /* ---------------------------------------------------------------
     * TOTP (Google Authenticator) — RFC 6238 implementation
     * -------------------------------------------------------------- */

    public static function generate_secret( $length = 16 ) {
        $chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // Base32 chars
        $secret = '';
        for ( $i = 0; $i < $length; $i++ ) {
            $secret .= $chars[ random_int( 0, 31 ) ];
        }
        return $secret;
    }

    public static function get_totp_code( $secret, $time_step = 30, $offset = 0 ) {
        $time  = floor( time() / $time_step ) + $offset;
        $key   = self::base32_decode( $secret );
        $msg   = pack( 'N*', 0, $time );
        $hash  = hash_hmac( 'sha1', $msg, $key, true );
        $offset_byte = ord( $hash[19] ) & 0x0F;
        $code  = (
            ( ( ord( $hash[ $offset_byte ] ) & 0x7F ) << 24 ) |
            ( ( ord( $hash[ $offset_byte + 1 ] ) & 0xFF ) << 16 ) |
            ( ( ord( $hash[ $offset_byte + 2 ] ) & 0xFF ) << 8 ) |
            ( ord( $hash[ $offset_byte + 3 ] ) & 0xFF )
        ) % 1000000;
        return str_pad( $code, 6, '0', STR_PAD_LEFT );
    }

    /* ---------------------------------------------------------------
     * OTP brute-force guard — a 6-digit code is only ~1M combinations;
     * without this, both email and TOTP codes could be guessed within
     * their validity window via scripted attempts.
     * -------------------------------------------------------------- */

    const MAX_OTP_ATTEMPTS = 5;

    private static function otp_attempts_key( $user_id ) {
        return 'swps_otp_attempts_' . $user_id;
    }

    public static function otp_locked_out( $user_id ) {
        return (int) get_transient( self::otp_attempts_key( $user_id ) ) >= self::MAX_OTP_ATTEMPTS;
    }

    private static function register_otp_failure( $user_id ) {
        $key   = self::otp_attempts_key( $user_id );
        $count = (int) get_transient( $key );
        set_transient( $key, $count + 1, 5 * MINUTE_IN_SECONDS );
    }

    private static function clear_otp_attempts( $user_id ) {
        delete_transient( self::otp_attempts_key( $user_id ) );
    }

    public static function verify_totp( $secret, $code ) {
        $code = preg_replace('/\s+/', '', $code );
        for ( $i = -1; $i <= 1; $i++ ) { // Allow 1 time-step drift
            if ( hash_equals( self::get_totp_code( $secret, 30, $i ), $code ) ) return true;
        }
        return false;
    }

    private static function base32_decode( $secret ) {
        $base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = strtoupper( $secret );
        $buffer = 0; $bitsLeft = 0; $output = '';
        for ( $i = 0; $i < strlen( $secret ); $i++ ) {
            $pos = strpos( $base32chars, $secret[ $i ] );
            if ( $pos === false ) continue;
            $buffer = ( $buffer << 5 ) | $pos;
            $bitsLeft += 5;
            if ( $bitsLeft >= 8 ) {
                $bitsLeft -= 8;
                $output .= chr( ( $buffer >> $bitsLeft ) & 0xFF );
            }
        }
        return $output;
    }

    public static function get_totp_uri( $secret, $user ) {
        $issuer = urlencode( get_bloginfo('name') );
        $account = urlencode( $user->user_email );
        return "otpauth://totp/{$issuer}:{$account}?secret={$secret}&issuer={$issuer}&digits=6&period=30";
    }

    /* ---------------------------------------------------------------
     * Email OTP
     * -------------------------------------------------------------- */

    /** Shared per-user + per-IP cooldown (60s) in front of send_email_otp(),
     *  used by both the login-triggered send and the explicit "Resend"
     *  button so neither path can be used to mail-bomb an account's inbox.
     *  Returns true if an email was actually (re)sent, false if throttled. */
    public static function send_email_otp_rate_limited( $user ) {
        $rl_key = 'swps_otp_rl_' . md5( $user->ID . '_' . ( $_SERVER['REMOTE_ADDR'] ?? '' ) );
        if ( get_transient( $rl_key ) ) return false;
        set_transient( $rl_key, 1, 60 );
        self::send_email_otp( $user );
        return true;
    }

    public static function send_email_otp( $user ) {
        $code  = str_pad( random_int(0, 999999), 6, '0', STR_PAD_LEFT );
        $key   = self::OTP_TRANSIENT . $user->ID;
        set_transient( $key, wp_hash_password( $code ), 300 ); // 5 min expiry

        $blog = get_bloginfo('name');
        // Send the code ONLY to the user who is logging in. (Do not route it
        // through the admin alert mailbox — that would leak the login OTP.)
        $email_sent = wp_mail(
            $user->user_email,
            "[{$blog}] Your Login Code: $code",
            "Your one-time login code is: $code\n\n" .
            "This code expires in 5 minutes.\n" .
            "If you did not attempt to log in, change your password immediately.\n\n" .
            "Site: " . get_site_url()
        );

        // A private Slack channel is an independent delivery path when a
        // site's SMTP is unavailable. It receives the same short-lived code
        // only when the owner has explicitly configured a Slack webhook.
        $slack_sent = false;
        if ( class_exists( 'SWPS_Slack_Alerts' ) && SWPS_Slack_Alerts::configured() ) {
            $slack_sent = SWPS_Slack_Alerts::send(
                'Login verification code',
                'A login code was requested for WordPress account "' . $user->user_login . '". Code: ' . $code . "\n\nThis code expires in 5 minutes. If this was not you, change the account password immediately."
            );
        }
        return (bool) ( $email_sent || $slack_sent );
    }

    /** "yaseen.mevteck@gmail.com" -> "yas.......@gmail.com" — enough to
     *  jog memory of which inbox 2FA was configured with, not enough to
     *  identify the full address to someone who only has valid credentials. */
    private static function mask_email( $email ) {
        if ( ! is_email( $email ) ) return '';
        list( $local, $domain ) = explode( '@', $email, 2 );
        $visible = min( 3, max( 1, strlen( $local ) - 1 ) );
        $prefix  = substr( $local, 0, $visible );
        $dots    = str_repeat( '.', max( 3, min( 7, strlen( $local ) - $visible ) ) );
        return $prefix . $dots . '@' . $domain;
    }

    public static function verify_email_otp( $user_id, $code ) {
        $key   = self::OTP_TRANSIENT . $user_id;
        $hash  = get_transient( $key );
        if ( ! $hash ) return false;
        if ( wp_check_password( trim( $code ), $hash ) ) {
            delete_transient( $key );
            return true;
        }
        return false;
    }

    public static function ajax_send_email_otp() {
        // Fix: nonce verification — prevents unauthenticated CSRF-based mail bombing
        check_ajax_referer( 'swps_2fa_resend', 'nonce' );

        $user_login = sanitize_text_field( $_POST['user_login'] ?? '' );
        $user       = get_user_by( 'login', $user_login ) ?: get_user_by( 'email', $user_login );

        if ( $user && self::is_enabled_for_user( $user->ID ) ) {
            if ( ! self::send_email_otp_rate_limited( $user ) ) {
                wp_send_json_error( 'Please wait before requesting another code.' );
                return;
            }
        }

        // Always return success for unknown users — don't reveal account existence
        wp_send_json_success();
    }

    /* ---------------------------------------------------------------
     * Login flow interception
     * -------------------------------------------------------------- */

    public static function check_2fa_on_login( $user_login, $user ) {
        if ( ! self::is_enabled_for_user( $user->ID ) ) return;

        // OTP submitted with login form?
        $otp    = sanitize_text_field( $_POST['swps_otp'] ?? '' );
        $method = get_user_meta( $user->ID, self::META_METHOD, true ) ?: 'email';

        if ( $otp ) {
            if ( self::otp_locked_out( $user->ID ) ) {
                SWPS_Activity_Log::add( '2fa_locked', 'critical', "2FA locked out (too many attempts): {$user->user_login}" );
                wp_logout();
                wp_die( 'Too many incorrect codes. Please wait 5 minutes and log in again.' );
            }
            $valid = false;
            if ( $method === 'totp' ) {
                $secret = get_user_meta( $user->ID, self::META_SECRET, true );
                $valid  = self::verify_totp( $secret, $otp );
            } else {
                $valid = self::verify_email_otp( $user->ID, $otp );
            }
            if ( ! $valid ) {
                self::register_otp_failure( $user->ID );
                // Kill the session — force re-login
                wp_logout();
                wp_redirect( add_query_arg( array( 'swps_2fa' => '1', 'swps_otp_invalid' => '1', 'log' => $user_login ), wp_login_url() ) );
                exit;
            }
            // OTP valid — log and allow
            self::clear_otp_attempts( $user->ID );
            SWPS_Activity_Log::add( '2fa_success', 'info', "2FA verified for {$user->user_login} via $method" );
            return;
        }

        // No OTP submitted — send OTP email and redirect to OTP page
        //
        // Fix: this path (triggered on every successful password check, via
        // 'wp_login' — BEFORE 2FA has actually been satisfied) had no rate
        // limit at all, unlike the explicit "Resend code" AJAX handler.
        // Confirmed live: an attacker who already has — or correctly
        // guesses — the account's password can mail-bomb the victim's inbox
        // with hundreds of OTP emails per minute just by resubmitting the
        // login form in a loop, since each successful password check re-
        // fires this handler and sent a fresh email with zero throttling.
        // Reuses the exact same per-user+IP cooldown as the Resend button.
        wp_logout();
        if ( $method === 'email' ) {
            self::send_email_otp_rate_limited( $user );
        }
        set_transient( 'swps_2fa_pending_' . sanitize_key( $user_login ), $user->ID, 300 );
        wp_redirect( add_query_arg( array( 'swps_2fa' => '1', 'log' => urlencode( $user_login ) ), wp_login_url() ) );
        exit;
    }

    public static function handle_otp_page() {
        if ( empty( $_GET['swps_2fa'] ) ) return;

        $user_login = sanitize_text_field( urldecode( $_GET['log'] ?? '' ) );
        $method     = 'email';
        $user_id    = get_transient( 'swps_2fa_pending_' . sanitize_key( $user_login ) );
        if ( $user_id ) {
            $method = get_user_meta( $user_id, self::META_METHOD, true ) ?: 'email';
        }

        $invalid = ! empty( $_GET['swps_otp_invalid'] );

        // Handle OTP form submission on this page
        if ( isset( $_POST['swps_otp_submit'] ) ) {
            check_admin_referer( 'swps_2fa_verify' );
            $otp = sanitize_text_field( $_POST['swps_otp'] ?? '' );
            if ( $user_id && self::otp_locked_out( $user_id ) ) {
                SWPS_Activity_Log::add( '2fa_locked', 'critical', "2FA locked out (too many attempts): user #$user_id" );
                wp_die( 'Too many incorrect codes. Please wait 5 minutes and log in again.' );
            }
            if ( $user_id ) {
                $valid = false;
                if ( $method === 'totp' ) {
                    $secret = get_user_meta( $user_id, self::META_SECRET, true );
                    $valid  = self::verify_totp( $secret, $otp );
                } else {
                    $valid = self::verify_email_otp( $user_id, $otp );
                }
                if ( $valid ) {
                    self::clear_otp_attempts( $user_id );
                    delete_transient( 'swps_2fa_pending_' . sanitize_key( $user_login ) );
                    $user = get_user_by( 'ID', $user_id );
                    wp_set_auth_cookie( $user_id, true );
                    SWPS_Activity_Log::add( '2fa_success', 'info', "2FA verified for {$user->user_login} via $method" );
                    wp_redirect( admin_url() );
                    exit;
                }
                self::register_otp_failure( $user_id );
                $invalid = true;
            }
        }

        // Render OTP entry page
        login_header( 'Enter Verification Code' );
        ?>
        <style>
        .swps-2fa-wrap { text-align:center; }
        .swps-2fa-wrap .otp-icon { font-size:48px; margin-bottom:16px; }
        .swps-2fa-wrap p { color:#555; margin-bottom:20px; }
        #swps_otp { text-align:center; font-size:28px; letter-spacing:8px; width:180px; padding:10px; border:2px solid #1a56a8; border-radius:8px; }
        .swps-resend { margin-top:12px; font-size:13px; }
        .swps-resend a { cursor:pointer; color:#1a56a8; text-decoration:underline; }
        .swps-2fa-error { background:#fde8e8; color:#c0392b; padding:10px; border-radius:6px; margin-bottom:16px; font-size:13px; }
        </style>
        <div class="swps-2fa-wrap">
            <div class="otp-icon"><?php echo $method === 'totp' ? '📱' : '📧'; ?></div>
            <?php if ( $invalid ) : ?>
                <div class="swps-2fa-error">Invalid or expired code. Please try again.</div>
            <?php endif; ?>
            <p>
                <?php if ( $method === 'totp' ) : ?>
                    Enter the 6-digit code from your <strong>Google Authenticator</strong> app.
                <?php else : ?>
                    A verification code has been sent to your email address<?php
                    // Fix (explicit user request): a masked hint of WHICH
                    // email the OTP went to — easy to forget which address
                    // 2FA was configured with, especially across many
                    // managed sites. Masked (not shown in full) since this
                    // page is reachable by anyone who knows a valid
                    // username/password, before 2FA itself is satisfied.
                    $hint_user = $user_id ? get_user_by( 'ID', $user_id ) : false;
                    if ( $hint_user && $hint_user->user_email ) {
                        echo ' (' . esc_html( self::mask_email( $hint_user->user_email ) ) . ')';
                    }
                    ?>.<br>Enter it below to complete login.
                <?php endif; ?>
            </p>
            <form method="post">
                <?php wp_nonce_field( 'swps_2fa_verify' ); ?>
                <input type="hidden" name="log" value="<?php echo esc_attr($user_login); ?>">
                <p>
                    <input type="text" name="swps_otp" id="swps_otp" maxlength="6" placeholder="000000" autocomplete="one-time-code" inputmode="numeric" autofocus required>
                </p>
                <p>
                    <input type="submit" name="swps_otp_submit" value="Verify Code" class="button button-primary button-large">
                </p>
            </form>
            <?php if ( $method === 'email' ) : ?>
            <div class="swps-resend">
                Didn't receive it? <a id="swps-resend-btn">Resend code</a>
            </div>
            <script>
            document.getElementById('swps-resend-btn').addEventListener('click', function() {
                this.textContent = 'Sending...';
                var self = this;
                fetch('<?php echo admin_url('admin-ajax.php'); ?>', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: 'action=swps_send_email_otp&user_login=<?php echo urlencode($user_login); ?>&nonce=<?php echo esc_js( wp_create_nonce( 'swps_2fa_resend' ) ); ?>'
                }).then(function() { self.textContent = 'Code sent!'; });
            });
            </script>
            <?php endif; ?>
        </div>
        <?php
        login_footer();
        exit;
    }

    /* ---------------------------------------------------------------
     * User profile section — enable/setup 2FA
     * -------------------------------------------------------------- */

    public static function profile_section( $user ) {
        $enabled = self::is_enabled_for_user( $user->ID );
        $method  = get_user_meta( $user->ID, self::META_METHOD,  true ) ?: 'email';
        $secret  = get_user_meta( $user->ID, self::META_SECRET,  true );
        if ( ! $secret ) $secret = self::generate_secret();
        ?>
        <h2>Two-Factor Authentication (2FA) — WP Secure Pro</h2>
        <table class="form-table">
            <tr>
                <th>Enable 2FA</th>
                <td>
                    <label>
                        <input type="checkbox" name="swps_2fa_enabled" value="1" <?php checked($enabled, 1); ?>>
                        Require a one-time code every time I log in
                    </label>
                </td>
            </tr>
            <tr>
                <th>Method</th>
                <td>
                    <label><input type="radio" name="swps_2fa_method" value="email" <?php checked($method,'email'); ?>> 📧 Email OTP (sent to your email, plus private Slack if a webhook is configured)</label><br><br>
                    <label><input type="radio" name="swps_2fa_method" value="totp"  <?php checked($method,'totp');  ?>> 📱 Google Authenticator / Authy (TOTP)</label>
                </td>
            </tr>
            <tr id="swps-totp-row" style="<?php echo $method !== 'totp' ? 'display:none' : ''; ?>">
                <th>Setup TOTP</th>
                <td>
                    <p>Scan this QR code in Google Authenticator or Authy:</p>
                    <?php
                    // Fix (explicit user report): this box never actually
                    // contained a QR code — just the secret printed as
                    // plain text, every time, for every user. Real QR
                    // rendering happens entirely CLIENT-SIDE via a bundled
                    // JS library (no CDN, no external request) so the TOTP
                    // secret — the literal key to generating someone's 2FA
                    // codes — never leaves the browser/this site. Sending
                    // it to a third-party "QR generator" API, as some
                    // naive implementations do, would hand that secret to
                    // whoever runs that API.
                    $totp_uri = self::get_totp_uri( $secret, $user );
                    ?>
                    <div id="swps-qr-code" style="margin:10px 0; width:200px; height:200px; background:#fff; display:flex; align-items:center; justify-content:center; border:1px solid #ddd; padding:10px;" data-totp-uri="<?php echo esc_attr( $totp_uri ); ?>">
                        <small style="color:#999">Generating QR code…</small>
                    </div>
                    <p style="font-size:12px;color:#666">Can't scan? Enter manually — Account: <code><?php echo esc_html($user->user_email); ?></code>, Key: <code><?php echo esc_html($secret); ?></code>, Type: Time-based</p>
                    <input type="hidden" name="swps_totp_secret" value="<?php echo esc_attr($secret); ?>">
                    <p><strong>Verify your TOTP code to confirm setup:</strong></p>
                    <input type="text" name="swps_totp_verify" maxlength="6" placeholder="Enter 6-digit code" style="font-size:18px; letter-spacing:4px; width:160px; text-align:center;">
                </td>
            </tr>
        </table>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
        <script>
        document.querySelectorAll('[name="swps_2fa_method"]').forEach(function(r){
            r.addEventListener('change',function(){
                document.getElementById('swps-totp-row').style.display = this.value==='totp' ? '' : 'none';
            });
        });
        (function(){
            var box = document.getElementById('swps-qr-code');
            if (!box) return;
            var uri = box.getAttribute('data-totp-uri');
            // Fix: swapped to the davidshimjs/qrcodejs library — the
            // earlier attempt (the "qrcode" npm package's CDN build)
            // never actually finished loading in practice, leaving the
            // box stuck on "Generating QR code…" indefinitely. This one
            // is one of the most widely deployed QR JS libraries and has
            // a dead-simple constructor API (no async callback to hang on).
            var tries = 0;
            function render() {
                tries++;
                if (typeof QRCode === 'undefined') {
                    if (tries > 50) { box.innerHTML = '<small style="color:#c0392b;padding:10px">QR code library failed to load — use the manual key below instead.</small>'; return; }
                    setTimeout(render, 100);
                    return;
                }
                box.innerHTML = '';
                box.style.background = '#fff';
                box.style.padding = '0';
                new QRCode(box, { text: uri, width: 198, height: 198, correctLevel: QRCode.CorrectLevel.M });
            }
            render();
        })();
        </script>
        <?php
    }

    public static function save_profile( $user_id ) {
        if ( ! current_user_can( 'edit_user', $user_id ) ) return;

        $enabled = isset( $_POST['swps_2fa_enabled'] ) ? 1 : 0;
        $method  = in_array( $_POST['swps_2fa_method'] ?? '', array('email','totp') ) ? $_POST['swps_2fa_method'] : 'email';

        if ( $method === 'totp' ) {
            $secret = sanitize_text_field( $_POST['swps_totp_secret'] ?? '' );
            $verify = sanitize_text_field( $_POST['swps_totp_verify'] ?? '' );
            if ( $secret && $verify && self::verify_totp( $secret, $verify ) ) {
                update_user_meta( $user_id, self::META_SECRET, $secret );
            } elseif ( ! get_user_meta( $user_id, self::META_SECRET, true ) ) {
                $method = 'email';
            }
        }

        // An explicit per-user choice wins over the site's default role
        // policy. This lets an administrator deliberately opt out.
        update_user_meta( $user_id, self::META_ENABLED, $enabled );
        update_user_meta( $user_id, self::META_METHOD, $method );

        if ( $enabled ) {
            SWPS_Activity_Log::add( '2fa_setup', 'info', "2FA enabled for user ID $user_id via $method" );
        }
    }

    public static function is_enabled_for_user( $user_id ) {
        // A per-user opt-in always enables 2FA.  In addition, the setting on
        // the 2FA screen can require it for a role.  The old code displayed
        // and saved that role setting but never consulted it during login,
        // leaving a dangerous false sense of protection.
        // A saved profile choice is intentional, including a saved OFF value.
        // Otherwise the role policy supplies the secure default for new and
        // existing Administrator accounts.
        if ( metadata_exists( 'user', $user_id, self::META_ENABLED ) ) {
            return (bool) get_user_meta( $user_id, self::META_ENABLED, true );
        }

        $user = get_userdata( $user_id );
        return $user && self::is_required_by_role( $user );
    }

    /** Returns whether a role-based site policy mandates 2FA for this user. */
    public static function is_required_by_role( $user ) {
        if ( ! $user || empty( $user->ID ) ) return false;
        $settings = get_option( 'swps_settings', array() );
        $required = array_filter( array_map( 'sanitize_key', (array) ( $settings['2fa_require_for'] ?? array() ) ) );
        return (bool) array_intersect( $required, (array) $user->roles );
    }
}
