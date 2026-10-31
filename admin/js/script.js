jQuery(document).ready(function($) {

    // Run Security Scan
    $('#swps-run-scan-btn').on('click', function() {
        var btn = $(this);
        btn.prop('disabled', true).html('<span class="dashicons dashicons-update-alt" style="animation:spin 1s linear infinite"></span> Scanning...');
        $('#swps-scan-progress').show();
        $('#swps-scan-result').hide();

        $.post(swps_vars.url, {
            action: 'swps_run_scan',
            nonce:  swps_vars.nonce
        }, function(response) {
            btn.prop('disabled', false).html('<span class="dashicons dashicons-search"></span> Run Scan Now');
            $('#swps-scan-progress').hide();

            if (response.success) {
                var data     = response.data;
                var threats  = data.threats ? data.threats.length : 0;
                var color    = threats > 0 ? '#e74c3c' : '#27ae60';
                var icon     = threats > 0 ? '⚠️' : '✓';
                var html     = '<div class="swps-alert-inline" style="border-left:4px solid ' + color + ';background:' + (threats > 0 ? '#fde8e8' : '#d4edda') + ';color:' + color + '">';
                html        += icon + ' Scan complete: ' + data.scanned_files + ' files scanned, <strong>' + threats + ' threats</strong> found.</div>';

                if (threats > 0) {
                    html += '<p style="margin-top:10px;font-weight:600">Suspicious files:</p><ul>';
                    $.each(data.threats, function(i, t) {
                        html += '<li><code>' + t.file + '</code>: ' + t.threats.join(', ') + '</li>';
                    });
                    html += '</ul>';
                }

                $('#swps-scan-result').html(html).show();
            } else {
                $('#swps-scan-result').html('<div class="swps-alert-inline swps-critical">Scan failed. Please try again.</div>').show();
            }
        }).fail(function() {
            btn.prop('disabled', false).text('Run Scan Now');
            $('#swps-scan-progress').hide();
            $('#swps-scan-result').html('<div class="swps-alert-inline swps-critical">Request failed. Check your connection.</div>').show();
        });
    });

    // Block IP buttons
    $(document).on('click', '.swps-block-btn', function() {
        var ip  = $(this).data('ip');
        var btn = $(this);
        if (!ip) return;
        if (!confirm('Block IP address: ' + ip + '?')) return;
        btn.prop('disabled', true).text('Blocking...');

        $.post(swps_vars.url, {
            action: 'swps_block_ip',
            nonce:  swps_vars.nonce,
            ip:     ip,
            reason: 'Manual block from dashboard'
        }, function(response) {
            if (response.success) {
                btn.text('Blocked').css({background:'#c0392b',color:'#fff',cursor:'default'}).prop('disabled', true);
                showToast('IP ' + ip + ' has been blocked.', 'success');
                // Fix: the "Currently Blocked IPs" table below is rendered
                // once, server-side, at page load — this AJAX call updates
                // the database but that table has no way to know, so it
                // kept showing "0 blocked" / the IP missing from the list
                // even though the block genuinely succeeded. A reload is
                // the simplest way to guarantee the list is ever accurate
                // after this action.
                setTimeout(function(){ location.reload(); }, 900);
            } else {
                btn.prop('disabled', false).text('Block');
                showToast((response.data && response.data.message) || 'Block failed.', 'error');
            }
        }).fail(function() {
            btn.prop('disabled', false).text('Block');
            showToast('Request failed (server/network error).', 'error');
        });
    });

    // Clear log
    $('#swps-clear-log-btn').on('click', function() {
        if (!confirm('Clear all activity log entries? This cannot be undone.')) return;
        var btn = $(this).prop('disabled', true);
        $.post(swps_vars.url, {
            action: 'swps_clear_log',
            nonce:  swps_vars.nonce
        }, function(response) {
            if (response.success) {
                location.reload();
            } else {
                btn.prop('disabled', false);
                showToast('Clear failed.', 'error');
            }
        }).fail(function() {
            btn.prop('disabled', false);
            showToast('Request failed (server/network error).', 'error');
        });
    });

    // Toast notification
    function showToast(msg, type) {
        var color = type === 'success' ? '#27ae60' : '#e74c3c';
        var toast = $('<div>').text(msg).css({
            position: 'fixed', bottom: '24px', right: '24px',
            background: color, color: '#fff',
            padding: '12px 24px', borderRadius: '8px',
            boxShadow: '0 4px 16px rgba(0,0,0,0.2)',
            zIndex: 99999, fontSize: '14px', fontWeight: '600'
        }).appendTo('body');
        setTimeout(function() { toast.fadeOut(400, function() { toast.remove(); }); }, 3000);
    }

    // Ensure unchecked swps_settings[...] checkboxes submit a 0 (otherwise an
    // unchecked box is simply absent and the toggle can never be turned OFF).
    $(document).on('submit', 'form', function() {
        var $f = $(this);
        $f.find('input[type=checkbox][name^="swps_settings["]').each(function() {
            if (!this.checked) {
                $('<input>', { type: 'hidden', name: this.name, value: '0' }).appendTo($f);
            }
        });
    });

    // CSS spin animation
    $('<style>@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }</style>').appendTo('head');

    // ── Full in-plugin navigation without page reloads ──
    // Fix: both (a) switching a group's internal tab (Firewall & Hardening
    // → WAF/Hardening/Headers, etc.) and (b) switching between the 9
    // sidebar pages themselves used to be plain links, so every click did a
    // full browser reload. Both are now intercepted the same way: fetch the
    // target page's (and, for grouped pages, the target tab's) rendered
    // HTML over admin-ajax and swap it into #swps-page-content. The plain
    // <a href> is left in place as a real fallback (JS off, right-click-
    // open-in-new-tab, bookmarking) and as the shareable/bookmarkable URL.
    function swpsParsePageTab(href) {
        try {
            var u = new URL(href, window.location.origin);
            return { page: u.searchParams.get('page') || '', tab: u.searchParams.get('tab') || '' };
        } catch (e) { return { page: '', tab: '' }; }
    }

    function swpsNavigate($link, href) {
        var pt = swpsParsePageTab(href);
        if (!pt.page || pt.page.indexOf('swps-') !== 0) return false; // not one of our pages — let it navigate normally
        var $content = $('#swps-page-content');
        if (!$content.length) return false; // AJAX nav unavailable on this screen — fall back to a real navigation

        $content.addClass('swps-gtab-loading');
        $.post(swps_vars.url, { action: 'swps_load_page', nonce: swps_vars.nonce, page: pt.page, tab: pt.tab })
            .done(function(res) {
                if (res && res.success) {
                    $content.html(res.data.html); // jQuery .html() re-executes any <script> tags inside
                    if (history.pushState) history.pushState({}, res.data.title || '', href);
                    if (res.data.title) document.title = res.data.title;
                    swpsUpdateSidebarHighlight(pt.page);
                    $('html, body').animate({ scrollTop: 0 }, 150);
                } else {
                    window.location.href = href; // fall back to a real navigation
                }
            })
            .fail(function() {
                window.location.href = href; // network/server error — fall back to a real navigation
            })
            .always(function() {
                $content.removeClass('swps-gtab-loading');
            });
        return true;
    }

    // In-page group tabs (data-tab is set directly by PHP, no need to parse it)
    $(document).on('click', '.swps-gtab', function(e) {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.which === 2) return; // open-in-new-tab etc.
        if ($(this).hasClass('swps-gtab-active')) return;
        if (swpsNavigate($(this), $(this).attr('href'))) e.preventDefault();
    });

    // WordPress's own left sidebar menu, scoped to our plugin's own entries
    $(document).on('click', '#adminmenu a[href*="page=swps-"]', function(e) {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.which === 2) return;
        if (swpsNavigate($(this), $(this).attr('href'))) e.preventDefault();
    });

    // Keeps WP's own left-sidebar highlighting in sync after an AJAX nav —
    // otherwise the PREVIOUS page stays visually marked "current" forever,
    // since that highlighting is normally only computed on a full page load.
    function swpsUpdateSidebarHighlight(page) {
        var $menu = $('#adminmenu');
        $menu.find('li.current, li.wp-has-current-submenu, li.wp-menu-open').removeClass('current wp-has-current-submenu wp-menu-open');
        $menu.find('a.wp-has-current-submenu, a.current').removeClass('wp-has-current-submenu current');
        var $top = $menu.find('> li').has('a[href*="page=swps-dashboard"]').first();
        $top.addClass('wp-has-current-submenu wp-menu-open');
        $top.find('> a').addClass('wp-has-current-submenu');
        var $match = $menu.find('a[href*="page=' + page + '"]').first();
        $match.closest('li').addClass('current');
    }

    // Back/forward after an AJAX nav pushed a new URL: simplest correct
    // behavior is a real reload, since there's no client-side history stack
    // of previously-fetched HTML to restore from.
    window.addEventListener('popstate', function() {
        window.location.reload();
    });
});
