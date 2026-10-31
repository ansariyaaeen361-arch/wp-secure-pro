<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-location-alt"></span> Live Attack Map</h1>
    <p class="description" style="margin:-8px 0 16px;max-width:760px">
        A world map showing where recent blocked attacks on your site came from. Darker red means more
        attacks from that country. Hover a country to see the exact number.
    </p>

    <?php
    $log     = get_transient(SWPS_Live_Traffic::TRANSIENT_KEY) ?: array();
    $attacks = array_filter($log, fn($e) => ! empty($e['bot']) || SWPS_IP_Blocker::is_blocked($e['ip']));

    $country_counts = array();
    foreach ($attacks as $entry) {
        $country = $entry['country'] ?: 'Unknown';
        $country_counts[$country] = ($country_counts[$country] ?? 0) + 1;
    }
    arsort($country_counts);

    // Map values keyed by ISO-2 code (jsVectorMap uses ISO-2), excluding Unknown.
    $map_values = array();
    foreach ($country_counts as $code => $count) {
        if ($code !== 'Unknown' && strlen($code) === 2) $map_values[strtoupper($code)] = $count;
    }
    $max_attacks = $map_values ? max($map_values) : 0;
    ?>

    <!-- Stats row -->
    <div class="swps-stats-grid" style="max-width:720px">
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-red"><?php echo number_format(count($attacks)); ?></div>
            <div class="swps-stat-label">Attack Requests</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num swps-color-orange"><?php echo count($country_counts); ?></div>
            <div class="swps-stat-label">Countries</div>
        </div>
        <div class="swps-stat-card">
            <div class="swps-stat-num"><?php echo number_format(count($log)); ?></div>
            <div class="swps-stat-label">Total Requests (1h)</div>
        </div>
    </div>

    <!-- World Map -->
    <div class="swps-card">
        <div class="swps-card-header">
            <span class="dashicons dashicons-location-alt"></span> Attack Origin Map (Last Hour)
            <div class="swps-card-actions" style="margin-left:auto">
                <button id="swps-map-refresh" class="swps-btn-sm">Refresh</button>
            </div>
        </div>
        <div class="swps-card-body" style="padding:0">
            <div id="swps-vmap" style="width:100%;height:480px;background:#0f1923;border-radius:0 0 10px 10px"></div>
            <?php if (empty($map_values)): ?>
            <div class="swps-empty" style="padding:16px">No attacks recorded in the last hour. The map will fill in as attacks are blocked.</div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Top attacking countries -->
    <?php if (!empty($country_counts)): ?>
    <div class="swps-card">
        <div class="swps-card-header"><span class="dashicons dashicons-chart-bar"></span> Top Attacking Countries</div>
        <div class="swps-card-body">
        <table class="swps-table swps-table-striped">
            <thead><tr><th>Rank</th><th>Country</th><th>Attacks</th><th>Share</th><th>Action</th></tr></thead>
            <tbody>
            <?php $rank = 1; $total_attacks = array_sum($country_counts); ?>
            <?php foreach (array_slice($country_counts, 0, 15, true) as $country => $count): ?>
            <tr>
                <td><strong>#<?php echo $rank++; ?></strong></td>
                <td>
                    <?php if ($country !== 'Unknown' && strlen($country) === 2): ?>
                    <img src="https://flagcdn.com/16x12/<?php echo strtolower($country); ?>.png" alt="" style="margin-right:6px;vertical-align:middle">
                    <?php endif; ?>
                    <?php echo esc_html($country); ?>
                </td>
                <td><strong><?php echo $count; ?></strong></td>
                <td>
                    <?php $pct = $total_attacks ? round(($count / $total_attacks) * 100) : 0; ?>
                    <div style="display:flex;align-items:center;gap:8px;min-width:120px">
                        <div style="flex:1;height:6px;background:#e0e6ef;border-radius:3px;overflow:hidden">
                            <div style="width:<?php echo $pct; ?>%;height:100%;background:#e74c3c;border-radius:3px"></div>
                        </div>
                        <span class="swps-nowrap"><?php echo $pct; ?>%</span>
                    </div>
                </td>
                <td>
                    <?php if ($country !== 'Unknown' && strlen($country) === 2): ?>
                    <button class="swps-btn-sm swps-geoblock-country" data-country="<?php echo esc_attr($country); ?>">Block Country</button>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
    </div>
    <?php endif; ?>
</div>

<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/css/jsvectormap.min.css">
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/js/jsvectormap.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/maps/world.js"></script>
<script>
jQuery(function($) {
    var values = <?php echo wp_json_encode($map_values ?: new stdClass()); ?>;
    window.swpsAttackValues = values;

    function initMap() {
        if (typeof jsVectorMap === 'undefined') { return; }
        try {
            new jsVectorMap({
                selector: '#swps-vmap',
                map: 'world',
                zoomButtons: true,
                backgroundColor: '#0f1923',
                regionStyle: {
                    initial:  { fill: '#24384a', stroke: '#0f1923', strokeWidth: 0.4 },
                    hover:    { fill: '#f1c40f' }
                },
                series: {
                    regions: [{
                        attribute: 'fill',
                        values: values,
                        scale: ['#ffb3a7', '#e74c3c', '#7b1a10'],
                        normalizeFunction: 'polynomial'
                    }]
                },
                onRegionTooltipShow: function(event, tooltip, code) {
                    var v = values[code] || 0;
                    try { tooltip.text(tooltip.text() + ' — ' + v + ' attack' + (v === 1 ? '' : 's'), true); } catch (e) {}
                }
            });
        } catch (e) { console.warn('SWPS map init failed', e); }
    }
    initMap();

    $('#swps-map-refresh').on('click', function() { location.reload(); });

    $('.swps-geoblock-country').on('click', function() {
        var c = $(this).data('country');
        alert('To block ' + c + ', open: Advanced Settings → Country Blocking (GeoIP), add ' + c + ', and save.');
    });
});
</script>
