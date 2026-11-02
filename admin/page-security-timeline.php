<?php if ( ! defined('ABSPATH') ) exit; ?>
<div class="wrap swps-wrap">
    <h1 class="swps-page-title"><span class="dashicons dashicons-chart-area"></span> Security Timeline</h1>
    <p class="description" style="margin:-8px 0 16px;max-width:760px">
        A visual history of security events over time, so you can quickly see trends and notice unusual
        spikes in attacks or warnings.
    </p>

    <?php
    global $wpdb;
    $table = $wpdb->prefix . SWPS_TABLE_LOG;

    // Build 7-day chart data
    $days_data = array();
    for ($i = 6; $i >= 0; $i--) {
        $date  = date('Y-m-d', strtotime("-$i days"));
        $label = date('M j', strtotime("-$i days"));
        $counts = $wpdb->get_row($wpdb->prepare(
            "SELECT
                COUNT(*) as total,
                SUM(severity='critical') as critical,
                SUM(severity='warning') as warning,
                SUM(severity='info') as info
             FROM $table WHERE DATE(created_at) = %s", $date
        ), ARRAY_A);
        $days_data[] = array(
            'label'    => $label,
            'date'     => $date,
            'total'    => intval($counts['total'] ?? 0),
            'critical' => intval($counts['critical'] ?? 0),
            'warning'  => intval($counts['warning'] ?? 0),
            'info'     => intval($counts['info'] ?? 0),
        );
    }

    // 24-hour hourly data
    $hours_data = array();
    for ($h = 23; $h >= 0; $h--) {
        $from  = date('Y-m-d H:i:s', strtotime("-$h hours"));
        $to    = date('Y-m-d H:i:s', strtotime("-" . ($h-1) . " hours"));
        $count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $table WHERE created_at BETWEEN %s AND %s", $from, $to));
        $hours_data[] = array('label' => date('Ha', strtotime("-$h hours")), 'count' => intval($count));
    }
    ?>

    <!-- Charts -->
    <div class="swps-grid-2col">

        <!-- 7-Day Timeline -->
        <div class="swps-card">
            <h2>7-Day Security Events</h2>
            <canvas id="swps-weekly-chart" height="200"></canvas>
        </div>

        <!-- 24-Hour Timeline -->
        <div class="swps-card">
            <h2>24-Hour Activity</h2>
            <canvas id="swps-hourly-chart" height="200"></canvas>
        </div>
    </div>

    <!-- Event Type Breakdown -->
    <div class="swps-grid-2col">
        <div class="swps-card">
            <h2>Event Types (Last 7 Days)</h2>
            <canvas id="swps-event-types-chart" height="200"></canvas>
        </div>
        <div class="swps-card">
            <h2>Severity Distribution</h2>
            <canvas id="swps-severity-chart" height="200"></canvas>
        </div>
    </div>

    <!-- Top Events Table -->
    <div class="swps-card">
        <h2>Top Event Types (Last 30 Days)</h2>
        <?php
        $top_events = $wpdb->get_results("
            SELECT event_type, COUNT(*) as count, severity
            FROM $table
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY event_type
            ORDER BY count DESC
            LIMIT 15
        ", ARRAY_A);
        ?>
        <table class="swps-table widefat striped">
            <thead><tr><th>Event Type</th><th>Count</th><th>Severity</th><th>Last 7 Days</th></tr></thead>
            <tbody>
            <?php foreach ($top_events as $event): ?>
            <?php
                $badge = $event['severity'] === 'critical' ? 'swps-badge-critical' : ($event['severity'] === 'warning' ? 'swps-badge-warning' : 'swps-badge-ok');
                $last7 = $wpdb->get_var($wpdb->prepare(
                    "SELECT COUNT(*) FROM $table WHERE event_type = %s AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)",
                    $event['event_type']
                ));
            ?>
            <tr>
                <td><code><?php echo esc_html($event['event_type']); ?></code></td>
                <td><strong><?php echo number_format($event['count']); ?></strong></td>
                <td><span class="swps-badge <?php echo $badge; ?>"><?php echo esc_html($event['severity']); ?></span></td>
                <td>
                    <div style="display:flex;align-items:center;gap:8px">
                        <div style="width:80px;height:6px;background:#e0e6ef;border-radius:3px;overflow:hidden">
                            <div style="width:<?php echo min(round(($last7/$event['count'])*100), 100); ?>%;height:100%;background:var(--swps-primary);border-radius:3px"></div>
                        </div>
                        <?php echo $last7; ?>
                    </div>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script>
jQuery(document).ready(function($) {

    // Fix (live — confirmed all 4 charts on this page rendered blank):
    // Chart.js loads from an external <script src> tag that the group-tab
    // AJAX nav system injects right alongside this inline script — a
    // browser doesn't reliably finish that external load before the next
    // inline <script> block runs when it's injected this way (unlike
    // normal top-to-bottom HTML parsing), so `new Chart(...)` below could
    // run before the Chart global even existed, throwing immediately and
    // leaving every chart's canvas empty with no visible error. Same fix
    // pattern as the Attack Map and the 2FA QR code's library loads.
    var chartTries = 0;
    function initCharts() {
        if (typeof Chart === 'undefined') {
            chartTries++;
            if (chartTries > 50) {
                $('#swps-weekly-chart, #swps-hourly-chart, #swps-event-types-chart, #swps-severity-chart').each(function(){
                    $(this).replaceWith('<p style="color:#f87171;text-align:center;padding:20px">Chart library failed to load — check your connection and refresh.</p>');
                });
                return;
            }
            setTimeout(initCharts, 100);
            return;
        }

    Chart.defaults.color = '#7f8c8d';
    Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';

    var weeklyData = <?php echo json_encode($days_data); ?>;
    var hourlyData = <?php echo json_encode($hours_data); ?>;

    // Weekly chart
    new Chart(document.getElementById('swps-weekly-chart'), {
        type: 'bar',
        data: {
            labels: weeklyData.map(d => d.label),
            datasets: [
                {
                    label: 'Critical',
                    data: weeklyData.map(d => d.critical),
                    backgroundColor: 'rgba(231,76,60,0.8)',
                    borderRadius: 4,
                },
                {
                    label: 'Warning',
                    data: weeklyData.map(d => d.warning),
                    backgroundColor: 'rgba(243,156,18,0.8)',
                    borderRadius: 4,
                },
                {
                    label: 'Info',
                    data: weeklyData.map(d => d.info),
                    backgroundColor: 'rgba(41,128,185,0.5)',
                    borderRadius: 4,
                },
            ]
        },
        options: {
            responsive: true,
            plugins: { legend: { position: 'top' } },
            scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } }
        }
    });

    // Hourly chart
    new Chart(document.getElementById('swps-hourly-chart'), {
        type: 'line',
        data: {
            labels: hourlyData.map(d => d.label),
            datasets: [{
                label: 'Events',
                data: hourlyData.map(d => d.count),
                borderColor: '#1a56a8',
                backgroundColor: 'rgba(26,86,168,0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 3,
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: { y: { beginAtZero: true } }
        }
    });

    // Event types pie
    var eventData = <?php echo json_encode(array_slice($top_events, 0, 6)); ?>;
    new Chart(document.getElementById('swps-event-types-chart'), {
        type: 'doughnut',
        data: {
            labels: eventData.map(e => e.event_type),
            datasets: [{
                data: eventData.map(e => parseInt(e.count)),
                backgroundColor: ['#1a56a8','#e74c3c','#f39c12','#27ae60','#9b59b6','#2980b9'],
                borderWidth: 2,
                borderColor: '#fff',
            }]
        },
        options: { responsive: true, plugins: { legend: { position: 'right' } } }
    });

    // Severity donut
    var totalCrit = weeklyData.reduce((a,d) => a + d.critical, 0);
    var totalWarn = weeklyData.reduce((a,d) => a + d.warning, 0);
    var totalInfo = weeklyData.reduce((a,d) => a + d.info, 0);
    new Chart(document.getElementById('swps-severity-chart'), {
        type: 'doughnut',
        data: {
            labels: ['Critical','Warning','Info'],
            datasets: [{
                data: [totalCrit, totalWarn, totalInfo],
                backgroundColor: ['#e74c3c','#f39c12','#2980b9'],
                borderWidth: 2,
                borderColor: '#fff',
            }]
        },
        options: { responsive: true, plugins: { legend: { position: 'right' } } }
    });

    } // end initCharts
    initCharts();
});
</script>
