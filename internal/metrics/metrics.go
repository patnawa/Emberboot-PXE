// Package metrics defines Emberboot's Prometheus instrumentation. One Registry
// per process, injected into each service.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// M holds every Emberboot metric. Field names mirror the exported metric names.
type M struct {
	reg *prometheus.Registry

	DHCPRequests            *prometheus.CounterVec // stage: discover|pxe_request|ipxe_script
	DHCPIgnored             prometheus.Counter
	RogueDetected           prometheus.Counter
	TFTPTransfers           *prometheus.CounterVec // file is an allow-listed boot file or "other"
	HTTPPayloadBytes        prometheus.Counter
	HTTPRequests            *prometheus.CounterVec // kind: script|iso|file|answer, code
	BootAdmissionRejected   *prometheus.CounterVec // resource: connection|stream
	ImagesReady             prometheus.Gauge
	ImagesInvalid           prometheus.Gauge
	ConfigReloads           *prometheus.CounterVec // result: ok|rejected
	SessionsActive          prometheus.Gauge
	Sessions                *prometheus.CounterVec // result: handoff|failed|stalled
	SessionTelemetryDropped *prometheus.CounterVec // operation: touch|meta|finish
	AlertsFired             *prometheus.CounterVec // kind
	ManagementAuth          *prometheus.CounterVec // result: failed|blocked
}

// New creates the registry and all metrics.
func New() *M {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	m := &M{
		reg: reg,
		DHCPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "emberboot_dhcp_requests_total",
			Help: "PXE-relevant DHCP requests seen, by stage.",
		}, []string{"stage"}),
		DHCPIgnored: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "emberboot_dhcp_ignored_total",
			Help: "DHCP packets seen and ignored (non-PXE or denied).",
		}),
		RogueDetected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "emberboot_rogue_pxe_responses_total",
			Help: "PXE responses on the wire from servers that are not us.",
		}),
		TFTPTransfers: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "emberboot_tftp_transfers_total",
			Help: "TFTP transfers (iPXE bootloader only), by file and result.",
		}, []string{"file", "result"}),
		HTTPPayloadBytes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "emberboot_http_payload_bytes_total",
			Help: "Bytes served to booting clients over HTTP.",
		}),
		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "emberboot_http_requests_total",
			Help: "Boot HTTP requests, by kind and status code.",
		}, []string{"kind", "code"}),
		BootAdmissionRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "emberboot_boot_admission_rejected_total",
			Help: "Boot HTTP work rejected at a configured capacity limit, by resource.",
		}, []string{"resource"}),
		ImagesReady: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "emberboot_images_ready",
			Help: "Images currently Ready (validated and offered).",
		}),
		ImagesInvalid: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "emberboot_images_invalid",
			Help: "Images present but failed validation.",
		}),
		ConfigReloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "emberboot_config_reloads_total",
			Help: "Config reload attempts, by result.",
		}, []string{"result"}),
		SessionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "emberboot_boot_sessions_active",
			Help: "Boot Sessions currently in progress.",
		}),
		Sessions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "emberboot_boot_sessions_total",
			Help: "Finished Boot Sessions, by result.",
		}, []string{"result"}),
		SessionTelemetryDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "emberboot_session_telemetry_dropped_total",
			Help: "Boot-session telemetry operations dropped to keep boot traffic non-blocking, by operation.",
		}, []string{"operation"}),
		AlertsFired: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "emberboot_alerts_fired_total",
			Help: "Alerts fired, by kind.",
		}, []string{"kind"}),
		ManagementAuth: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "emberboot_management_auth_total",
			Help: "Management authentication failures and rate-limit blocks, by result.",
		}, []string{"result"}),
	}
	reg.MustRegister(
		m.DHCPRequests, m.DHCPIgnored, m.RogueDetected, m.TFTPTransfers,
		m.HTTPPayloadBytes, m.HTTPRequests, m.BootAdmissionRejected, m.ImagesReady, m.ImagesInvalid,
		m.ConfigReloads, m.SessionsActive, m.Sessions, m.SessionTelemetryDropped,
		m.AlertsFired, m.ManagementAuth,
	)
	return m
}

// Handler serves the /metrics endpoint.
func (m *M) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
