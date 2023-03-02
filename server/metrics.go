package server

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	httpRequestsTotal    *prometheus.CounterVec
	httpRequestsDuration *prometheus.HistogramVec

	getRequestsTotal *prometheus.CounterVec

	// unit: seconds
	defaultDurationBucket = []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}
)

// MetricRegister register metrics when server starts
func MetricRegister(registerer prometheus.Registerer) {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}
	MetricRegisterOn(registerer)
}

// MetricRegisterOn register needed promutheus metrics on given registerer
func MetricRegisterOn(registerer prometheus.Registerer) {
	/* http request */
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_request_total",
			Help: "The amount of requests per HTTP status code",
		},
		[]string{"code", "api"})
	httpRequestsDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "A histogram of latencies for requests",
			Buckets: defaultDurationBucket},
		[]string{})

	/* service */
	getRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "get_request_total",
			Help: "The amount of requests to get scan report and status",
		},
		[]string{"api", "status"})

	registerer.Register(httpRequestsTotal)
	registerer.Register(httpRequestsDuration)
	registerer.Register(getRequestsTotal)
}

// MetricUnRegister unregister metrics when server shutdown
func MetricUnRegister(registerer prometheus.Registerer) {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}
	MetricUnRegisterFrom(registerer)
}

// MetricUnRegisterFrom unregister metrics from registerer
func MetricUnRegisterFrom(registerer prometheus.Registerer) {
	registerer.Unregister(httpRequestsTotal)
	registerer.Unregister(httpRequestsDuration)
	registerer.Unregister(getRequestsTotal)
}

func MetricMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now().UTC()
		c.Next()

		status := strconv.Itoa(c.Writer.Status())
		elapsed := float64(time.Since(start)) / float64(time.Second)

		httpRequestsDuration.WithLabelValues().Observe(elapsed)
		httpRequestsTotal.WithLabelValues(status, c.FullPath()).Inc()
	}
}
