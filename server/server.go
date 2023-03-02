package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/shlin168/go-nvd/utils"
)

var ErrStop = errors.New("stop server")

type Server struct {
	srv         *http.Server
	mSrv        *http.Server
	controllers []Controller
	acsLogger   *zap.Logger
	errLogger   *zap.Logger
	reg         *prometheus.Registry
	killed      chan struct{}
}

type Options func(*Server) error

func ErrorLogger(logger *zap.Logger) Options {
	return func(s *Server) error {
		s.errLogger = logger
		return nil
	}
}

func AccessLogger(logger *zap.Logger) Options {
	return func(s *Server) error {
		s.acsLogger = logger
		return nil
	}
}

func Controllers(cs ...Controller) Options {
	return func(s *Server) error {
		s.controllers = cs
		return nil
	}
}

func Registry(reg *prometheus.Registry) Options {
	return func(s *Server) error {
		s.reg = reg
		return nil
	}
}

func New(lisAddr, metricsAddr string, opts ...Options) (*Server, error) {
	s := &Server{
		killed: make(chan struct{}),
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	if len(s.controllers) == 0 {
		return nil, errors.New("no controllers provided")
	}
	if s.acsLogger == nil {
		s.acsLogger = utils.DefaultLogger
	}
	if s.errLogger == nil {
		s.errLogger = utils.DefaultLogger
	}

	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(ginzap.GinzapWithConfig(s.acsLogger, &ginzap.Config{
		UTC:        true,
		TimeFormat: time.RFC3339,
		SkipPaths:  []string{APIGroupNVD + APIPathReady},
	}))
	r.Use(ginzap.RecoveryWithZap(s.errLogger, true))

	grpNVD := r.Group(APIGroupNVD)
	for _, controller := range s.controllers {
		controller.Register(grpNVD)
	}

	mr := gin.New()
	mr.GET("/metrics", gin.WrapH(promhttp.Handler()))

	s.srv = &http.Server{
		Addr:    lisAddr,
		Handler: r,
	}
	s.mSrv = &http.Server{
		Addr:    metricsAddr,
		Handler: mr,
	}
	return s, nil
}

// Start starts the server and wait for stop signal
func (s *Server) Start(ctx context.Context) {
	grp, gCtx := errgroup.WithContext(ctx)
	stopSig := make(chan os.Signal, 1)
	signal.Notify(stopSig, syscall.SIGINT, syscall.SIGTERM)

	defer close(s.killed)

	// Since the argument of MetricRegister is an interface (prometheus.Registry implements prometheus.Registerer interface)
	// check and pass with 'nil' if not given to avoid checking nil interface in metric Register/UnRegister functions.
	if s.reg == nil {
		MetricRegister(nil)
	} else {
		MetricRegister(s.reg)
	}
	defer func() {
		if s.reg == nil {
			MetricUnRegister(nil)
		} else {
			MetricUnRegister(s.reg)
		}
	}()

	grp.Go(func() error {
		return s.mSrv.ListenAndServe()
	})
	grp.Go(func() error {
		return s.srv.ListenAndServe()
	})

	// wait for stop signal
	grp.Go(func() error {
		select {
		case <-gCtx.Done():
			return nil
		case <-stopSig:
			return ErrStop
		}
	})

	// stop everything
	var shutdownErr error
	grp.Go(func() error {
		<-gCtx.Done() // when first goroutine returns with error, context will be canceled
		if err := s.srv.Shutdown(ctx); err != nil {
			shutdownErr = errors.Join(shutdownErr, err)
		}
		if err := s.mSrv.Shutdown(ctx); err != nil {
			shutdownErr = errors.Join(shutdownErr, err)
		}
		return shutdownErr
	})

	if err := grp.Wait(); err != nil && !errors.Is(err, ErrStop) && !errors.Is(err, http.ErrServerClosed) {
		panic(fmt.Errorf("failed to serve: %w", err))
	}
	s.errLogger.Info("Server is shutdown")
}

// FullyStopped wait for server to be fully killed, which is use in testing to avoid data race in metrics
func (s *Server) FullyStopped() {
	<-s.killed
}
