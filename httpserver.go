package httpserver

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"time"

	"golang.org/x/sync/errgroup"
)

type Logger interface {
	Println(...interface{})
}

var DefaultLogger Logger = log.New(os.Stderr, "", log.LstdFlags)

func GetLogger(r *http.Request) (Logger, bool) {
	v := r.Context().Value(LoggerContextKey)
	if v == nil {
		return DefaultLogger, false
	}

	logger, ok := v.(Logger)
	if !ok {
		return DefaultLogger, false
	}

	return logger, true
}

type ckLogger int

const LoggerContextKey ckLogger = 1

type Option func(*Server) *Server

func WithPort(port int) Option {
	return func(server *Server) *Server {
		server.server.Addr = ":" + strconv.Itoa(port)
		return server
	}
}

func WithLogger(logger Logger) Option {
	return func(server *Server) *Server {
		server.logger = logger
		return server
	}
}

func WithAccessLog(logFormatter LogFormatter) Option {
	return func(server *Server) *Server {
		server.logFormatter = logFormatter
		return server
	}
}

func WithRecoverer(recoverer Recoverer) Option {
	return func(server *Server) *Server {
		server.recoverer = recoverer
		return server
	}
}

func WithReadTimeout(timeout time.Duration) Option {
	return func(server *Server) *Server {
		server.server.ReadTimeout = timeout
		return server
	}
}

func WithReadHeaderTimeout(timeout time.Duration) Option {
	return func(server *Server) *Server {
		server.server.ReadHeaderTimeout = timeout
		return server
	}
}

func WithWriteTimeout(timeout time.Duration) Option {
	return func(server *Server) *Server {
		server.server.WriteTimeout = timeout
		return server
	}
}

func WithIdleTimeout(timeout time.Duration) Option {
	return func(server *Server) *Server {
		server.server.IdleTimeout = timeout
		return server
	}
}

func WithGracefulShutdown(timeout time.Duration, sig ...os.Signal) Option {
	return func(server *Server) *Server {
		server.shutdown = &shutdown{
			timeout: timeout,
			sig:     sig,
		}
		return server
	}
}

func WithTLS(certFile, keyFile string) Option {
	return func(server *Server) *Server {
		server.tls = &tls{
			certFile: certFile,
			keyFile:  keyFile,
		}
		return server
	}
}

func New(handler http.Handler, options ...Option) *Server {
	server := &Server{
		server: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 30 * time.Second,
		},
	}

	for _, option := range options {
		server = option(server)
	}

	return server
}

type Server struct {
	server       *http.Server
	logger       Logger
	logFormatter LogFormatter
	recoverer    Recoverer
	shutdown     *shutdown
	tls          *tls
}

type LogContext struct {
	Request    *http.Request
	StatusCode int
	Size       uint64
	Duration   time.Duration
}

type LogFormatter func(*LogContext) string

func DefaultLogFormatter(ctx *LogContext) string {
	scheme := "http"
	if ctx.Request.TLS != nil {
		scheme = "https"
	}

	return fmt.Sprintf(
		"\"%s %s://%s%s %s\" from %s - %d %dB in %s",
		ctx.Request.Method,
		scheme,
		ctx.Request.Host,
		ctx.Request.RequestURI,
		ctx.Request.Proto,
		ctx.Request.RemoteAddr,
		ctx.StatusCode,
		ctx.Size,
		ctx.Duration.String(),
	)
}

type Recoverer func(http.ResponseWriter, *http.Request, interface{}, []byte)

func DefaultRecoverer(w http.ResponseWriter, r *http.Request, v interface{}, stak []byte) {
	value := fmt.Sprint(v)

	entry := fmt.Sprintf("panic: %s\n%s", value, debug.Stack())

	logger, _ := GetLogger(r)
	logger.Println(entry)

	http.Error(w, value, http.StatusInternalServerError)
}

type shutdown struct {
	sig     []os.Signal
	timeout time.Duration
}

type tls struct {
	certFile string
	keyFile  string
}

func (server *Server) ListenAndServe() error {
	if server.recoverer != nil {
		handler := server.server.Handler
		server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					server.recoverer(w, r, v, debug.Stack())
				}
			}()

			handler.ServeHTTP(w, r)
		})
	}

	if server.logFormatter != nil {
		handler := server.server.Handler
		server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			ww := &wrappedWriter{ResponseWriter: w}

			defer func() {
				ctx := LogContext{
					Request:    r,
					StatusCode: ww.statusCode,
					Size:       ww.size,
					Duration:   time.Since(start),
				}

				entry := server.logFormatter(&ctx)

				logger, _ := GetLogger(r)
				logger.Println(entry)
			}()

			handler.ServeHTTP(ww, r)
		})
	}

	if logger := server.logger; logger != nil {
		handler := server.server.Handler
		server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), LoggerContextKey, logger)
			handler.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	eg := errgroup.Group{}
	eg.Go(func() error {
		if server.tls != nil {
			if err := server.server.ListenAndServeTLS(server.tls.certFile, server.tls.keyFile); err != nil {
				if err != http.ErrServerClosed {
					return err
				}
			}

			return nil
		}

		if err := server.server.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				return err
			}
		}

		return nil
	})

	if shutdown := server.shutdown; shutdown != nil && len(shutdown.sig) > 0 {
		c := make(chan os.Signal, 1)
		signal.Notify(c, shutdown.sig...)
		<-c

		ctx, cancel := context.WithTimeout(context.Background(), shutdown.timeout)
		defer cancel()

		server.server.SetKeepAlivesEnabled(false)
		if err := server.server.Shutdown(ctx); err != nil {
			server.server.Close()
		}
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}

type wrappedWriter struct {
	http.ResponseWriter
	statusCode int
	size       uint64
}

func (w *wrappedWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.size += uint64(n)
	return n, err
}

func (w *wrappedWriter) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
	w.statusCode = statusCode
}
