// Command sbcore runs sing-box for the S3X-UI panel. It serves the protocols
// Xray lacks and is driven by the panel over a token-guarded loopback HTTP API.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JohnMuyuan/s3x-ui/sidecar/sbcore/core"
	"github.com/JohnMuyuan/s3x-ui/sidecar/sbcore/logger"

	C "github.com/sagernet/sing-box/constant"
)

// TokenEnv carries the API token so it never shows up in the process list.
const TokenEnv = "SBCORE_TOKEN"

func main() {
	listen := flag.String("listen", "127.0.0.1:62790", "management API address (loopback only)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("sbcore (sing-box %s)\n", C.Version)
		return
	}
	if err := run(*listen, os.Getenv(TokenEnv)); err != nil {
		logger.Error(err)
		os.Exit(1)
	}
}

func run(listen, token string) error {
	if token == "" {
		return errors.New(TokenEnv + " is empty")
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("refusing non-loopback listen address %q", listen)
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	c := core.NewCore()
	srv := &http.Server{Handler: newAPI(c, token), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("api: ", err)
		}
	}()
	logger.Info("sbcore (sing-box ", C.Version, ") api listening on ", listen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = srv.Close()
	return c.Stop()
}
