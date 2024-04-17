package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/ayang64/front/proxy"
)

func intOr(vs ...string) int {
	for _, v := range vs {
		if v == "" {
			continue
		}
		i, err := strconv.Atoi(v)
		if err != nil {
			continue
		}
		return i
	}
	return 0
}

func or[T comparable](vs ...T) T {
	var zero T
	for _, v := range vs {
		if v != zero {
			return v
		}
	}
	return zero
}

func main() {
	httpport := flag.Int("httpport", 80, "http port")
	httpsport := flag.Int("httpsport", 443, "https port")
	config := flag.String("config", "/usr/local/front/proxy.json", "configuration file")
	dircache := flag.String("dircache", "/usr/local/front/dircache", "location of certificate cache")
	flag.Parse()

	server, err := proxy.New(
		proxy.WithHTTPPort(*httpport),
		proxy.WithHTTPSPort(*httpsport),
		proxy.WithConfigPath(*config),
		proxy.WithDircachePath(*dircache))
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT)
	defer stop()

	if err := server.Serve(ctx); err != nil {
		log.Fatal(err)
	}
}
