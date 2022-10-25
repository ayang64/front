package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/ayang64/front/proxy"
)

func main() {
	httpport := flag.Int("httpport", 80, "http port")
	httpsport := flag.Int("httpsport", 443, "https port")
	config := flag.String("config", "./proxy.json", "configuration file")
	dircache := flag.String("dircache", "./dircache", "location of certificate cache")
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
