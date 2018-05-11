package main

import (
	"flag"
	"log"
	"net"

	"github.com/cockroachdb/cmux"
	"github.com/dhtech/authservice/rpc"
	"github.com/dhtech/authservice/webui"
)

var (
	listenAddress = flag.String("listen", ":1214", "Address to listen to")
)

func main() {
	flag.Parse()

	s, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	mux := cmux.New(s)
	sg := mux.Match(cmux.HTTP2HeaderField("content-type", "application/grpc"))
	sh := mux.Match(cmux.Any())

	w := webui.New()
	r := rpc.New(nil, w)

	go r.Serve(sg)
	go w.Serve(sh)

	err = mux.Serve()
	if err != nil {
		log.Fatalf("failed to serve mux: %v", err)
	}
}
