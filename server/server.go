package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/gdbelvin/key-transparency/proxy"
	"github.com/gdbelvin/key-transparency/rest"

	pb "github.com/gdbelvin/key-transparency/proto"
)

var port = flag.Int("port", 50051, "TCP port to listen on")

func main() {
	flag.Parse()

	portString := fmt.Sprintf(":%d", *port)
	// TODO: fetch private TLS key from repository
	lis, err := net.Listen("tcp", portString)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	v1 := proxy.New()
	s := rest.New(v1)

	// TODO: Auto config or manual config.
	pb.RegisterE2EKeyProxyServer(s, v1)
	//s.AddResource("/v1/user/{userid}", "GET", v1.GetUser)

	s.Serve(lis)
}
