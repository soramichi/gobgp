package server

import (
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/packet"
	"net"
	"os"
)

type MRTServer struct {
	ch   chan Event
	file *os.File
}

func NewMRTServer(filename string, c chan Event) *MRTServer {
	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0664)
	if err != nil {
		log.Error("Can't open ", filename)
		return nil
	}
	return &MRTServer{
		ch:   c,
		file: f,
	}
}

func (s *MRTServer) Serve() error {
	for {
		select {
		case e := <-s.ch:
			switch e.EventType {
			case EVENT_PEERS:
				peerList := e.EventData.([]*bgp.PeerInfo)
				m := bgp.NewTableDumpV2PITable(net.ParseIP("127.0.0.1"), "", peerList)
				log.Info(m)
			}
		}
	}
}
