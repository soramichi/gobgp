package main

import (
	"bytes"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/jessevdk/go-flags"
	"github.com/osrg/gobgp/config"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
)

type QuaggaConfig struct {
	id          int
	config      *config.Neighbor
	gobgpConfig *config.Global
	serverIP    net.IP
}

func NewQuaggaConfig(id int, gConfig *config.Global, myConfig *config.Neighbor, server net.IP) *QuaggaConfig {
	return &QuaggaConfig{
		id:          id,
		config:      myConfig,
		gobgpConfig: gConfig,
		serverIP:    server,
	}
}

func (qt *QuaggaConfig) Config() *bytes.Buffer {
	buf := bytes.NewBuffer(nil)

	buf.WriteString("hostname bgpd\n")
	buf.WriteString("password zebra\n")
	buf.WriteString(fmt.Sprintf("router bgp %d\n", qt.config.PeerAs))
	buf.WriteString(fmt.Sprintf("bgp router-id 192.168.0.%d\n", qt.id))
	buf.WriteString(fmt.Sprintf("network 192.168.%d.0/24\n", qt.id))
	buf.WriteString(fmt.Sprintf("neighbor %s remote-as %d\n", qt.serverIP, qt.gobgpConfig.As))
	buf.WriteString(fmt.Sprintf("neighbor %s password %s\n", qt.serverIP, qt.config.AuthPassword))
	buf.WriteString("log file /var/log/quagga/bgpd.log")
	return buf
}

func create_config_files(nr int, outputDir string) {
	quaggaConfigList := make([]*QuaggaConfig, 0)

	gobgpConf := config.Bgp{
		Global: config.Global{
			As:       65000,
			RouterId: net.ParseIP("192.168.255.1"),
		},
	}

	for i := 1; i < nr+1; i++ {
		c := config.Neighbor{
			PeerAs:          65000 + uint32(i),
			NeighborAddress: net.ParseIP(fmt.Sprintf("10.0.0.%d", i)),
			AuthPassword:    fmt.Sprintf("hoge%d", i),
		}
		gobgpConf.NeighborList = append(gobgpConf.NeighborList, c)
		q := NewQuaggaConfig(i, &gobgpConf.Global, &c, net.ParseIP("10.0.255.1"))
		quaggaConfigList = append(quaggaConfigList, q)
		os.Mkdir(fmt.Sprintf("%s/q%d", outputDir, i), 0755)
		err := ioutil.WriteFile(fmt.Sprintf("%s/q%d/bgpd.conf", outputDir, i), q.Config().Bytes(), 0644)
		if err != nil {
			log.Fatal(err)
		}
	}

	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	encoder.Encode(gobgpConf)

	err := ioutil.WriteFile(fmt.Sprintf("%s/gobgpd.conf", outputDir), buffer.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	var opts struct {
		ClientNumber int    `short:"n" long:"client-number" description:"specfying the number of clients" default:"8"`
		OutputDir    string `short:"c" long:"output" description:"specifing the output directory"`
	}
	parser := flags.NewParser(&opts, flags.Default)

	_, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}

	if opts.OutputDir == "" {
		opts.OutputDir, _ = filepath.Abs(".")
	} else {
		if _, err := os.Stat(opts.OutputDir); os.IsNotExist(err) {
			os.Mkdir(opts.OutputDir, 0755)
		}
	}

	create_config_files(opts.ClientNumber, opts.OutputDir)
}
