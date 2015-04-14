package bgp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestMrtHdr(t *testing.T) {
	buf := new(bytes.Buffer)
	var tdate, tlen uint32 = 1, 4
	var ttype, tsubtype uint16 = 2, 3
	mrt := &MrtHdr{tdate, ttype, tsubtype, tlen}
	fmt.Printf("date:%v type:%v subtype:%v len:%v\n", tdate, ttype, tsubtype, tlen)
	binary.Write(buf, binary.BigEndian, mrt)
	fmt.Printf("binary mrt: %x\n", buf.Bytes())
	mhdr, err := NewMrtHdr(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("recreating MrtHdr from binary :%+v \n", mhdr)
}

func TestMrtPFunc(t *testing.T) {
	var (
		tt1, ts1 = uint16(1), uint16(0)  //start
		tt2, ts2 = uint16(3), uint16(1)  //i am dead , but wrong subtype
		tt3, ts3 = uint16(2), uint16(0)  //deprecated
		tt4, ts4 = uint16(11), uint16(0) //ospf state change
		tbuf     = []byte{0, 0, 0, 0, 0, 0, 0, 0}
		tf       parsefunc
		ok       bool
	)
	//binbuf := new(bytes.Buffer)
	mrt1 := &MrtMsg{
		Hdr: MrtHdr{1, tt1, ts1, 10},
		Msg: tbuf,
	}
	mrt2 := &MrtMsg{
		Hdr: MrtHdr{1, tt2, ts2, 10},
		Msg: tbuf,
	}
	mrt3 := &MrtMsg{
		Hdr: MrtHdr{1, tt3, ts3, 10},
		Msg: tbuf,
	}
	mrt4 := &MrtMsg{
		Hdr: MrtHdr{1, tt4, ts4, 10},
		Msg: tbuf,
	}
	fmt.Println("trying to parse informational message")
	if tf, ok = mrt1.PFunc(); !ok {
		t.Fatal("tf should be non nil")
	}
	hdr := tf(mrt1.Msg)
	fmt.Printf("type is :%s\n", hdr.Type())
	fmt.Println("trying to parse informational message with opt string")
	mrt1.Msg = []byte{'f', 'o', 'o', ' ', 's', 't', 'r'}
	mrt1.Hdr.Mrt_type = tt2
	if tf, ok = mrt1.PFunc(); !ok {
		t.Fatal("tf should be non nil")
	}
	hdr = tf(mrt1.Msg)
	fmt.Printf("type is :%s\n", hdr.Type())
	fmt.Println("trying to parse malformed informational message")
	if tf, ok = mrt2.PFunc(); ok {
		t.Fatal("this should fail with tf being nil cause subtype is non-0")
	}
	fmt.Println("trying to parse deprecated message")
	if tf, ok = mrt3.PFunc(); ok {
		t.Fatal("this should fail with tf being nil cause it's deprecated")
	}
	fmt.Println("trying to parse OSPF message")
	//first call to littleendian to come to hostbyteorder and then switch to big
	binary.BigEndian.PutUint32(mrt4.Msg[:4], binary.LittleEndian.Uint32(net.IPv4(1, 2, 3, 4).To4()))
	binary.BigEndian.PutUint32(mrt4.Msg[4:], binary.LittleEndian.Uint32(net.IPv4(5, 6, 7, 8).To4()))
	//binary.Write(binbuf, binary.BigEndian, net.IPv4allsys.To4())
	//mrt4.Msg = make([]byte,8)
	//mrt4.Msg = binbuf.Bytes()
	//copy(mrt4.BGPMsg,binbuf.Bytes())
	if tf, ok = mrt4.PFunc(); !ok {
		t.Fatal("this shouldn't fail")
	}
	hdr = tf(mrt4.Msg)
	fmt.Printf("type is :%s .String representation: %s\n", hdr.Type(), hdr)
}

func TestScan(t *testing.T) {
	fmt.Println("testing the scanner interface")
	f, err := os.Open("../test/testfiles/mrt3")
	if err != nil {
		t.Fatal(err)
	}
	mrtscanner := bufio.NewScanner(f)
	mrtscanner.Split(SplitMrt)
	count := 0
	for mrtscanner.Scan() {
		count++
		dat := mrtscanner.Bytes()
		h, _ := NewMrtHdr(dat[:MrtHdr_size]) /* the error has been checked in Read() */
		if h.Mrt_len == 0 {
			t.Logf("terminating from 0 mrt len")
			return
		}
		mrtmsg := MrtMsg{Hdr: h, Msg: dat[MrtHdr_size:]}
		if tf, ok := mrtmsg.PFunc(); ok {
			tf(mrtmsg.Msg)
		}
	}
	if err := mrtscanner.Err(); err != nil {
		fmt.Printf("error: %s", err)
	}
	fmt.Printf("scanned and parsed: %d entries from bufio\n", count)
}

func TestMrtTableDumpV2PITableMarshalBinary(t *testing.T) {
	ptime := time.Unix(1300475700, 0)

	peers := []MrtTableDumpV2PeerEntry{
		MrtTableDumpV2PeerEntry{
			PeerType:  2,
			PeerBGPID: binary.LittleEndian.Uint32(net.IPv4(198, 51, 100, 5)),
			PeerIP:    []byte(net.IPv4(198, 51, 100, 5)),
			PeerAS:    65541,
		},
		MrtTableDumpV2PeerEntry{
			PeerType:  2,
			PeerBGPID: binary.LittleEndian.Uint32(net.IPv4(192, 0, 2, 33)),
			PeerIP:    []byte(net.IPv4(192, 0, 2, 33)),
			PeerAS:    65542,
		},
	}
	msg := &MrtTableDumpV2PITable{
		MrtMsgDef:   MrtMsgDef{time: ptime, t: 13, st: 4, sz: 0},
		CollectorID: binary.LittleEndian.Uint32(net.IPv4(198, 51, 100, 4)),
		ViewNameLen: 0,
		ViewName:    nil,
		PeerCount:   2,
		Peers:       peers,
	}
	fmt.Printf("i say:%v\n", msg.t)

	if msg == nil {
		t.Fatal("Could not create PI Table")
	}

	ser, err := msg.MarshalBinary()
	if err != nil {
		t.Fatal("Could not serialize data")
	}
	fmt.Printf("serialized msg is:%+v\n", ser)
	ummsg := &MrtTableDumpV2PITable{}
	ummsg.UnmarshalBinary(ser)
	if len(ummsg.Peers) != len(msg.Peers) || ummsg.sz != msg.sz {
		fmt.Printf("peer len um:%d , peer len m:%d , sz um:%d , sz m:%d", len(ummsg.Peers), len(msg.Peers), ummsg.sz, msg.sz)
		t.Fatal("marshaled and unmarshaled copies do not match")
	}
}

func TestMrtTableDumpV2RIBGenMarshalBinary(t *testing.T) {
	rarg := RibTable{Seq: 12, AFI: 13, SAFI: 14, Nlri: []byte{'\x01', '\x02', '\x03'}}
	pathmap := []Path{}
	m := NewMrtTableDumpV2RIBGen(rarg, pathmap)

	if m == nil {
		t.Fatal("Could not create RIB_GENERIC")
	}
	_, err := m.MarshalBinary()

	if err != nil {
		t.Fatal("Could not serialize data", err)
	}
}
