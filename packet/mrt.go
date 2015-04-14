package bgp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
	"unicode/utf8"
	//"runtime"
)

var logger = log.New(os.Stderr, "go-mrt: ", log.Ldate|log.Llongfile)

type MrtHdr struct {
	Mrt_timestamp uint32
	Mrt_type      uint16
	Mrt_subtype   uint16
	Mrt_len       uint32
}

type parsefunc func([]byte) MrtSubTyper

type MrtMsg struct {
	Hdr MrtHdr
	Msg []byte
}

type MrtSubTyper interface {
	Type() string //almost dummy functionality
	String() string
	Data() []byte
}

type Mrter interface {
	Hdr() MrtHdr
	Type() uint16
	SubType() uint16
	Len() uint32
	Msg() []byte
}

type MrtOSPFHdr struct {
	otype    uint16
	RemoteIP uint32
	LocalIP  uint32
}

func (m *MrtOSPFHdr) Type() string {
	return "OSPFHdr"
}

func (m *MrtOSPFHdr) String() string {
	remip := make(net.IP, 4)
	locip := make(net.IP, 4)
	remip[0] = byte(m.RemoteIP)
	remip[1] = byte(m.RemoteIP >> 8)
	remip[2] = byte(m.RemoteIP >> 16)
	remip[3] = byte(m.RemoteIP >> 24)
	locip[0] = byte(m.LocalIP)
	locip[1] = byte(m.LocalIP >> 8)
	locip[2] = byte(m.LocalIP >> 16)
	locip[3] = byte(m.LocalIP >> 24)
	return fmt.Sprintf("OSPF Header. Type [%d] Remote IP [%s] Local IP [%s]", m.otype, remip, locip)
}

func (m *MrtOSPFHdr) Data() []byte {
	return []byte("not impl")
}

type MrtInfoMsg struct {
	inftype uint16
	optmsg  string
}

func (m *MrtInfoMsg) String() string {
	return fmt.Sprintf("Informational Message. Type [%v] Optstring [%s]", m.inftype, m.optmsg)
}

func (m *MrtInfoMsg) Type() string {
	return m.String()
}

func (m *MrtInfoMsg) Data() []byte {
	return []byte("not impl")
}

func (m *MrtMsg) PFunc() (ret parsefunc, ok bool) {
	var subtype = m.Hdr.Mrt_subtype
	var mtype = m.Hdr.Mrt_type
	infofunc := func(a []byte) MrtSubTyper {
		runes := []rune{}
		infomsg := &MrtInfoMsg{inftype: mtype, optmsg: "No Optional Message"}
		for len(a) > 0 {
			r, sz := utf8.DecodeRune(a)
			if r == utf8.RuneError {
				logger.Println("failed to decode rune in optional message")
				return infomsg
			}
			a = a[sz:]
			runes = append(runes, r)
		}
		if len(runes) > 0 {
			infomsg.optmsg = string(runes)
		}
		return infomsg
	}

	ospffunc := func(a []byte) MrtSubTyper {
		ret := &MrtOSPFHdr{otype: subtype}
		buf := bytes.NewReader(a)
		err := binary.Read(buf, binary.BigEndian, &ret.RemoteIP)
		err = binary.Read(buf, binary.BigEndian, &ret.LocalIP)
		if err != nil {
			panic(fmt.Sprintf("error while reading binary OSPF header: %s", err))
		}
		return ret
	}

	bgp4mpscfunc := func(a []byte) MrtSubTyper {
		ret := &MrtBGP4MPStateChangeHdr{}
		buf := bytes.NewReader(a)
		if subtype == BGP4MP_STATE_CHANGE {
			ret.PeerASN = make([]byte, 2)
			ret.LocalASN = make([]byte, 2)
		} else {
			ret.PeerASN = make([]byte, 4)
			ret.LocalASN = make([]byte, 4)
		}
		err := binary.Read(buf, binary.BigEndian, &ret.PeerASN)
		if err != nil {
			panic(fmt.Sprintf("error while reading binary BGP4MP header: %s", err))
		}
		binary.Read(buf, binary.BigEndian, &ret.LocalASN)
		binary.Read(buf, binary.BigEndian, &ret.InterfaceInd)
		binary.Read(buf, binary.BigEndian, &ret.AddrFamily)
		if ret.AddrFamily == 1 {
			ret.PeerIP = make([]byte, 4)
			ret.LocalIP = make([]byte, 4)
		} else if ret.AddrFamily == 2 {
			ret.PeerIP = make([]byte, 16)
			ret.LocalIP = make([]byte, 16)
		}
		binary.Read(buf, binary.BigEndian, &ret.PeerIP)
		binary.Read(buf, binary.BigEndian, &ret.LocalIP)
		binary.Read(buf, binary.BigEndian, &ret.OldState)
		binary.Read(buf, binary.BigEndian, &ret.NewState)
		return ret
	}

	bgp4mpmsgfunc := func(a []byte) MrtSubTyper {
		ret := &MrtBGP4MPMsgHdr{}
		buf := bytes.NewReader(a)
		totread := 0
		if subtype == BGP4MP_MESSAGE {
			ret.PeerASN = make([]byte, 2)
			ret.LocalASN = make([]byte, 2)
			totread += 4
		} else if subtype == BGP4MP_MESSAGE_AS4 {
			ret.PeerASN = make([]byte, 4)
			ret.LocalASN = make([]byte, 4)
			totread += 8
		}
		err := binary.Read(buf, binary.BigEndian, &ret.PeerASN)
		if err != nil {
			panic(fmt.Sprintf("error while reading binary BGP4MP header: %s", err))
		}
		binary.Read(buf, binary.BigEndian, &ret.LocalASN)
		binary.Read(buf, binary.BigEndian, &ret.InterfaceInd)
		//fmt.Printf("ADdr family should be:%v\n", binary.BigEndian.Uint16(a[6:8]))
		binary.Read(buf, binary.BigEndian, &ret.AddrFamily)
		totread += 2
		if ret.AddrFamily == 1 {
			ret.PeerIP = make([]byte, 4)
			ret.LocalIP = make([]byte, 4)
			totread += 8
		} else if ret.AddrFamily == 2 {
			ret.PeerIP = make([]byte, 16)
			ret.LocalIP = make([]byte, 16)
			totread += 32
		} else {
			panic("Address Family in BGP4MP msg func is wrong")
		}
		binary.Read(buf, binary.BigEndian, &ret.PeerIP)
		binary.Read(buf, binary.BigEndian, &ret.LocalIP)
		datsz := len(a) - totread
		if datsz < 0 {
			panic("no data left in BGP message")
		}
		ret.data = make([]byte, datsz)
		buf.Read(ret.data)
		return ret
	}

	ret = nil
	ok = false
	switch mtype {
	case MSG_PROTOCOL_BGP4MP:
		if subtype == BGP4MP_STATE_CHANGE || subtype == BGP4MP_STATE_CHANGE_AS4 {
			ret, ok = bgp4mpscfunc, true
		} else if subtype == BGP4MP_MESSAGE || subtype == BGP4MP_MESSAGE_AS4 ||
			subtype == BGP4MP_MESSAGE_LOCAL || subtype == BGP4MP_MESSAGE_AS4_LOCAL {
			ret, ok = bgp4mpmsgfunc, true
		}
	case MSG_START, MSG_I_AM_DEAD:
		if subtype == 0 {
			ret, ok = infofunc, true
		} else {
			logger.Println("Mrt type is Informational but Subtype non-zero")
		}
	case MSG_PROTOCOL_OSPF:
		if subtype == 0 || subtype == 1 {
			ret, ok = ospffunc, true
		} else {
			logger.Println("Mrt type is OSPF but Subtype is neither 0 or 1")
		}
	case MSG_NULL, MSG_DIE, MSG_PEER_DOWN, MSG_PROTOCOL_BGP, MSG_PROTOCOL_IDRP, MSG_PROTOCOL_BGP4PLUS, MSG_PROTOCOL_BGP4PLUS1:
		logger.Println("Deprecated message type")
	default:
		logger.Printf("unknown. header [%v]\n", m.Hdr)
	}
	return
}

type MrtBGP4MPStateChangeHdr struct {
	PeerASN      []byte
	LocalASN     []byte
	InterfaceInd uint16
	AddrFamily   uint16
	PeerIP       []byte
	LocalIP      []byte
	OldState     uint16
	NewState     uint16
}

func (m *MrtBGP4MPStateChangeHdr) Type() string {
	return "BGP4MPStateChange"
}

func (m *MrtBGP4MPStateChangeHdr) String() string {
	return "BGP4MPStateChange"
}

func (m *MrtBGP4MPStateChangeHdr) Data() []byte {
	return []byte("not impl")
}

type MrtBGP4MPMsgHdr struct {
	PeerASN      []byte
	LocalASN     []byte
	InterfaceInd uint16
	AddrFamily   uint16
	PeerIP       []byte
	LocalIP      []byte
	data         []byte
}

func (m *MrtBGP4MPMsgHdr) Type() string {
	return "BGP4MPMsg"
}

func (m *MrtBGP4MPMsgHdr) String() string {
	if len(m.PeerIP) < 4 || len(m.LocalIP) < 4 {
		return "BGP4MPMsg unable to read IPs"
	}
	return fmt.Sprintf("LocalIP:%s RemoteIP:%s", net.IPv4(m.PeerIP[0], m.PeerIP[1], m.PeerIP[2], m.PeerIP[3]), net.IPv4(m.LocalIP[0], m.LocalIP[1], m.LocalIP[2], m.LocalIP[3]))
}

func (m *MrtBGP4MPMsgHdr) Data() []byte {
	return m.data
}

type MrtTableDumpV1Hdr struct {
	ViewNum   uint16
	SeqNum    uint16
	Prefix    []byte
	PrefixLen uint8
	Status    uint8
	OrigTime  uint32
	PeerIP    []byte
	PeerAS    uint16
	AttrLen   uint16
}

func (m *MrtTableDumpV1Hdr) Type() string {
	return "TableDumpV1Hdr"
}

func (m *MrtTableDumpV1Hdr) String() string {
	return "TableDumpV1Hdr"
}

type MrtTableDumpV2PITable struct {
	MrtMsgDef
	CollectorID uint32
	ViewNameLen uint16
	ViewName    []rune //rune is actually uint32
	PeerCount   uint16
	Peers       []MrtTableDumpV2PeerEntry
}

type MrtTableDumpV2MsgIf interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary([]byte) error
}

type MrtMsgIf interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary([]byte) error
	Type() int
	SubType() int
}

type MrtMsgDef struct {
	time time.Time //date
	t    uint16    //type:These will be set by BrandMRT
	st   uint16    //subtype
	sz   uint32    //size set by Serialze
}

func (msg *MrtMsgDef) MarshalBinary() ([]byte, error) {
	b := new(bytes.Buffer)
	u32time := uint32(msg.time.Unix()) //XXX: this is bad, we lose info and are vuln to 2038bug.
	binary.Write(b, binary.BigEndian, u32time)
	binary.Write(b, binary.BigEndian, msg.t)
	binary.Write(b, binary.BigEndian, msg.st)
	binary.Write(b, binary.BigEndian, msg.sz)
	//this must be set before someone serializes the header.
	return b.Bytes(), nil
}

func (msg *MrtMsgDef) Type() int {
	return int(msg.t)
}

func (msg *MrtMsgDef) SubType() int {
	return int(msg.st)
}

func (msg *MrtTableDumpV2PITable) MarshalBinary() ([]byte, error) {
	b := new(bytes.Buffer)
	var err error
	w := func(a interface{}) {
		if err != nil {
			return
		}
		err = binary.Write(b, binary.BigEndian, a)
	}
	w(msg.CollectorID)
	w(msg.ViewNameLen)
	w(msg.ViewName)
	w(msg.PeerCount)
	for _, p := range msg.Peers {
		w(p.PeerType)
		w(p.PeerBGPID)
		w(p.PeerIP)
		if (p.PeerType & 2) != 0 {
			w(p.PeerAS)
		} else {
			w(uint16(p.PeerAS))
		}
	}
	if err != nil {
		return nil, err
	}
	msg.sz = uint32(b.Len()) //XXX sanity check
	hdr := msg.MrtMsgDef
	hdrb, _ := hdr.MarshalBinary()
	log.Printf("MarshalBinary: msg with serialized vals: %+v  hdr:%+v , hdrb:%+v\n", msg, hdr, hdrb)
	return append(hdrb, b.Bytes()...), nil
}

func (msg *MrtTableDumpV2PITable) UnmarshalBinary(from []byte) error {
	b := bytes.NewBuffer(from)
	var err error
	var mrttime uint32
	var genu16 uint16
	r := func(e error) {
		if e != nil {
			err = e
			log.Println(err)
		}
	}
	r(binary.Read(b, binary.BigEndian, &mrttime))
	msg.time = time.Unix(int64(mrttime), 0)
	r(binary.Read(b, binary.BigEndian, &genu16))
	msg.t = genu16
	r(binary.Read(b, binary.BigEndian, &msg.st))
	r(binary.Read(b, binary.BigEndian, &msg.sz))
	//r(msg.CollectorID)
	r(binary.Read(b, binary.BigEndian, &msg.CollectorID))
	r(binary.Read(b, binary.BigEndian, &msg.ViewNameLen))
	if err != nil {
		log.Fatal(err)
	}
	msg.ViewName = make([]rune, msg.ViewNameLen)
	r(binary.Read(b, binary.BigEndian, &msg.ViewName))
	r(binary.Read(b, binary.BigEndian, &msg.PeerCount))
	if err != nil {
		log.Fatal(err)
	}
	msg.Peers = make([]MrtTableDumpV2PeerEntry, msg.PeerCount)
	for _, p := range msg.Peers {
		var ipb []byte
		var as2 uint16
		r(binary.Read(b, binary.BigEndian, &p.PeerType))
		if err != nil {
			log.Fatal(err)
		}
		if (p.PeerType & 1) != 0 {
			ipb = make([]byte, 16)
		} else {
			//XXX:fix , cause this loses the val
			ipb = make([]byte, 4)
		}
		if err != nil {
			log.Fatal(err)
		}
		r(binary.Read(b, binary.BigEndian, &p.PeerBGPID))
		r(binary.Read(b, binary.BigEndian, &ipb))
		p.PeerIP = net.IP(ipb)
		if (p.PeerType & 2) != 0 {
			r(binary.Read(b, binary.BigEndian, &p.PeerAS))
		} else {
			//XXX:fix , cause this loses the val
			r(binary.Read(b, binary.BigEndian, &as2))
			p.PeerAS = uint32(as2)
		}
	}
	log.Printf("decode finished! hdr:%+v\n", msg.MrtMsgDef)
	return nil
}

func addr2uint32(a net.IP) (u uint32) {
	if a == nil {
		log.Printf("nil ip in addr2uint32. maybe ipv6?")
		return
	}

	u |= uint32(a[0])       // 127
	u |= uint32(a[1]) << 8  // 0
	u |= uint32(a[2]) << 16 // 0
	u |= uint32(a[3]) << 24 // 1
	return
}

//the struct to pass the peer info into dumptable
type PeerInfo struct {
	AS      uint32
	ID      net.IP
	LocalID net.IP
	Address net.IP
}

func NewTableDumpV2PITable(id net.IP, viewname string, peers []*PeerInfo) MrtMsgIf {
	ret := &MrtTableDumpV2PITable{
		CollectorID: addr2uint32(id.To4()),
		ViewNameLen: uint16(len(viewname)),
		ViewName:    []rune(viewname),
		PeerCount:   uint16(len(peers)),
		Peers:       make([]MrtTableDumpV2PeerEntry, len(peers)),
	}

	for i, p := range peers {
		pt := uint8(0)
		pid := uint32(0)
		//if address is v6 set bit 0
		if p.Address.To4() == nil {
			pt |= 1
		}

		//if as is 4byte set bit 1
		if p.AS > 65535 {
			pt |= 1 << 1
		}

		ret.Peers[i].PeerType = pt
		if p.ID.To4() == nil {
			log.Printf("nil peer id in NewTableDumpV2PITable")
		} else {
			pid = addr2uint32(p.ID)
		}

		ret.Peers[i].PeerBGPID = pid
		ret.Peers[i].PeerIP = p.Address
		ret.Peers[i].PeerAS = p.AS
	}

	ret.t = MSG_TABLE_DUMP_V2
	ret.st = PEER_INDEX_TABLE
	ret.time = time.Now()
	return ret
}

type MrtTableDumpV2PeerEntry struct {
	PeerType  uint8
	PeerBGPID uint32
	PeerIP    net.IP
	PeerAS    uint32
}

type MrtTableDumpV2RIBDef struct {
	MrtMsgDef
	SequenceNum uint32
	PrefixLen   uint8
	Prefix      uint32
	EntryCount  uint16
	Entries     []MrtTableDumpV2RIBEntry
}

type NLRI struct {
	length byte
	prefix []byte
}

type MrtTableDumpV2RIBGen struct {
	MrtMsgDef
	SequenceNum uint32
	AFI         uint16
	SAFI        uint8
	NLRIEntries []NLRI
	EntryCount  uint16
	Entries     []MrtTableDumpV2RIBEntry
}

type MrtTableDumpV2RIBEntry struct {
	PeerIndex uint16
	OrigTime  time.Time
	AttrLen   uint16
	BGPAttrs  []byte
}

//we will need to implement a local Path type to shove in there the Path info from
// the Path struct in gobgp/table/path.go
type Path struct {
	Peerindex uint16
	Time      uint32
	Attrlen   uint16
	Attr      []byte
}

//Both Ribtable types have a header that will be populated by info in this
//struct. The caller should populate it accordingly. It contains placewords
//both for ribgens and ribdefs.
type RibTable struct {
	Seq  int
	AFI  uint16
	SAFI uint8
	Nlri []byte
	IP   net.IP
}

//this will be called from gobgp/table
func NewMrtTableDumpV2RIBDef(header RibTable, table []Path) MrtMsgIf {
	ret := &MrtTableDumpV2RIBDef{}
	ret.SequenceNum = uint32(header.Seq) //XXX: handle reset to 0 case
	//XXX: set the prefix correctly
	//create the entries from the table
	//finally brand the mrt by setting MrtMsgDef thingies
	//this should be a type
	ret.t = MSG_TABLE_DUMP_V2
	ret.st = RIB_IPV4_UNICAST //XXX: or ipv6 depending on prefix net.IP
	ret.time = time.Now()
	return ret
}

//implementig MrtMsgIf for ribdef
func (m *MrtTableDumpV2RIBDef) UnmarshalBinary(from []byte) error {
	return nil
}

func (m *MrtTableDumpV2RIBDef) MarshalBinary() ([]byte, error) {
	return nil, nil
}

//implementig MrtMsgIf for ribgen
func NewMrtTableDumpV2RIBGen(header RibTable, table []Path) MrtMsgIf {
	ret := &MrtTableDumpV2RIBGen{}
	ret.SequenceNum = uint32(header.Seq)
	ret.t = MSG_TABLE_DUMP_V2
	ret.st = RIB_GENERIC
	ret.time = time.Now()
	return ret
}

func (m *MrtTableDumpV2RIBGen) MarshalBinary() ([]byte, error) {
	b := new(bytes.Buffer)
	var err error
	w := func(a interface{}) {
		if err != nil {
			return
		}
		err = binary.Write(b, binary.BigEndian, a)
	}
	w(m.SequenceNum)
	w(m.AFI)
	w(m.SAFI)
	//for _, e := range m.NLRIEntries {
	//}
	if err != nil {
		return nil, err
	}
	w(m.EntryCount)
	for _, e := range m.Entries {
		w(e.PeerIndex)
		w(uint32(e.OrigTime.Unix()))
		w(e.AttrLen)
	}
	if err != nil {
		return nil, err
	}
	m.sz = uint32(b.Len()) //XXX sanity check
	hdr := m.MrtMsgDef
	hdrb, _ := hdr.MarshalBinary()
	log.Printf("MarshalBinary: msg with serialized vals: %+v  hdr:%+v , hdrb:%+v\n", m, hdr, hdrb)
	return append(hdrb, b.Bytes()...), nil
}

func (m *MrtTableDumpV2RIBGen) UnmarshalBinary(from []byte) error {
	return nil
}

type MrtFile struct {
	file    io.Reader
	entries uint32
	off     int64
}

const (
	MrtHdr_size = 12
	dump_size   = 10000
)

// mrt-type consts
const (
	MSG_NULL               = iota //  0 empty msg (deprecated)
	MSG_START                     //  1 sender is starting up
	MSG_DIE                       //  2 receiver should shut down (deprecated)
	MSG_I_AM_DEAD                 //  3 sender is shutting down
	MSG_PEER_DOWN                 //  4 sender's peer is down (deprecated)
	MSG_PROTOCOL_BGP              //  5 msg is a BGP packet (deprecated)
	MSG_PROTOCOL_RIP              //  6 msg is a RIP packet
	MSG_PROTOCOL_IDRP             //  7 msg is an IDRP packet (deprecated)
	MSG_PROTOCOL_RIPNG            //  8 msg is a RIPNG packet
	MSG_PROTOCOL_BGP4PLUS         //  9 msg is a BGP4+ packet (deprecated)
	MSG_PROTOCOL_BGP4PLUS1        // 10 msg is a BGP4+ (draft 01) (deprecated)
	MSG_PROTOCOL_OSPF             // 11 msg is an OSPF packet
	MSG_TABLE_DUMP                // 12 routing table dump
	MSG_TABLE_DUMP_V2             // 13 routing table dump
	MSG_PROTOCOL_BGP4MP    = 16   // 16 zebras own packet format
	MSG_PROTOCOL_BGP4MP_ET = 17
	MSG_PROTOCOL_ISIS      = 32 // 32 msg is a ISIS package
	MSG_PROTOCOL_ISIS_ET   = 33
	MSG_PROTOCOL_OSPFV3    = 48 // 48 msg is a OSPFv3 package
	MSG_PROTOCOL_OSPFV3_ET = 49
)

// mrt-subtype consts
const (
	BGP4MP_STATE_CHANGE      = 0 // state change
	BGP4MP_MESSAGE           = 1 // bgp message
	BGP4MP_MESSAGE_AS4       = 4 // same as BGP4MP_MESSAGE with 4byte AS
	BGP4MP_STATE_CHANGE_AS4  = 5
	BGP4MP_MESSAGE_LOCAL     = 6 // same as BGP4MP_MESSAGE but for self
	BGP4MP_MESSAGE_AS4_LOCAL = 7 // originated updates. Not implemented
)

const (
	OSPF_STATE_CHANGE = iota
	OSPF_LSA_UPDATE
)

const (
	PEER_INDEX_TABLE = iota + 1
	RIB_IPV4_UNICAST
	RIB_IPV4_MULTICAST
	RIB_IPV6_UNICAST
	RIB_IPV6_MULTICAST
	RIB_GENERIC
)

func NewMrtHdr(b []byte) (ret MrtHdr, err error) {
	buf := bytes.NewReader(b)
	err = binary.Read(buf, binary.BigEndian, &ret)
	return
}

func NewMrtFile(f io.Reader) (ret MrtFile) {
	ret = MrtFile{f, 0, 0}
	return
}

//This function can be passed into a bufio.Scanner.Split() to read buffered
//mrt msgs
func SplitMrt(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if cap(data) < MrtHdr_size { // read more
		return 0, nil, nil
	}
	//this reads the data and (they are big endian so it handles that)
	hdr, errh := NewMrtHdr(data[:MrtHdr_size])
	if errh != nil {
		return 0, nil, errh
	}
	totlen := int(hdr.Mrt_len + MrtHdr_size)
	if len(data) < totlen { //need to read more
		return 0, nil, nil
	}
	//logger.Printf("scanned mrt with len:%d datalen is :%d", totlen, len(data))
	return totlen, data[0:totlen], nil
}

func (f *MrtFile) Read(b []byte) (n int, err error) {
	//fmt.Printf(" b len:%v cap:%v\n",len(b), cap(b))
	if cap(b) < MrtHdr_size {
		err = errors.New("buffer size less than header size")
		return
	}
	n, err = f.file.Read(b[:MrtHdr_size])
	if err != nil {
		return
	}
	hdr, errh := NewMrtHdr(b[:MrtHdr_size])
	if errh != nil {
		err = errors.New(fmt.Sprintf("error in reading header from offset %v : %s", f.off, errh))
		return
	}
	//fmt.Printf("got header at offset:%d ! :%v\n", f.off, hdr)
	//n = int(hdr.Mrt_len+MrtHdr_size)
	//f.off = f.off + int64(n)
	f.entries = f.entries + 1
	//this will just jump over the msg
	//noff,errs := f.file.Seek(int64(hdr.Mrt_len), os.SEEK_CUR)
	if dump_size-(hdr.Mrt_len+MrtHdr_size) <= 0 {
		err = errors.New(fmt.Sprintf("bgp message of size:%v at offset is too large", hdr.Mrt_len, f.off+MrtHdr_size))
		return
	}
	//fmt.Printf("i will access b[%v:%v] len:%v cap:%v\n",MrtHdr_size, hdr.Mrt_len+MrtHdr_size, len(b), cap(b))
	nr, err := f.file.Read(b[MrtHdr_size : hdr.Mrt_len+MrtHdr_size])
	if nr != int(hdr.Mrt_len) {
		n = n + nr //header + len of read
		err = errors.New(fmt.Sprintf("error in reading bgp message of size :%v . got :%v bytes.", hdr.Mrt_len, n))
		return
	}
	n = n + nr
	f.off += int64(n)
	//fmt.Printf("seeked at offset:%d \n", f.off)
	return
}
