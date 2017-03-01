package main

import (
	"log"
	"net"
	"sync"
	"time"

	"encoding/binary"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

type scanner struct {
	conn     *net.IPConn
	wconn    *net.IPConn
	mutex    sync.Mutex
	closed   bool
	die      chan bool
	synch    chan net.IP
	rstch    chan net.IP
	synackch chan net.IP
	syndata  []byte
	rstdata  []byte
	srcip    net.IP
	basen    uint32
	ones     int
	limit    int
	times    int
	ipnet    *net.IPNet
	rstmap   *bitmap
	ackmap   *bitmap
}

func (s *scanner) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.die)
	s.conn.Close()
	s.wconn.Close()
	return nil
}

func newScanner(port int, ipnet *net.IPNet, limit int, times int) (s *scanner, err error) {
	udp, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return
	}
	defer udp.Close()
	uaddr := udp.LocalAddr().(*net.UDPAddr)
	conn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: uaddr.IP})
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()
	wconn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: uaddr.IP})
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			wconn.Close()
		}
	}()
	rconn, err := ipv4.NewRawConn(conn)
	if err != nil {
		return
	}
	err = rconn.SetBPF([]bpf.RawInstruction{
		{0x30, 0, 0, 0x00000009},
		{0x15, 0, 8, 0x00000006},
		{0x28, 0, 0, 0x00000006},
		{0x45, 6, 0, 0x00001fff},
		{0xb1, 0, 0, 0x00000000},
		{0x48, 0, 0, 0x00000000},
		{0x15, 0, 3, uint32(port)},
		{0x48, 0, 0, 0x00000002},
		{0x15, 0, 1, uint32(3245)},
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000},
	})
	if err != nil {
		return
	}
	synlayer := &tcpLayer{
		srcPort: 3245,
		dstPort: port,
		window:  65535,
		ackn:    0,
		seqn:    832764234,
		flags:   SYN,
	}
	rstlayer := &tcpLayer{
		srcPort: 3245,
		dstPort: port,
		window:  65535,
		ackn:    0,
		seqn:    832764234,
		flags:   RST,
	}
	s = &scanner{
		conn:     conn,
		wconn:    wconn,
		die:      make(chan bool),
		synch:    make(chan net.IP, 65536),
		rstch:    make(chan net.IP, 65536),
		synackch: make(chan net.IP, 65536),
		syndata:  synlayer.marshal(),
		rstdata:  rstlayer.marshal(),
		srcip:    uaddr.IP,
	}
	s.ones, _ = ipnet.Mask.Size()
	s.basen = binary.BigEndian.Uint32(ipnet.IP.To4())
	s.limit = limit
	s.ipnet = ipnet
	s.times = times
	s.ackmap = newBitmap(int64(1) << uint32(32-s.ones))
	s.rstmap = newBitmap(int64(1) << uint32(32-s.ones))
	return
}

func (s *scanner) sendRST(ip net.IP) (err error) {
	binary.BigEndian.PutUint16(s.rstdata[16:], 0)
	binary.BigEndian.PutUint16(s.rstdata[16:], csum(s.rstdata, s.srcip, ip))
	_, err = s.wconn.WriteTo(s.rstdata, &net.IPAddr{IP: ip})
	return
}

func (s *scanner) sendSYN(ip net.IP) (err error) {
	// log.Println("send to ", ip)
	binary.BigEndian.PutUint16(s.syndata[16:], 0)
	binary.BigEndian.PutUint16(s.syndata[16:], csum(s.syndata, s.srcip, ip))
	_, err = s.wconn.WriteTo(s.syndata, &net.IPAddr{IP: ip})
	return
}

func (s *scanner) sender(f func(net.IP) error, ch chan net.IP) {
	defer s.Close()
	for {
		select {
		case <-s.die:
			return
		case ip := <-ch:
			v := binary.BigEndian.Uint32(ip.To4()) ^ s.basen
			if s.ackmap.check(v) || s.rstmap.check(v) {
				continue
			}
			for {
				err := f(ip)
				if err != nil {
					time.Sleep(time.Millisecond * 10)
				} else {
					break
				}
			}
			if s.limit != 0 {
				time.Sleep(time.Second / time.Duration(s.limit))
			}
		}
	}
}

func (s *scanner) synackReader() {
	defer s.Close()
	buf := make([]byte, 1500)
	var mask uint32
	if s.ones < 32 {
		mask = uint32(1<<uint32(32-s.ones)) - 1
	}
	for {
		var n int
		var ipaddr *net.IPAddr
		var err error
		n, ipaddr, err = s.conn.ReadFromIP(buf)
		if err != nil {
			log.Fatal(err)
		}
		if !s.ipnet.Contains(ipaddr.IP) {
			continue
		}
		tcp, err := decodeTCPlayer(buf[:n])
		if err != nil {
			continue
		}
		v := binary.BigEndian.Uint32(ipaddr.IP.To4()) & mask
		if s.rstmap.check(v) || s.ackmap.check(v) {
			continue
		}
		if tcp.chkFlag(RST) {
			s.rstmap.set(v)
			log.Println("rst: ", ipaddr.IP)
		}
		if tcp.chkFlag(SYN | ACK) {
			s.ackmap.set(v)
			log.Println("ack: ", ipaddr.IP)
		}
	}
}

func (s *scanner) run() {
	defer s.Close()
	go s.sender(s.sendSYN, s.synch)
	go s.synackReader()
	var max uint32
	if s.ones < 32 {
		max = uint32(1<<uint32(32-s.ones)) - 1
	}
	f := func() {
		var ip [4]byte
		for i := uint32(0); i <= max; i++ {
			binary.BigEndian.PutUint32(ip[:], s.basen|i)
			select {
			case <-s.die:
				return
			case s.synch <- net.IPv4(ip[0], ip[1], ip[2], ip[3]):
			}
		}
	}
	for i := 0; i < s.times; i++ {
		f()
	}
	time.Sleep(time.Second)
}
