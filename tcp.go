package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	tcpOptionKindEndList                         = 0
	tcpOptionKindNop                             = 1
	tcpOptionKindMSS                             = 2  // len = 4
	tcpOptionKindWindowScale                     = 3  // len = 3
	tcpOptionKindSACKPermitted                   = 4  // len = 2
	tcpOptionKindSACK                            = 5  // len = n
	tcpOptionKindEcho                            = 6  // len = 6, obsolete
	tcpOptionKindEchoReply                       = 7  // len = 6, obsolete
	tcpOptionKindTimestamps                      = 8  // len = 10
	tcpOptionKindPartialOrderConnectionPermitted = 9  // len = 2, obsolete
	tcpOptionKindPartialOrderServiceProfile      = 10 // len = 3, obsolete
	tcpOptionKindCC                              = 11 // obsolete
	tcpOptionKindCCNew                           = 12 // obsolete
	tcpOptionKindCCEcho                          = 13 // obsolete
	tcpOptionKindAltChecksum                     = 14 // len = 3, obsolete
	tcpOptionKindAltChecksumData                 = 15 // len = n, obsolete
)

const (
	FIN = 1
	SYN = 2
	RST = 4
	PSH = 8
	ACK = 16
	URG = 32

	ECE = 1
	CWR = 2
	NS  = 4
)

const (
	tcpLen = 20 // FIXME
)

type iPv4Layer struct {
	srcip net.IP
	dstip net.IP
}

type tcpOption struct {
	kind   uint8
	length uint8
	data   []byte
}

type tcpLayer struct {
	srcPort    int
	dstPort    int
	seqn       uint32
	ackn       uint32
	dataOffset uint8 // 4 bits, headerLen = dataOffset << 2
	reserved   uint8 // 3 bits, must be zero
	ecn        uint8 // 3 bits, NS, CWR and ECE
	flags      uint8 // 6 bits, URG, ACK, PSH, RST, SYN and FIN
	window     uint16
	chksum     uint16
	urgent     uint16 // if URG is set
	options    []tcpOption
	opts       [4]tcpOption // pre allocate
	padding    []byte
	pads       [4]byte // pre allocate
	payload    []byte
	data       []byte // if data is not nil, marshal method will use this slice
}

func decodeTCPlayer(data []byte) (tcp *tcpLayer, err error) {
	tcp = &tcpLayer{}
	defer func() {
		if err != nil {
			tcp = nil
		}
	}()

	length := len(data)
	if length < tcpLen {
		err = fmt.Errorf("Invalid TCP packet length %d < %d", length, tcpLen)
		return
	}

	tcp.srcPort = int(binary.BigEndian.Uint16(data[:2]))
	tcp.dstPort = int(binary.BigEndian.Uint16(data[2:4]))
	tcp.seqn = binary.BigEndian.Uint32(data[4:8])
	tcp.ackn = binary.BigEndian.Uint32(data[8:12])

	u16 := binary.BigEndian.Uint16(data[12:14])
	tcp.dataOffset = uint8(u16 >> 12)
	tcp.reserved = uint8(u16 >> 9 & (1<<3 - 1))
	tcp.ecn = uint8(u16 >> 6 & (1<<3 - 1))
	tcp.flags = uint8(u16 & (1<<6 - 1))
	if (length >> 2) < int(tcp.dataOffset) {
		err = errors.New("TCP data offset greater than packet length")
		return
	}
	headerLen := int(tcp.dataOffset) << 2

	tcp.window = binary.BigEndian.Uint16(data[14:16])
	tcp.chksum = binary.BigEndian.Uint16(data[16:18])
	tcp.urgent = binary.BigEndian.Uint16(data[18:20])

	if length > headerLen {
		tcp.payload = data[headerLen:]
	}

	if headerLen == tcpLen {
		return
	}

	data = data[tcpLen:headerLen]
	for len(data) > 0 {
		if tcp.options == nil {
			tcp.options = tcp.opts[:0]
		}
		tcp.options = append(tcp.options, tcpOption{kind: data[0]})
		opt := &tcp.options[len(tcp.options)-1]
		switch opt.kind {
		case tcpOptionKindEndList:
			opt.length = 1
			tcp.padding = data[1:]
			break
		case tcpOptionKindNop:
			opt.length = 1
		default:
			opt.length = data[1]
			if opt.length < 2 {
				err = fmt.Errorf("Invalid TCP option length %d < 2", opt.length)
				return
			} else if int(opt.length) > len(data) {
				err = fmt.Errorf("Invalid TCP option length %d exceeds remaining %d bytes", opt.length, len(data))
				return
			}
			opt.data = data[2:opt.length]
		}
		data = data[opt.length:]
	}

	return
}

func (tcp *tcpLayer) marshal() (data []byte) {
	tcp.padding = nil

	headerLen := tcpLen
	for _, v := range tcp.options {
		switch v.kind {
		case tcpOptionKindEndList, tcpOptionKindNop:
			headerLen++
		default:
			v.length = uint8(len(v.data) + 2)
			headerLen += int(v.length)
		}
	}
	if rem := headerLen % 4; rem != 0 {
		tcp.padding = tcp.pads[:4-rem]
		headerLen += len(tcp.padding)
	}

	if len(tcp.data) >= len(tcp.payload)+headerLen {
		data = tcp.data
	} else {
		data = make([]byte, len(tcp.payload)+headerLen)
	}

	binary.BigEndian.PutUint16(data, uint16(tcp.srcPort))
	binary.BigEndian.PutUint16(data[2:], uint16(tcp.dstPort))
	binary.BigEndian.PutUint32(data[4:], tcp.seqn)
	binary.BigEndian.PutUint32(data[8:], tcp.ackn)

	var u16 uint16
	tcp.dataOffset = uint8(headerLen / 4)
	u16 = uint16(tcp.dataOffset) << 12
	u16 |= uint16(tcp.reserved) << 9
	u16 |= uint16(tcp.ecn) << 6
	u16 |= uint16(tcp.flags)
	binary.BigEndian.PutUint16(data[12:], u16)

	binary.BigEndian.PutUint16(data[14:], tcp.window)
	binary.BigEndian.PutUint16(data[18:], tcp.urgent)

	start := 20
	for _, v := range tcp.options {
		data[start] = byte(v.kind)
		switch v.kind {
		case tcpOptionKindEndList, tcpOptionKindNop:
			start++
		default:
			data[start+1] = v.length
			copy(data[start+2:start+len(v.data)+2], v.data)
			start += int(v.length)
		}
	}
	copy(data[start:], tcp.padding)
	start += len(tcp.padding)
	copy(data[start:], tcp.payload)
	binary.BigEndian.PutUint16(data[16:], 0)
	data = data[:start+len(tcp.payload)]
	// binary.BigEndian.PutUint16(data[16:], csum(data, srcip, dstip))
	return
}

func (tcp *tcpLayer) setFlag(flag uint8) {
	tcp.flags |= flag
}

func (tcp *tcpLayer) chkFlag(flag uint8) bool {
	return tcp.flags&flag == flag
}

func csum(data []byte, srcip, dstip net.IP) uint16 {
	srcip = srcip.To4()
	dstip = dstip.To4()
	pseudoHeader := []byte{
		srcip[0], srcip[1], srcip[2], srcip[3],
		dstip[0], dstip[1], dstip[2], dstip[3],
		0, // reserved
		6, // tcp protocol number
		0, 0,
	}
	binary.BigEndian.PutUint16(pseudoHeader[10:], uint16(len(data)))

	var sum uint32

	f := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 != 0 {
			sum += uint32(binary.BigEndian.Uint16([]byte{b[len(b)-1], 0}))
		}
	}

	f(pseudoHeader)
	f(data)

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return uint16(^sum)
}
