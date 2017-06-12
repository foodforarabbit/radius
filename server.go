package radius

import (
	"log"
	"errors"
	"net"
	"sync"
	"fmt"
)

// Handler is a value that can handle a server's RADIUS packet event.
type Handler interface {
	ServeRadius(w ResponseWriter, p *Packet)
}

type ErrorHandler interface {
	Error(e error, p *Packet)
}

// HandlerFunc is a wrapper that allows ordinary functions to be used as a
// handler.
type HandlerFunc func(w ResponseWriter, p *Packet)

type ErrorFunc func(e error, p *Packet)

// ServeRadius calls h(w, p).
func (h HandlerFunc) ServeRadius(w ResponseWriter, p *Packet) {
	h(w, p)
}

// Handle any errors
func (h ErrorFunc) Error(e error, p *Packet) {
	h(e, p)
}


// ResponseWriter is used by Handler when replying to a RADIUS packet.
type ResponseWriter interface {
	// LocalAddr returns the address of the local server that accepted the
	// packet.
	LocalAddr() net.Addr

	// RemoteAddr returns the address of the remote client that sent to packet.
	RemoteAddr() net.Addr

	// Write sends a packet to the sender.
	Write(packet *Packet) error

	// AccessAccept sends an Access-Accept packet to the sender that includes
	// the given attributes.
	AccessAccept(attributes ...*Attribute) error

	// AccessAccept sends an Access-Reject packet to the sender that includes
	// the given attributes.
	AccessReject(attributes ...*Attribute) error

	// AccessAccept sends an Access-Challenge packet to the sender that includes
	// the given attributes.
	AccessChallenge(attributes ...*Attribute) error

	AccountingResponse(attributes ...*Attribute) error
}

type responseWriter struct {
	// listener that received the packet
	conn *net.UDPConn
	// where the packet came from
	addr *net.UDPAddr
	// original packet
	packet *Packet
}

func (r *responseWriter) LocalAddr() net.Addr {
	return r.conn.LocalAddr()
}

func (r *responseWriter) RemoteAddr() net.Addr {
	return r.addr
}

func (r *responseWriter) accessRespond(code Code, attributes ...*Attribute) error {
	packet := Packet{
		Code:          code,
		Identifier:    r.packet.Identifier,
		Authenticator: r.packet.Authenticator,

		Secret: r.packet.Secret,

		Dictionary: r.packet.Dictionary,

		Attributes: attributes,
	}
	return r.Write(&packet)
}

func (r *responseWriter) AccessAccept(attributes ...*Attribute) error {
	// TOOD: do not send if packet was not Access-Request
	return r.accessRespond(CodeAccessAccept, attributes...)
}

func (r *responseWriter) AccessReject(attributes ...*Attribute) error {
	// TOOD: do not send if packet was not Access-Request
	return r.accessRespond(CodeAccessReject, attributes...)
}

func (r *responseWriter) AccessChallenge(attributes ...*Attribute) error {
	// TOOD: do not send if packet was not Access-Request
	return r.accessRespond(CodeAccessChallenge, attributes...)
}

func (r *responseWriter) AccountingResponse(attributes ...*Attribute) error {
	// TOOD: do not send if packet was not Access-Request
	return r.accessRespond(CodeAccountingResponse, attributes...)
}


func (r *responseWriter) Write(packet *Packet) error {
	raw, err := packet.Encode()
	if err != nil {
		return err
	}
	if _, err := r.conn.WriteToUDP(raw, r.addr); err != nil {
		return err
	}
	return nil
}

// Server is a server that listens for and handles RADIUS packets.
type Server struct {
	// Address to bind the server on. If empty, the address defaults to ":1812".
	Addr string

	// Network of the server. Valid values are "udp", "udp4", "udp6". If empty,
	// the network defaults to "udp".
	Network string

	// The shared secret between the client and server.
	Secret []byte

	// Client->Secret mapping
	ClientsMap map[string]string
	clientIP []string
	ClientIPMap map[string]string
	ClientNetMap map[string]string

	// Dictionary used when decoding incoming packets.
	Dictionary *Dictionary

	// The packet handler that handles incoming, valid packets.
	Handler Handler

	// Error handler for any errors outside the handler
	ErrorHandler ErrorHandler

	// Listener
	listener *net.UDPConn

	// quit channel
	CloseChan chan bool
}

func (s *Server) ResetClientNetMap() error {

	s.ClientNetMap = make(map[string]string, 0)
	s.ClientIPMap = make(map[string]string, 0)
	ipParseErrors := make([]string, 0)

		// return errors.New("Unable to parse CIDR or IP " + k)
	if s.ClientsMap != nil {
		for k, v := range s.ClientsMap {

			ip, subnet, err := net.ParseCIDR(k)
			if err == nil {
				s.ClientNetMap[subnet.String()] = v
			} else {
				ip = net.ParseIP(k)
				if ip != nil {
					s.ClientIPMap[string(ip)] = v
				} else {
					ipParseErrors = append(ipParseErrors, k)
				}
			}
		}
	}
	if len(ipParseErrors) > 0{
		return errors.New("Unable to parse CIDR or IP " + fmt.Sprintf("%v", ipParseErrors))
	}
	return nil
}

func (s *Server) AddClientsMap(m map[string]string ) {
	if s.ClientsMap == nil  && len(m) > 0 {
		s.ClientsMap = m
		s.ResetClientNetMap()
	}

}

func defaultErrorHandler(e error, p *Packet) {
	log.Printf("Radius Server Error %v", e)
}

// ListenAndServe starts a RADIUS server on the address given in s.
func (s *Server) ListenAndServe() error {
	if s.listener != nil {
		return errors.New("radius: server already started")
	}

	if s.ErrorHandler == nil {
		s.ErrorHandler = ErrorFunc(defaultErrorHandler)
	}

	if s.Handler == nil {
		err := errors.New("radius: nil Handler")
		s.ErrorHandler.Error(err, nil)
		return err
	}

	if s.CloseChan == nil {
		s.CloseChan = make(chan bool)
	}

	addrStr := ":1812"
	if s.Addr != "" {
		addrStr = s.Addr
	}

	network := "udp"
	if s.Network != "" {
		network = s.Network
	}

	addr, err := net.ResolveUDPAddr(network, addrStr)
	if err != nil {
		s.ErrorHandler.Error(err, nil)
		return err
	}
	s.listener, err = net.ListenUDP(network, addr)
	if err != nil {
		s.ErrorHandler.Error(err, nil)
		return err
	}

	if s.ClientsMap != nil {
		// double check, either IP or IPNet range
		err =  s.ResetClientNetMap()
		if err != nil {
			s.ErrorHandler.Error(err, nil)
		}
	}

	type activeKey struct {
		IP         string
		Identifier byte
	}

	var (
		activeLock sync.Mutex
		active     = map[activeKey]bool{}
	)

	for {
		select {
		case <- s.CloseChan:
			return nil
		default:
			buff := make([]byte, 4096)
			n, remoteAddr, err := s.listener.ReadFromUDP(buff)
			if err != nil && !err.(*net.OpError).Temporary() {
				s.ErrorHandler.Error(err, nil)
				break
			}

			if n == 0 {
				continue
			}

			buff = buff[:n]
			go func(conn *net.UDPConn, buff []byte, remoteAddr *net.UDPAddr) {
				secret := s.Secret

				inClientIPMap := false
				inClientNetMap := false

				if s.ClientIPMap[string(remoteAddr.IP)] != "" {
					secret = []byte( s.ClientIPMap[string(remoteAddr.IP)] )
					inClientIPMap = true
				} else {
					if s.ClientNetMap != nil {
				    for k, v := range s.ClientNetMap {

							_, subnet, err := net.ParseCIDR(k)
							if err != nil {
								s.ErrorHandler.Error(err, nil)
							}
							if subnet.Contains(remoteAddr.IP) {
							    secret = []byte(v)
									inClientNetMap = true
									break
							}
				    }
					}
				}
				if !inClientIPMap && !inClientNetMap {
					err := errors.New(fmt.Sprintf("%v", remoteAddr.IP) + " is not configured")
					s.ErrorHandler.Error(err, nil)
					return
				}

				packet, err := Parse(buff, secret, s.Dictionary)
				if err != nil {
					s.ErrorHandler.Error(err, nil)
					return
				}

				key := activeKey{
					IP:         remoteAddr.String(),
					Identifier: packet.Identifier,
				}

				activeLock.Lock()
				if _, ok := active[key]; ok {
					activeLock.Unlock()
					err = errors.New(remoteAddr.String() + " busy")
					s.ErrorHandler.Error(err, nil)
					return
				}
				active[key] = true
				activeLock.Unlock()

				response := responseWriter{
					conn:   conn,
					addr:   remoteAddr,
					packet: packet,
				}

				s.Handler.ServeRadius(&response, packet)

				activeLock.Lock()
				delete(active, key)
				activeLock.Unlock()
			}(s.listener, buff, remoteAddr)
		}
	}
	return errors.New("server has stopped working unexpectedly")
}

// Close stops listening for packets. Any packet that is currently being
// handled will not be able to respond to the sender.
func (s *Server) Close() error {
	if s.CloseChan != nil {
		s.CloseChan <- true
	}
	if s.listener == nil {
		return nil
	}
	defer func() {
		s.listener = nil
	}()
	return s.listener.Close()
}
