package radius

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// maximum RADIUS packet size
const maxPacketSize = 4095

// Code specifies the kind of RADIUS packet.
type Code byte

// Codes which are defined in RFC 2865 and RFC 5176.
const (
	CodeAccessRequest      Code = 1
	CodeAccessAccept       Code = 2
	CodeAccessReject       Code = 3
	CodeAccountingRequest  Code = 4
	CodeAccountingResponse Code = 5
	CodeAccessChallenge    Code = 11
	CodeStatusServer       Code = 12
	CodeStatusClient       Code = 13

	CodeDisconnectRequest Code = 40
	CodeDisconnectAck     Code = 41
	CodeDisconnectNak     Code = 42

	CodeReserved Code = 255
)

// Packet defines a RADIUS packet.
type Packet struct {
	Code          Code
	Identifier    byte
	Authenticator [16]byte

	Secret []byte

	Dictionary *Dictionary

	Attributes []*Attribute

	VendorId  uint32
	SubAttributes []*Attribute
}

// New returns a new packet with the given code and secret. The identifier and
// authenticator are filled with random data, and the dictionary is set to
// Builtin. nil is returned if not enough random data could be generated.
func New(code Code, secret []byte) *Packet {
	var buff [17]byte
	if _, err := rand.Read(buff[:]); err != nil {
		return nil
	}

	packet := &Packet{
		Code:       code,
		Identifier: buff[0],
		Secret:     secret,
		Dictionary: Builtin,
	}
	copy(packet.Authenticator[:], buff[1:])
	return packet
}

// Parse parses a RADIUS packet from wire data, using the given shared secret
// and dictionary. nil and an error is returned if there is a problem parsing
// the packet.
//
// Note: this function does not validate the authenticity of a packet.
// Ensuring a packet's authenticity should be done using the IsAuthentic
// method.
func Parse(data, secret []byte, dictionary *Dictionary) (*Packet, error) {
	if len(data) < 20 {
		return nil, errors.New("radius: packet must be at least 20 bytes long")
	}

	packet := &Packet{
		Code:       Code(data[0]),
		Identifier: data[1],
		Secret:     secret,
		Dictionary: dictionary,
	}

	length := binary.BigEndian.Uint16(data[2:4])
	if length < 20 || length > maxPacketSize {
		return nil, errors.New("radius: invalid packet length")
	}

	copy(packet.Authenticator[:], data[4:20])

	// Attributes
	attributes := data[20:]
	for len(attributes) > 0 {
		if len(attributes) < 2 {
			return nil, errors.New("radius: attribute must be at least 2 bytes long")
		}

		attrLength := attributes[1]
		if attrLength < 1 || attrLength > 253 || len(attributes) < int(attrLength) {
			return nil, errors.New("radius: invalid attribute length")
		}
		attrType := attributes[0]
		attrValue := attributes[2:attrLength]

		codec := dictionary.Codec(attrType)
		decoded, err := codec.Decode(packet, attrValue)
		if err != nil {
			return nil, err
		}
		attr := &Attribute{
			Type:  attrType,
			Value: decoded,
		}
		packet.AddAttr(attr)
		attributes = attributes[attrLength:]
	}

	// TODO: validate that the given packet (by code) has all the required attributes, etc.

	return packet, nil
}

// IsAuthentic returns if the packet is an authenticate response to the given
// request packet. Calling this function is only valid if both:
//  - p.code is one of:
//      CodeAccessAccept
//      CodeAccessReject
//      CodeAccountingRequest
//      CodeAccountingResponse
//      CodeAccessChallenge
//      CodeDisconnectRequest, Ack or Nak
//  - p.Authenticator contains the calculated authenticator
func (p *Packet) IsAuthentic(request *Packet) bool {
	switch p.Code {
	case CodeAccessAccept, CodeAccessReject, CodeAccountingRequest, CodeAccessChallenge,
		CodeDisconnectRequest, CodeDisconnectAck, CodeDisconnectNak:
		wire, err := p.Encode()
		if err != nil {
			return false
		}

		hash := md5.New()
		hash.Write(wire[0:4])
		if p.Code == CodeAccountingRequest || p.Code == CodeDisconnectRequest {
			var nul [16]byte
			hash.Write(nul[:])
		} else {
			hash.Write(request.Authenticator[:])
		}
		hash.Write(wire[20:])
		hash.Write(request.Secret)

		var sum [md5.Size]byte
		return bytes.Equal(hash.Sum(sum[0:0]), p.Authenticator[:])
	}
	return false
}

// ClearAttributes removes all of the packet's attributes.
func (p *Packet) ClearAttributes() {
	p.Attributes = nil
	p.SubAttributes = nil
	p.VendorId = 0
}

// Value returns the value of the first attribute whose dictionary name matches
// the given name. nil is returned if no such attribute exists.
func (p *Packet) Value(name string) interface{} {
	if attr := p.Attr(name); attr != nil {
		return attr.Value
	}
	return nil
}

// Attr returns the first attribute whose dictionary name matches the given
// name. nil is returned if no such attribute exists.
func (p *Packet) Attr(name string) *Attribute {
	for _, attr := range p.Attributes {
		if attrName, ok := p.Dictionary.Name(attr.Type, 0); ok && attrName == name {
			return attr
		}
	}
	for _, attr := range p.SubAttributes {
		if attrName, ok := p.Dictionary.Name(attr.Type, p.VendorId); ok && attrName == name {
			return attr
		}
	}
	return nil
}

// String returns the string representation of the value of the first attribute
// whose dictionary name matches the given name. The following rules are used
// for converting the attribute value to a string:
//
//  - If no such attribute exists with the given dictionary name, "" is
//    returned
//  - If the value implements fmt.Stringer, value.String() is returned
//  - If the value is string, itself is returned
//  - If the value is []byte, string(value) is returned
//  - Otherwise, "" is returned
func (p *Packet) String(name string) string {
	attr := p.Attr(name)
	if attr == nil {
		return ""
	}
	value := attr.Value

	if codec := p.Dictionary.Codec(attr.Type); codec != nil {
		if stringer, ok := codec.(AttributeStringer); ok {
			return stringer.String(value)
		}
	}

	if stringer, ok := value.(interface {
		String() string
	}); ok {
		return stringer.String()
	}

	if str, ok := value.(string); ok {
		return str
	}
	if raw, ok := value.([]byte); ok {
		return string(raw)
	}
	return ""
}

// Add adds an attribute whose dictionary name matches the given name.
func (p *Packet) Add(name string, value interface{}) error {
	attr, err := p.Dictionary.Attr(name, value)
	if err != nil {
		return err
	}
	return p.AddAttr(attr)
}

func (p *Packet) AddVSAAttr(attribute *Attribute) error {
	if vsa, ok := attribute.Value.(VendorSpecific); ok {
		vendor_id := vsa.VendorID
		vsa_data := vsa.Data

		// reset subattributes
		p.SubAttributes = nil
		p.VendorId = 0

		for _, attr := range p.Dictionary.SubAttributeDecode(vendor_id, vsa_data) {
			err := p.AddAttr(attr)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// AddAttr adds the given attribute to the packet.
func (p *Packet) AddAttr(attribute *Attribute) error {
	// when adding vsa attribute, instead add subattributes
	if attribute.Type == 26 {
		return p.AddVSAAttr(attribute)
	}

	//when adding subattributes
	if attribute.VendorId > 0 {
		if p.VendorId == 0 || p.VendorId == attribute.VendorId {
			// placeholder vsa attribute to trigger subattribute parsing on encode
			if p.VendorId == 0 {
				p.Attributes = append(p.Attributes, &Attribute{
					Type: 26,
				})
			}
			p.SubAttributes = append(p.SubAttributes, attribute)
			p.VendorId = attribute.VendorId
		} else {
			return errors.New(fmt.Sprintf("radius: can't add vsa vendor id mismatch %v %v", p.VendorId, attribute.VendorId))
		}
	} else {
		p.Attributes = append(p.Attributes, attribute)
	}
	return nil
}

// Set sets the value of the first attribute whose dictionary name matches the
// given name. If no such attribute exists, a new attribute is added
func (p *Packet) Set(name string, value interface{}) error {
	attr := p.Attr(name)
	if attr == nil || attr.Type == 26 {
		return p.Add(name, value)
	}
	_attr, err := p.Dictionary.Attr(name, value)
	if err == nil {
		attr.Value = _attr.Value
	}
	return err
}

// PAP returns the User-Name and User-Password attributes of an Access-Request
// packet.
//
// If the packet does not contain a User-Password attribute, the password is set
// to the empty string.
func (p *Packet) PAP() (username, password string, ok bool) {
	if p.Code != CodeAccessRequest {
		return
	}
	user := p.Value("User-Name")
	if user == nil {
		return
	}
	pass := p.Value("User-Password")
	if pass == nil {
		return
	}
	if userStr, valid := user.(string); valid {
		username = userStr
	} else {
		return
	}
	if passStr, valid := pass.(string); valid {
		password = passStr
	} else {
		username = ""
		return
	}
	ok = true
	return
}

// Encode encodes the packet to wire format. If there is an error encoding the
// packet, nil and an error is returned.
func (p *Packet) Encode() ([]byte, error) {
	var bufferAttrs bytes.Buffer
	var msg_auth_attr_offset = -1
	for _, attr := range p.Attributes {
		codec := p.Dictionary.Codec(attr.Type)
		value := attr.Value

		// allows setting VSA directly, or use p.SubAttributes (must have placeholder VSA attribute - can't use both)
		if attr.Type == 26 && len(p.SubAttributes) > 0 {
			vendor_id, data, err := p.Dictionary.SubAttributeEncode(p.SubAttributes, p.VendorId)
			if err != nil {
				return nil, errors.New("radius: sub attribute encoding error")
			}

			value = VendorSpecific {
				VendorID: vendor_id,
				Data: data,
			}
		}
		wire, err := codec.Encode(p, value)
		if err != nil {
			return nil, err
		}
		if len(wire) > 253 {
			return nil, errors.New("radius: encoded attribute is too long")
		}
		bufferAttrs.WriteByte(attr.Type)
		bufferAttrs.WriteByte(byte(len(wire) + 2))
		bufferAttrs.Write(wire)

		// if this was the Message-Authenticator attribute then remember where its value appears in the buffer so we can update it when we are done assembling the attributes
		if attr.Type == 80 && len(wire) == 16 { // checking for 16 is a sanity check
			msg_auth_attr_offset = bufferAttrs.Len() - 16
		}
	}

	length := 1 + 1 + 2 + 16 + bufferAttrs.Len()
	if length > maxPacketSize {
		return nil, errors.New("radius: encoded packet is too long")
	}

	attrBytes := bufferAttrs.Bytes()
	if msg_auth_attr_offset > 0 {
		// there is a Message-Authenticator attribute present. fill in the HMAC as defined by RFC 2869
		msgAuth := attrBytes[msg_auth_attr_offset : msg_auth_attr_offset+16]
		var nul [16]byte
		copy(msgAuth, nul[:])
		hash := hmac.New(md5.New, p.Secret)
		hash.Write([]byte{byte(p.Code), p.Identifier})
		binary.Write(hash, binary.BigEndian, uint16(length))
		if p.Code == CodeAccountingRequest || p.Code == CodeDisconnectRequest {
			var nul [16]byte
			hash.Write(nul[:])
		} else {
			hash.Write(p.Authenticator[:])
		}
		hash.Write(attrBytes)
		copy(msgAuth, hash.Sum(nil))
	}

	var buffer bytes.Buffer
	buffer.Grow(length)
	buffer.WriteByte(byte(p.Code))
	buffer.WriteByte(p.Identifier)
	binary.Write(&buffer, binary.BigEndian, uint16(length))

	switch p.Code {
	case CodeAccessRequest, CodeStatusServer:
		buffer.Write(p.Authenticator[:])
	case CodeAccessAccept, CodeAccessReject, CodeAccountingRequest, CodeAccountingResponse, CodeAccessChallenge,
		CodeDisconnectRequest, CodeDisconnectAck, CodeDisconnectNak:
		hash := md5.New()
		hash.Write(buffer.Bytes())
		if p.Code == CodeAccountingRequest || p.Code == CodeDisconnectRequest {
			var nul [16]byte
			hash.Write(nul[:])
		} else {
			hash.Write(p.Authenticator[:])
		}
		hash.Write(attrBytes)
		hash.Write(p.Secret)

		var sum [md5.Size]byte
		buffer.Write(hash.Sum(sum[0:0]))

		if p.Code == CodeAccountingRequest || p.Code == CodeDisconnectRequest {
			// save the calculated authenticator for the caller to use in validating the response
			copy(p.Authenticator[:], hash.Sum(sum[0:0]))
		}
	default:
		return nil, errors.New("radius: unknown Packet code")
	}

	buffer.ReadFrom(&bufferAttrs)

	return buffer.Bytes(), nil
}
