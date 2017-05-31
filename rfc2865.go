package radius

import (
	"bytes"
	"crypto/md5"

	"encoding/binary"
	"errors"
	"math"
	"fmt"
)

func init() {
	builtinOnce.Do(initDictionary)
	Builtin.MustRegister("User-Name", 1, AttributeText)
	Builtin.MustRegister("User-Password", 2, rfc2865UserPassword{})
	Builtin.MustRegister("CHAP-Password", 3, rfc2865ChapPassword{})
	Builtin.MustRegister("NAS-IP-Address", 4, AttributeAddress)
	Builtin.MustRegister("NAS-Port", 5, AttributeInteger)
	Builtin.MustRegister("Service-Type", 6, AttributeInteger)
	Builtin.MustRegister("Framed-Protocol", 7, AttributeInteger)
	Builtin.MustRegister("Framed-IP-Address", 8, AttributeAddress)
	Builtin.MustRegister("Framed-IP-Netmask", 9, AttributeAddress)
	Builtin.MustRegister("Framed-Routing", 10, AttributeInteger)
	Builtin.MustRegister("Filter-Id", 11, AttributeText)
	Builtin.MustRegister("Framed-MTU", 12, AttributeInteger)
	Builtin.MustRegister("Framed-Compression", 13, AttributeInteger)
	Builtin.MustRegister("Login-IP-Host", 14, AttributeAddress)
	Builtin.MustRegister("Login-Service", 15, AttributeInteger)
	Builtin.MustRegister("Login-TCP-Port", 16, AttributeInteger)
	Builtin.MustRegister("Reply-Message", 18, AttributeText)
	Builtin.MustRegister("Callback-Number", 19, AttributeString)
	Builtin.MustRegister("Callback-Id", 20, AttributeString)
	Builtin.MustRegister("Framed-Route", 22, AttributeText)
	Builtin.MustRegister("Framed-IPX-Network", 23, AttributeAddress)
	Builtin.MustRegister("State", 24, AttributeString)
	Builtin.MustRegister("Class", 25, AttributeString)
	Builtin.MustRegister("Vendor-Specific", 26, rfc2865VendorSpecific{})
	Builtin.MustRegister("Session-Timeout", 27, AttributeInteger)
	Builtin.MustRegister("Idle-Timeout", 28, AttributeInteger)
	Builtin.MustRegister("Termination-Action", 29, AttributeInteger)
	Builtin.MustRegister("Called-Station-Id", 30, AttributeString)
	Builtin.MustRegister("Calling-Station-Id", 31, AttributeString)
	Builtin.MustRegister("NAS-Identifier", 32, AttributeString)
	Builtin.MustRegister("Proxy-State", 33, AttributeString)
	Builtin.MustRegister("Login-LAT-Service", 34, AttributeString)
	Builtin.MustRegister("Login-LAT-Node", 35, AttributeString)
	Builtin.MustRegister("Login-LAT-Group", 36, AttributeString)
	Builtin.MustRegister("Framed-AppleTalk-Link", 37, AttributeInteger)
	Builtin.MustRegister("Framed-AppleTalk-Network", 38, AttributeInteger)
	Builtin.MustRegister("Framed-AppleTalk-Zone", 39, AttributeString)
	Builtin.MustRegister("CHAP-Challenge", 60, AttributeString)
	Builtin.MustRegister("NAS-Port-Type", 61, AttributeInteger)
	Builtin.MustRegister("Port-Limit", 62, AttributeInteger)
	Builtin.MustRegister("Login-LAT-Port", 63, AttributeString)

	// FreeRADIUS specific
	Builtin.MustRegister("Message-Authenticator", 80, AttributeString)
	Builtin.MustRegister("FreeRADIUS-Statistics-Type", 127, AttributeInteger)

	Builtin.MustRegister("FreeRADIUS-Total-Access-Requests", 128, AttributeString)
	Builtin.MustRegister("FreeRADIUS-Total-Access-Accepts", 129, AttributeString)
	Builtin.MustRegister("FreeRADIUS-Total-Access-Rejects", 130, AttributeString)
	Builtin.MustRegister("FreeRADIUS-Total-Access-Challenges", 131, AttributeString)
	Builtin.MustRegister("FreeRADIUS-Total-Auth-Responses", 132, AttributeString)
	Builtin.MustRegister("FreeRADIUS-Total-Auth-Duplicate-Requests", 133, AttributeString)
	Builtin.MustRegister("FreeRADIUS-Total-Auth-Malformed-Requests", 134, AttributeString)
	Builtin.MustRegister("FreeRADIUS-Total-Auth-Invalid-Requests", 135, AttributeString)
	Builtin.MustRegister("FreeRADIUS-Total-Auth-Dropped-Requests", 136, AttributeString)
	Builtin.MustRegister("FreeRADIUS-Total-Auth-Unknown-Types", 137, AttributeString)
}

type rfc2865UserPassword struct{}


func (rfc2865UserPassword) Decode(p *Packet, value []byte) (interface{}, error) {
	if p.Secret == nil {
		return nil, errors.New("radius: User-Password attribute requires Packet.Secret")
	}
	if len(value) < 16 || len(value) > 128 {
		return nil, errors.New("radius: invalid User-Password attribute length")
	}

	dec := make([]byte, 0, len(value))

	hash := md5.New()
	hash.Write(p.Secret)
	hash.Write(p.Authenticator[:])
	dec = hash.Sum(dec)

	for i, b := range value[:16] {
		dec[i] ^= b
	}

	for i := 16; i < len(value); i += 16 {
		hash.Reset()
		hash.Write(p.Secret)
		hash.Write(value[i-16 : i])
		dec = hash.Sum(dec)

		for j, b := range value[i : i+16] {
			dec[i+j] ^= b
		}
	}

	if i := bytes.IndexByte(dec, 0); i > -1 {
		return string(dec[:i]), nil
	}
	return string(dec), nil
}

func (rfc2865UserPassword) Encode(p *Packet, value interface{}) ([]byte, error) {
	if p.Secret == nil {
		return nil, errors.New("radius: User-Password attribute requires Packet.Secret")
	}
	var password []byte
	if bytePassword, ok := value.([]byte); !ok {
		strPassword, ok := value.(string)
		if !ok {
			return nil, errors.New("radius: User-Password attribute must be string or []byte")
		}
		password = []byte(strPassword)
	} else {
		password = bytePassword
	}

	if len(password) > 128 {
		return nil, errors.New("radius: User-Password longer than 128 characters")
	}

	chunks := int(math.Ceil(float64(len(password)) / 16.))
	if chunks == 0 {
		chunks = 1
	}

	enc := make([]byte, 0, chunks*16)

	hash := md5.New()
	hash.Write(p.Secret)
	hash.Write(p.Authenticator[:])
	enc = hash.Sum(enc)

	// need to pad password with nils
	if len(enc) - len(password) > 0 {
		padded_password := make([]byte, len(enc))
		copy(padded_password, password)
		password = padded_password
	}

	for i, b := range password[:16] {
		enc[i] ^= b
	}

	for i := 16; i < len(password); i += 16 {
		hash.Reset()
		hash.Write(p.Secret)
		hash.Write(enc[i-16 : i])
		enc = hash.Sum(enc)

		for j, b := range password[i : i+16] {
			enc[i+j] ^= b
		}
	}

	fmt.Println("password", enc)

	return enc, nil
}

type rfc2865ChapPassword struct{}

func (rfc2865ChapPassword) Encode(p *Packet, value interface{}) ([]byte, error) {
	var password []byte
	if bytePassword, ok := value.([]byte); !ok {
		strPassword, ok := value.(string)
		if !ok {
			return nil, errors.New("radius: CHAP-Password attribute must be string or []byte")
		}
		password = []byte(strPassword)
	} else {
		password = bytePassword
	}

	if len(password) > 128 {
		return nil, errors.New("radius: CHAP-Password longer than 128 characters")
	}

	var chapChallenge []byte
	if p.Value("CHAP-Challenge") != nil {
		chapChallenge = []byte(p.Value("CHAP-Challenge").(string))

	} else {
		chapChallenge = p.Authenticator[:]
	}

	code := make([]byte, 1)
	code[0] = 0x01

	hash := md5.New()
	hash.Write(code)
	hash.Write(password)
	hash.Write(chapChallenge)
	enc := hash.Sum(nil)

	enc = append(code, enc...)

	return enc, nil
}

func (rfc2865ChapPassword) Decode(p *Packet, value []byte) (interface{}, error) {
	return nil, errors.New("radius: decode doesn't work, see https://www.ietf.org/rfc/rfc1334.txt")
}


// VendorSpecific defines RFC 2865's Vendor-Specific attribute.
type VendorSpecific struct {
	VendorID uint32
	Data     []byte
}

type rfc2865VendorSpecific struct{}

func (rfc2865VendorSpecific) Decode(p *Packet, value []byte) (interface{}, error) {
	if len(value) < 5 {
		return nil, errors.New("radius: Vendor-Specific attribute too small")
	}
	var attr VendorSpecific
	attr.VendorID = binary.BigEndian.Uint32(value[:4])
	attr.Data = make([]byte, len(value)-4)
	copy(attr.Data, value[4:])
	return attr, nil
}

func (rfc2865VendorSpecific) Encode(p *Packet, value interface{}) ([]byte, error) {
	attr, ok := value.(VendorSpecific)
	if !ok {
		return nil, errors.New("radius: Vendor-Specific attribute is not type VendorSpecific")
	}
	b := make([]byte, 4+len(attr.Data))
	binary.BigEndian.PutUint32(b[:4], attr.VendorID)
	copy(b[4:], attr.Data)
	return b, nil
}
