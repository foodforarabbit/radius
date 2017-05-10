package radius

import (
	"errors"
	"sync"
	"fmt"
	"os"
	"bufio"
	"strings"
	"encoding/binary"
	"bytes"
	"strconv"
)

var builtinOnce sync.Once

// Builtin is the built-in dictionary. It is initially loaded with the
// attributes defined in RFC 2865 and RFC 2866.
var Builtin *Dictionary

func initDictionary() {
	Builtin = &Dictionary{}
	Builtin.InitObjects()
}

type dictEntry struct {
	Type  byte
	Name  string
	Codec AttributeCodec
}

type dictAttr struct {
	attributesByType [1069]*dictEntry
	attributesByName map[string]*dictEntry
}

// Dictionary stores mappings between attribute names and types and
// AttributeCodecs.
type Dictionary struct {
	mu              	sync.RWMutex						// mutex lock
	Vendor						string									// current Vendor name
	VendorId					map[string]uint32					// vendor name to id map
	VendorName				map[uint32]string					// vendor id to name map
	AttributeVendorId map[string]uint32					// attribute to vendor id map
	values						map[uint32]*dictAttr				// vendor id to attribute dictionary map
}

func (d *Dictionary) to_byte(bst string) byte {
	i, _ := strconv.ParseInt(bst, 10, 8)
	b_buf := bytes.NewBuffer([]byte{})
	binary.Write(b_buf, binary.LittleEndian, i)
	return b_buf.Bytes()[0]
}

// vendor attribute parsing
func (d *Dictionary) ParseAttrs(arr []string, _vendor_id ...uint32) bool {
	if len(arr) != 4 {
		return false
	}
	if strings.ToUpper(arr[0]) == "ATTRIBUTE" {
		num, _ := strconv.ParseInt(arr[2], 10, 32)
		if num > 255 {
			return false
		}
		switch arr[3] {
			case "string":
				d.MustRegister(arr[1], d.to_byte(arr[2]), AttributeString, _vendor_id...)
			case "integer":
				d.MustRegister(arr[1], d.to_byte(arr[2]), AttributeInteger, _vendor_id...)
			case "ipaddr":
				d.MustRegister(arr[1], d.to_byte(arr[2]), AttributeAddress, _vendor_id...)
			case "octets":
				d.MustRegister(arr[1], d.to_byte(arr[2]), AttributeString, _vendor_id...)
			case "date":
				d.MustRegister(arr[1], d.to_byte(arr[2]), AttributeTime, _vendor_id...)
		}
		return true
	}
	return false
}

// vendor id parsing
func (d *Dictionary) ParseVendor(arr []string) bool {
	if len(arr) == 3 && strings.ToUpper(arr[0]) == "VENDOR" {
		vendor_id, _ := strconv.ParseUint(arr[2], 10, 32)
		if vendor_id > 0 {
			d.RegisterVendor(arr[1], uint32(vendor_id))
			return true
		}
	}
	return false
}

// vendor attributes begin parsing
func (d *Dictionary) ParseBeginVendor(arr []string ) (vendor_name string, ok bool) {
	if len(arr) == 2 && strings.ToUpper(arr[0]) == "BEGIN-VENDOR" {
		vendor_name = arr[1]
		ok = true
	}
	return
}

// vendor attributes end parsing
func (d *Dictionary) ParseEndVendor(arr  []string ) (vendor_name string, ok bool) {
	if len(arr) == 2 && strings.ToUpper(arr[0]) == "END-VENDOR" {
		vendor_name = arr[1]
		ok = true
	}
	return
}


// load vsa dictionary file to be parsed
// see paloalto.dictionary for example
func (d *Dictionary) LoadDicts(path string) error {
	// _, err := filepath.Abs(filepath.Dir(path))
	// if err != nil {
	// 	return err
	// }

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return err
	}
	inFile, _ := os.Open(path)
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
//	scanner.Split(bufio.ScanLines)

	var vendor_id uint32
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		arr := strings.Fields(line)

		if !d.ParseAttrs(arr, vendor_id) && !d.ParseVendor(arr){
			if vendor_name, ok := d.ParseBeginVendor(arr); ok {
				if vendor_id, ok = d.VendorId[vendor_name]; !ok {
					return errors.New(fmt.Sprintf("radius: vendor %v is not registered", vendor_name))
				}
			} else if vendor_name, ok := d.ParseEndVendor(arr); ok {
				if _vendor_id, ok := d.VendorId[vendor_name]; !ok {
					return errors.New(fmt.Sprintf("radius: vendor %v is not registered", vendor_name))
				} else if _vendor_id == vendor_id {
					vendor_id = 0
				}
			}
		}
	}
	return nil
}

// get attribute dictionary
func (d *Dictionary) Values(_vendor_id ...uint32) *dictAttr {
	var vendor_id uint32
	if len(_vendor_id) > 0 {
		vendor_id = _vendor_id[0]
	}
	return d.values[vendor_id]
}

// get attribute dictionary
func (d *Dictionary) AttributeByType(t byte, _vendor_id ...uint32) (entry *dictEntry, ok bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if dict := d.Values(_vendor_id...); dict != nil {
		entry = dict.attributesByType[t]
		if entry != nil {
			ok = true
		}
	}
	return
}

// get attribute dictionary
func (d *Dictionary) AttributeByName(name string, _vendor_id ...uint32) (entry *dictEntry, vendor_id uint32, ok bool) {

	if len(_vendor_id) > 0 {
		vendor_id = _vendor_id[0]
	} else {
		vendor_id = d.AttributeVendorId[name]
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if dict := d.Values(vendor_id); dict != nil {
		entry, ok = dict.attributesByName[name]
	}
	return
}

// get vendor id from name
func (d *Dictionary) GetVendorId(v string) uint32 {
	return d.VendorId[v]
}

// get vendor name from id
func (d *Dictionary) GetVendorName(i uint32) string {
	return d.VendorName[i]
}

// switch vendor (obsolete soon)
func (d *Dictionary) SwitchVendor( v string) {
	if d.VendorId[v] != 0 {
		d.Vendor = v
	}
}

func (d *Dictionary) InitObjects() {
	// initialize vendor name to id map if needed
	if d.VendorId == nil {
		d.VendorId = make(map[string]uint32)
	}

	// initialize vendor id to name map if needed
	if d.VendorName == nil {
		d.VendorName = make(map[uint32]string)
	}

	// initialize vendor name to id map if needed
	if d.AttributeVendorId == nil {
		d.AttributeVendorId = make(map[string]uint32)
	}

	// initialize vendor id to attribute dictionary map if needed
	if d.values == nil {
		d.values = make(map[uint32]*dictAttr)
	}

	// init default attribute dictionaries
	d.InitAttributeDictionaries()
}

func (d *Dictionary) InitAttributeDictionaries(_vendor_id ...uint32) {
	var vendor_id uint32
	if len(_vendor_id) > 0 {
		vendor_id = _vendor_id[0]
	}

	// initialize attribute dictionary id (0)
	if d.values[vendor_id] ==  nil {
		d.values[vendor_id]  = &dictAttr{
			attributesByName: make(map[string]*dictEntry),
		}
	}
}

// add vendor id + name mapping
func (d *Dictionary) RegisterVendor(v string, id uint32){

	// 0 reserved for "default" dictionary
	if id <= 0 {
		panic("RegisterVendor ID must > 0")
		return
	}

	if _, ok := d.VendorId[v]; !ok {
			// do mapping
			d.VendorId[v] = id
			d.VendorName[id] = v

			// initialize vendor attribute dictionaries
			d.InitAttributeDictionaries(id)
	}
}

// Register registers the AttributeCodec for the given attribute name and type.
func (d *Dictionary) Register(name string, t byte, codec AttributeCodec, _vendor_id ...uint32) error {
	var vendor_id uint32
	if len(_vendor_id) > 0 {
		vendor_id = _vendor_id[0]
		if vendor_id == 0 {
			return errors.New(fmt.Sprintf("radius: attempting to register non-default attribute %v: %v %v", t, name, codec))
		}
	}
	if _, ok := d.AttributeByType(t, _vendor_id...); !ok {
		entry := &dictEntry{
			Type:  t,
			Name:  name,
			Codec: codec,
		}
		d.AttributeVendorId[name] = vendor_id
		attribute_dictionaries := d.Values(vendor_id)
		attribute_dictionaries.attributesByType[t] = entry
		attribute_dictionaries.attributesByName[name] = entry
		return nil
	}
	return errors.New(fmt.Sprintf("radius: attribute %v: %v already registered for vendor %v", t, name, vendor_id))
}

// MustRegister is a helper for Register that panics if it returns an error.
func (d *Dictionary) MustRegister(name string, t byte, codec AttributeCodec, _vendor_id ...uint32) {
	if err := d.Register(name, t, codec, _vendor_id...); err != nil {
		panic(err)
	}
}

func (d *Dictionary) get(name string, _vendor_id ...uint32) (t byte, codec AttributeCodec, vendor_id uint32, ok bool) {
	if entry, vendor_id2,  _ := d.AttributeByName(name, _vendor_id...); entry != nil {
		t = entry.Type
		codec = entry.Codec
		vendor_id = vendor_id2
		ok = true
	}
	return
}

// Attr returns a new *Attribute whose type is registered under the given
// name.
//
// If name is not registered, nil and an error is returned.
func (d *Dictionary) Attr(name string, value interface{}, _vendor_id ...uint32) (*Attribute, error) {
	t, codec, vendor_id, ok := d.get(name, _vendor_id...)
	if !ok {
		return nil, errors.New("radius: attribute name not registered")
	}
	if transformer, ok := codec.(AttributeTransformer); ok {
		transformed, err := transformer.Transform(value)
		if err != nil {
			return nil, err
		}
		value = transformed
	}
	return &Attribute{
		Type:  t,
		Value: value,
		VendorId: vendor_id,
	}, nil
}
// MustAttr is a helper for Attr that panics if Attr were to return an error.
func (d *Dictionary) MustAttr(name string, value interface{}, _vendor_id ...uint32) *Attribute {
	attr, err := d.Attr(name, value, _vendor_id...)
	if err != nil {
		panic(err)
	}
	return attr
}

// Name returns the registered name for the given attribute type. ok is false
// if the given type is not registered.
func (d *Dictionary) Name(t byte, _vendor_id ...uint32) (name string, ok bool) {
	if entry, _ := d.AttributeByType(t, _vendor_id...); entry != nil {
		name = entry.Name
		ok = true
	}
	return
}

// Type returns the registered type for the given attribute name. ok is false
// if the given name is not registered.
func (d *Dictionary) Type(name string, _vendor_id ...uint32) (t byte, ok bool) {
	if entry, _, _ := d.AttributeByName(name, _vendor_id...); entry != nil {
		t = entry.Type
		ok = true
	}
	return
}

// Codec returns the AttributeCodec for the given registered type. nil is
// returned if the given type is not registered.
func (d *Dictionary) Codec(t byte, _vendor_id ...uint32) AttributeCodec {
	if entry, _ := d.AttributeByType(t, _vendor_id...); entry != nil {
		return entry.Codec
	}
	return AttributeUnknown
}

func (d *Dictionary) SubAttributeEncode(attributes []*Attribute, _vendor_id ...uint32) (vendor_id uint32, data []byte, err error) {
	if len(_vendor_id) > 0 {
		vendor_id = _vendor_id[0]
	}

	var bufferAttrs bytes.Buffer
	for _, attr := range attributes {
		if vendor_id == 0 {
			vendor_id = attr.VendorId
		}
		if vendor_id == 0 || attr.VendorId != vendor_id {
				panic(fmt.Sprintf("radius: vsa attribute error vendor id %v attribute id %v", vendor_id, attr.VendorId))
		}
		codec := d.Codec(attr.Type, vendor_id)
		wire, err2 := codec.Encode(nil, attr.Value)
		if err2 != nil {
			err = err2
			return
		}
		bufferAttrs.WriteByte(attr.Type)
		bufferAttrs.WriteByte(byte(len(wire) + 2))
		bufferAttrs.Write(wire)
	}
	data = bufferAttrs.Bytes()
	return
}

func (d *Dictionary) SubAttributeDecode(vendor_id uint32, data []byte) (attributes []*Attribute) {
	data_length := len(data)
	if data_length < 2 || data_length > 249 {
		return
	}

	n := byte(0)
	for (n+2) < byte(data_length) {
		attribute_id := data[n:n+1][0]
		length := data[n+1:n+2][0]

		if entry, _ := d.AttributeByType(attribute_id, vendor_id); entry != nil {
			val := make([]byte, length - 2)
			copy(val, data[n+2:length+n])
			decoded, err := entry.Codec.Decode(nil, val)

			if err == nil {
				attr := &Attribute {
					Type: attribute_id,
					VendorId: vendor_id,
					Value: decoded,
				}

				attributes = append(attributes, attr)
			}
		}
		n = n + length
	}

	return
}
