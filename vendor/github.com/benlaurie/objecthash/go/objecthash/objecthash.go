package objecthash

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
)

const hashLength int = sha256.Size

func hash(t string, b []byte) [hashLength]byte {
	h := sha256.New()
	h.Write([]byte(t))
	h.Write(b)

	var r [hashLength]byte
	copy(r[:], h.Sum(nil))
	return r
}

// Set represents an unordered, unduplicated list of objects.
// FIXME: if What You Hash Is What You Get, then this needs to be safe
// to use as a set.  Note: not actually safe to use as a set
type Set []interface{}

type sortableHashes [][hashLength]byte

func (h sortableHashes) Len() int           { return len(h) }
func (h sortableHashes) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h sortableHashes) Less(i, j int) bool { return bytes.Compare(h[i][:], h[j][:]) < 0 }

func hashSet(s Set) ([hashLength]byte, error) {
	h := make([][hashLength]byte, len(s))
	for n, e := range s {
		hn, err := ObjectHash(e)
		if err != nil {
			return [hashLength]byte{}, err
		}
		h[n] = hn
	}

	sort.Sort(sortableHashes(h))
	b := new(bytes.Buffer)
	var prev [hashLength]byte
	for _, hh := range h {
		if hh != prev {
			b.Write(hh[:])
		}
		prev = hh
	}
	return hash(`s`, b.Bytes()), nil
}

func hashList(l []interface{}) ([hashLength]byte, error) {
	h := new(bytes.Buffer)
	for _, o := range l {
		b, err := ObjectHash(o)
		if err != nil {
			return [hashLength]byte{}, err
		}
		h.Write(b[:])
	}
	return hash(`l`, h.Bytes()), nil
}

func hashUnicode(s string) [hashLength]byte {
	//return hash(`u`, norm.NFC.Bytes([]byte(s)))
	return hash(`u`, []byte(s))
}

type hashEntry struct {
	khash [hashLength]byte
	vhash [hashLength]byte
}
type byKHash []hashEntry

func (h byKHash) Len() int      { return len(h) }
func (h byKHash) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h byKHash) Less(i, j int) bool {
	return bytes.Compare(h[i].khash[:],
		h[j].khash[:]) < 0
}

func hashDict(d map[string]interface{}) ([hashLength]byte, error) {
	e := make([]hashEntry, len(d))
	n := 0
	for k, v := range d {
		khash, err := ObjectHash(k)
		if err != nil {
			return [hashLength]byte{}, err
		}
		e[n].khash = khash

		vhash, err := ObjectHash(v)
		if err != nil {
			return [hashLength]byte{}, err
		}
		e[n].vhash = vhash

		n++
	}
	sort.Sort(byKHash(e))
	h := new(bytes.Buffer)
	for _, ee := range e {
		h.Write(ee.khash[:])
		h.Write(ee.vhash[:])
	}
	return hash(`d`, h.Bytes()), nil
}

func floatNormalize(originalFloat float64) (s string, err error) {
	// sign
	f := originalFloat
	s = `+`
	if f < 0 {
		s = `-`
		f = -f
	}
	// exponent
	e := 0
	for f > 1 {
		f /= 2
		e++
	}
	for f <= .5 {
		f *= 2
		e--
	}
	s += fmt.Sprintf("%d:", e)
	// mantissa
	if f > 1 || f <= .5 {
		return "", fmt.Errorf("Could not normalize float: %f", originalFloat)
	}
	for f != 0 {
		if f >= 1 {
			s += `1`
			f--
		} else {
			s += `0`
		}
		if f >= 1 {
			return "", fmt.Errorf("Could not normalize float: %f", originalFloat)
		}
		if len(s) >= 1000 {
			return "", fmt.Errorf("Could not normalize float: %f", originalFloat)
		}
		f *= 2
	}
	return
}

func hashFloat(f float64) ([hashLength]byte, error) {
	normalizedFloat, err := floatNormalize(f)
	if err != nil {
		return [hashLength]byte{}, err
	}
	return hash(`f`, []byte(normalizedFloat)), nil
}

func hashInt(i int) [hashLength]byte {
	return hash(`i`, []byte(fmt.Sprintf("%d", i)))
}

func hashBool(b bool) [hashLength]byte {
	bb := []byte(`0`)
	if b {
		bb = []byte(`1`)
	}
	return hash(`b`, bb)
}

// ObjectHash returns the hash of a subset of allowed Go objects.
func ObjectHash(o interface{}) ([hashLength]byte, error) {
	switch v := o.(type) {
	case []interface{}:
		return hashList(v)
	case string:
		return hashUnicode(v), nil
	case map[string]interface{}:
		return hashDict(v)
	case float64:
		return hashFloat(v)
	case nil:
		return hash(`n`, []byte(``)), nil
	case int:
		return hashInt(v), nil
	case Set:
		return hashSet(v)
	case bool:
		return hashBool(v), nil
	default:
		return [hashLength]byte{}, fmt.Errorf("Unsupported type: %T", o)
	}
}

// CommonJSONHash computes the ObjectHash of a Common JSON object.
func CommonJSONHash(j string) ([hashLength]byte, error) {
	var f interface{}
	if err := json.Unmarshal([]byte(j), &f); err != nil {
		return [hashLength]byte{}, err
	}
	return ObjectHash(f)
}

// Convert an object to the Common JSON equivalent
func CommonJSONify(o interface{}) (interface{}, error) {
	j, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}

	var c interface{}
	err = json.Unmarshal([]byte(j), &c)
	if err != nil {
		return nil, err
	}

	return c, nil
}
