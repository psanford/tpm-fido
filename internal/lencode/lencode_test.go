package lencode

import (
	"bytes"
	"io"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	payload0 := make([]byte, 16)
	for i := 0; i < len(payload0); i++ {
		payload0[i] = 'a'
	}
	if err := enc.Encode(payload0); err != nil {
		t.Fatal(err)
	}

	payload1 := make([]byte, 255)
	for i := 0; i < len(payload1); i++ {
		payload1[i] = 'b'
	}
	if err := enc.Encode(payload1); err != nil {
		t.Fatal(err)
	}

	dec := NewDecoder(&buf)

	n, err := dec.NextLen()
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload0) {
		t.Fatalf("payload0 len mismatch %d vs %d", n, len(payload0))
	}

	got0, err := dec.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got0, payload0) {
		t.Fatalf("Payload0 mismatch %v vs %v", got0, payload0)
	}

	got1, err := dec.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got1, payload1) {
		t.Fatalf("Payload1 mismatch %v vs %v", got1, payload1)
	}

	got2, err := dec.Decode()
	if err != io.EOF {
		t.Fatalf("Expected EOF, got %s %v", err, got2)
	}
}

func TestSeparatorMismatch(t *testing.T) {
	var buf bytes.Buffer

	enc := NewEncoder(&buf, SeparatorOpt(nil))

	payload0 := make([]byte, 16)
	for i := 0; i < len(payload0); i++ {
		payload0[i] = 'a'
	}
	if err := enc.Encode(payload0); err != nil {
		t.Fatal(err)
	}

	r := bytes.NewReader(buf.Bytes())
	dec := NewDecoder(r)

	_, err := dec.Decode()
	if err != separatorMismatchErr {
		t.Fatalf("Expected %s got %s", separatorMismatchErr, err)
	}

	r = bytes.NewReader(buf.Bytes())
	dec = NewDecoder(r, SeparatorOpt(nil))

	got0, err := dec.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got0, payload0) {
		t.Fatalf("Payload0 mismatch %v vs %v", got0, payload0)
	}
}

func TestDecodeUnexpectedEOF(t *testing.T) {
	payload := []byte{0x01}
	r := bytes.NewReader(payload)
	dec := NewDecoder(r, SeparatorOpt(nil))

	_, err := dec.Decode()
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("Short read should trigger UnexpectedEOF error but was %s", err)
	}
}

func TestTooLong(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	payload := bytes.Repeat([]byte{'a'}, 256)

	err := enc.Encode(payload)
	expect := "Message too long to encode length in 1 byte"
	if err.Error() != expect {
		t.Fatalf("Expected too long error, got: %s", err)
	}
}
