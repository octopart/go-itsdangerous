package itsdangerous

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func assert(t *testing.T, actual, expected []byte) {
	if !bytes.Equal(actual, expected) {
		t.Errorf("expecting %s, got %s instead", expected, actual)
	}
}

func TestSignatureSign(t *testing.T) {
	s := NewSignature("secret-key", "", "", "", nil, nil)
	expected := []byte("my string.wh6tMHxLgJqB6oY1uT73iMlyrOA")
	actual, _ := s.Sign([]byte("my string"))
	assert(t, actual, expected)
}

func TestSignatureUnsign(t *testing.T) {
	s := NewSignature("secret-key", "", "", "", nil, nil)
	expected := []byte("my string")
	actual, _ := s.Unsign([]byte("my string.wh6tMHxLgJqB6oY1uT73iMlyrOA"))
	assert(t, actual, expected)
}

func TestTimestampSignatureUnsign(t *testing.T) {
	t.Skip()
	s := NewTimestampSignature("secret-key", "", "", "", nil, nil)
	expected := []byte("my string")
	actual, _ := s.Unsign([]byte("my string.BpSAPw.NnKk1nQ206g1c1aJAS1Nxkt4aug"), 0)
	assert(t, actual, expected)
}

type testCase struct {
	Before  string
	After   string
	IsTimed bool
}

func testSig(t *testing.T, c testCase) {
	s := NewSignature("super secret 1", "cookie-session", ".", "hmac", nil, nil)

	before, err := s.UnsignB64([]byte(c.After))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, []byte(c.Before)) {
		t.Fatalf("before did not match: expected: \n%s \ngot: \n%s", c.Before, before)
	}

	// zlib output differs between go / python
	// so skip cases where After is compressed
	if c.After[0] != '.' {
		after, err := s.SignB64([]byte(c.Before))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, []byte(c.After)) {
			t.Fatalf("after did not match: expected: \n%s \ngot: \n%s", c.After, after)
		}
	}
}

func testTimedSig(t *testing.T, c testCase) {
	s := NewTimestampSignature("super secret 1", "cookie-session", ".", "hmac", nil, nil)

	before, err := s.UnsignB64([]byte(c.After), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, []byte(c.Before)) {
		t.Fatalf("before did not match: expected: \n%s \ngot: \n%s", c.Before, before)
	}

	// zlib output differs between go / python
	// so skip cases where After is compressed
	if c.After[0] != '.' {
		after, err := s.SignB64([]byte(c.Before))
		if err != nil {
			t.Fatal(err)
		}

		a1 := bytes.Split(after, []byte{'.'})[0]
		exp1 := bytes.Split([]byte(c.After), []byte{'.'})[0]
		if !bytes.Equal(a1, exp1) {
			t.Fatalf("after did not match: expected: \n%s \ngot: \n%s", exp1, a1)
		}
	}
}

func TestPythonOutput(t *testing.T) {
	cs := []testCase{}
	f, err := os.Open("testdata/testdata.json")
	if err != nil {
		t.Fatal(err)
	}

	dec := json.NewDecoder(f)
	err = dec.Decode(&cs)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range cs {
		if c.IsTimed {
			testTimedSig(t, c)
		} else {
			testSig(t, c)
		}
	}
}
