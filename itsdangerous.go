/*
Package itsdangerous implements various functions to deal with untrusted sources.
Mainly useful for web applications.

This package exists purely as a port of https://github.com/mitsuhiko/itsdangerous,
where the original version is written in Python.
*/
package itsdangerous

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"io/ioutil"
	"time"
)

func base64Encode(b []byte) []byte {
	dst := make([]byte, base64.URLEncoding.EncodedLen(len(b)))
	base64.URLEncoding.Encode(dst, b)
	for i := len(dst) - 1; i > 0; i-- {
		if dst[i] == '=' {
			dst = dst[:i]
		}
	}
	return dst
}

func ZBase64Encode(b []byte) []byte {

	isCompressed := false
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	zw.Write(b)
	if err := zw.Close(); err == nil {
		cb := zbuf.Bytes()
		if len(cb) < len(b)+1 {
			isCompressed = true
			b = cb
		}
	}

	dst := base64Encode(b)

	if isCompressed {
		dst = append([]byte{'.'}, dst...)
	}
	return dst
}

func base64Decode(b []byte) ([]byte, error) {
	// if leading '.' itsdangerous has compressed this with zlib
	decompress := false
	if b[0] == '.' {
		decompress = true
		b = b[1:]
	}

	for i := 0; i < len(b)%4; i++ {
		b = append(b, '=')
	}

	dst := make([]byte, base64.URLEncoding.DecodedLen(len(b)))
	n, err := base64.URLEncoding.Decode(dst, b)
	if err != nil {
		return nil, err
	}
	dst = dst[:n]

	// if leading '.' decompress now
	if decompress {
		br := bytes.NewReader(dst)
		r, err := zlib.NewReader(br)
		if err != nil {
			return nil, err
		}
		done, err := ioutil.ReadAll(r)
		return done, err
	}

	return dst, nil
}

func getTimestamp() uint32 {
	return uint32(time.Now().Unix())
}
