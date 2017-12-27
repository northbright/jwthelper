package jwthelper

import (
	"io/ioutil"

	"github.com/northbright/pathhelper"
)

// ReadKey reads the key file on disk into a buffer.
func ReadKey(keyFile string) ([]byte, error) {
	var buf []byte

	// Make Abs key file path with current executable path if KeyFilePath is relative.
	p, err := pathhelper.GetAbsPath(keyFile)
	if err != nil {
		return []byte{}, err
	}

	if buf, err = ioutil.ReadFile(p); err != nil {
		return []byte{}, err
	}

	return buf, nil
}
