package jwthelper

import (
	"fmt"
	"sync"
)

type MultipleKeysSigner struct {
	m       sync.Mutex
	signers map[string]*Signer
}

var (
	ErrInvalidMultipleKeysSigner = fmt.Errorf("invalid multiple keys signer")
	ErrSignerNotFound            = fmt.Errorf("signer not found by given kid(key id)")
)

func NewMultipleKeysSigner() *MultipleKeysSigner {
	return &MultipleKeysSigner{
		m:       sync.Mutex{},
		signers: map[string]*Signer{},
	}
}

func (s *MultipleKeysSigner) Set(kid string, signer *Signer) {
	s.m.Lock()
	defer s.m.Unlock()
	s.signers[kid] = signer
}

func (s *MultipleKeysSigner) Get(kid string) *Signer {
	s.m.Lock()
	defer s.m.Unlock()
	signer := s.signers[kid]

	return signer
}

func (s *MultipleKeysSigner) Valid() bool {
	if s.signers == nil {
		return false
	}
	return true
}

func (s *MultipleKeysSigner) SignedString(kid string, claims ...Claim) (string, error) {
	if !s.Valid() {
		return "", ErrInvalidMultipleKeysSigner
	}

	signer := s.Get(kid)
	if signer == nil {
		return "", ErrSignerNotFound
	}

	claims = append(claims, NewClaim("kid", kid))
	return signer.SignedString(claims...)
}
