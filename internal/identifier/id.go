package identifier

import (
	"crypto/rand"
	"encoding/hex"
)

func New(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("domainops: secure random source unavailable: " + err.Error())
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
