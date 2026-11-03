package sandbox

import "crypto/rand"

func randRead(p []byte) (int, error) { return rand.Read(p) }
