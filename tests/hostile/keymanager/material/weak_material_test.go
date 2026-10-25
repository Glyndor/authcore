package material

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// weakSecrets are 32-byte values no random generator produces in practice.
func weakSecrets() map[string][]byte {
	up := make([]byte, 32)
	down := make([]byte, 32)
	offset := make([]byte, 32)
	few := make([]byte, 32)
	for i := range up {
		up[i] = byte(i)
		down[i] = byte(31 - i)
		offset[i] = byte(0x80 + i)
		few[i] = byte(i*7%9) + 1
	}
	return map[string][]byte{
		"zeros":      bytes.Repeat([]byte{0}, 32),
		"ones":       bytes.Repeat([]byte{0xff}, 32),
		"repeated":   bytes.Repeat([]byte{0xab}, 32),
		"block of 2": bytes.Repeat([]byte{0x12, 0x34}, 16),
		"block of 4": bytes.Repeat([]byte{0x12, 0x34, 0x56, 0x78}, 8),
		"ascending":  up,
		"descending": down,
		"offset run": offset,
		"few values": few,
	}
}

func TestHostile_WeakRefreshSecretIsRefused(t *testing.T) {
	for name, secret := range weakSecrets() {
		t.Run(name, func(t *testing.T) {
			hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
				sb := hostiletest.NewSandbox(t)
				s := hostiletest.NewSet(t)
				dir := sb.WithSet(t, s)
				hostiletest.Put(t, filepath.Join(dir, layout.FileRefreshSecret), []byte(hex.EncodeToString(secret)+"\n"), 0o600)
				hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly), s)
			})
		})
	}
}

func TestHostile_WeakSigningSeedIsRefused(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		sb := hostiletest.NewSandbox(t)
		s := hostiletest.NewSet(t)
		dir := sb.WithSet(t, s)
		priv := ed25519.NewKeyFromSeed(make([]byte, 32))
		privPEM, _ := pemcodec.EncodePrivateKeyPEM(priv)
		pubPEM, _ := pemcodec.EncodePublicKeyPEM(priv.Public().(ed25519.PublicKey))
		hostiletest.Put(t, filepath.Join(dir, layout.FilePrivateKey), privPEM, 0o600)
		hostiletest.Put(t, filepath.Join(dir, layout.FilePublicKey), pubPEM, 0o644)
		hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly), s)
	})
}
