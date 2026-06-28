package storee2e

import (
	"testing"

	"lds.li/session"
	"lds.li/session/kvtest"
)

func TestMemoryKV_E2E(t *testing.T) {
	kv := session.NewMemoryKV()

	kvtest.RunComplianceTest(t, kv, nil)
}
