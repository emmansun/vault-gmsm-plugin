package pki

import (
	"context"
	"crypto"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/hashicorp/vault/sdk/logical"
)

// meetingToken is a key an appliance holds that finishes a signature only once
// a second one has arrived. Two requests that sign at the same time meet inside
// it; a request that waits for the one beside it never does, and the wait ends
// so that the test fails rather than hangs.
type meetingToken struct {
	key *sm2.PrivateKey

	mu     sync.Mutex
	inside int
	peak   int
	met    chan struct{}
	once   sync.Once
}

func newMeetingToken(key *sm2.PrivateKey) *meetingToken {
	return &meetingToken{key: key, met: make(chan struct{})}
}

func (t *meetingToken) Public() crypto.PublicKey { return &t.key.PublicKey }

func (t *meetingToken) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return t.key.Sign(r, digest, opts)
}

func (t *meetingToken) SignMessage(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.mu.Lock()
	t.inside++
	if t.inside > t.peak {
		t.peak = t.inside
	}
	met := t.inside >= 2
	t.mu.Unlock()

	if met {
		t.once.Do(func() { close(t.met) })
	}

	// A signature waiting for its partner gives up after a while, which turns a
	// mount that serialises its signers into a failure instead of a hang.
	select {
	case <-t.met:
	case <-time.After(5 * time.Second):
	}

	t.mu.Lock()
	t.inside--
	t.mu.Unlock()

	return t.key.SignMessage(r, msg, opts)
}

func (t *meetingToken) Close() error { return nil }

// together is the largest number of signatures that were in flight at once.
func (t *meetingToken) together() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.peak
}

// singleProvider is a provider that holds one key and answers with it whatever
// reference it is asked for.
type singleProvider struct {
	token issuerKey
}

func (p *singleProvider) Signer(_ context.Context, _ string) (issuerKey, error) {
	return p.token, nil
}

// TestSigningHoldsOnlyTheReadLock issues two certificates at once through a key
// that will not finish a signature until a second one has arrived. When signing
// took the write lock the second request never reached the key and the first
// waited for it; with the read lock the two meet, which is what lets the mount
// sign more than one certificate at a time.
func TestSigningHoldsOnlyTheReadLock(t *testing.T) {
	key, bundle := externalAuthority(t, "Concurrent CA")
	token := newMeetingToken(key)
	name := registerProvider(t, &singleProvider{token: token})

	b, storage := newTestBackend(t)
	importExternal(t, b, storage, bundle, name, "authority-1")
	writeWebRole(t, b, storage)

	// Both requests start together: what matters is what happens while both are
	// signing, not which of them the scheduler runs first.
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, commonName := range []string{"one.example.com", "two.example.com"} {
		wg.Add(1)
		go func(commonName string) {
			defer wg.Done()
			<-start

			resp, err := request(t, b, storage, logical.UpdateOperation, "issue/web", map[string]interface{}{
				"common_name": commonName,
			})
			if err != nil {
				t.Errorf("issuing %s failed: %v", commonName, err)
				return
			}
			if resp == nil || resp.IsError() {
				t.Errorf("issuing %s answered %v", commonName, resp)
			}
		}(commonName)
	}
	close(start)
	wg.Wait()

	if got := token.together(); got < 2 {
		t.Fatalf("%d signatures were in flight at once, so one request waited for the other", got)
	}
}
