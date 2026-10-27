package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"testing/synctest"
	"time"
)

type contextBody struct{ ctx context.Context }

func (b contextBody) Read([]byte) (int, error) { <-b.ctx.Done(); return 0, b.ctx.Err() }
func (contextBody) Close() error               { return nil }

func TestGetContextEndDoesNotCountAsProviderFailure(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%v", deadline), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				want := context.Canceled
				if deadline {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), time.Second)
					want = context.DeadlineExceeded
				}
				defer cancel()
				h := &http.Client{Transport: memoryTransport(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Body: contextBody{r.Context()}}, nil
				})}
				failed := 0
				done := make(chan error, 1)
				go func() {
					_, err := Get(ctx, h, "https://keys.example/jwks", errFetch, func() { failed++ })
					done <- err
				}()
				synctest.Wait()
				if deadline {
					time.Sleep(time.Second)
				} else {
					cancel()
				}
				err := <-done
				if !errors.Is(err, want) || errors.Is(err, errFetch) || failed != 0 {
					t.Fatalf("Get = %v, failures=%d; want context error and no failed attempt", err, failed)
				}
			})
		})
	}
}

func TestGetClientTimeoutCountsAsProviderFailure(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(fmt.Sprintf("body=%v", body), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := &http.Client{Timeout: time.Second, Transport: memoryTransport(func(r *http.Request) (*http.Response, error) {
					if body {
						return &http.Response{StatusCode: 200, Body: contextBody{r.Context()}}, nil
					}
					<-r.Context().Done()
					return nil, r.Context().Err()
				})}
				failed := 0
				_, err := Get(context.Background(), h, "https://keys.example/jwks", errFetch, func() { failed++ })
				if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, errFetch) || failed != 1 {
					t.Fatalf("Get = %v, failures=%d; want provider timeout and one failed attempt", err, failed)
				}
			})
		})
	}
}

func TestGetReadFailureCountsAsProviderFailure(t *testing.T) {
	h := &http.Client{Transport: memoryTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: readFailure{}}, nil
	})}
	failed := 0
	_, err := Get(context.Background(), h, "https://keys.example/jwks", errFetch, func() { failed++ })
	if !errors.Is(err, errFetch) || !errors.Is(err, io.ErrUnexpectedEOF) || failed != 1 {
		t.Fatalf("Get = %v, failures=%d; want read failure and one failed attempt", err, failed)
	}
}

type readFailure struct{}

func (readFailure) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (readFailure) Close() error             { return nil }
