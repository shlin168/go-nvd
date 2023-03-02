package utils

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/go-getter/v2"
)

var (
	DefaultTimeout = 30 * time.Second
	DefaultRetries = 0
	DefaultBackoff = 3 * time.Second

	pwd, _ = os.Getwd()
)

// Getter utilize go-getter package to download the files (only support download file so far)
type Getter struct {
	timeout  time.Duration
	retryMax int
	backoff  time.Duration
	client   getter.Client
}

type ClientOption func(*Getter) error

func Timeout(timeout time.Duration) ClientOption {
	return func(gc *Getter) error {
		if timeout <= 0 {
			return fmt.Errorf("invalid timeout: %v", timeout)
		}
		gc.timeout = timeout
		return nil
	}
}

func Backoff(backoff time.Duration) ClientOption {
	return func(gc *Getter) error {
		if backoff <= 0 {
			return fmt.Errorf("invalid backoff: %v", backoff)
		}
		gc.backoff = backoff
		return nil
	}
}

func Retries(times int) ClientOption {
	return func(gc *Getter) error {
		if times < 0 {
			return fmt.Errorf("invalid retries: %v", times)
		}
		gc.retryMax = times
		return nil
	}
}

// NewGetter initializes Getter client, default only http getter
func NewGetter(opts ...ClientOption) (*Getter, error) {
	gc := &Getter{
		timeout:  DefaultTimeout,
		retryMax: DefaultRetries,
		backoff:  DefaultBackoff,
		client:   *getter.DefaultClient,
	}

	for _, opt := range opts {
		if err := opt(gc); err != nil {
			return nil, err
		}
	}

	// change default getter to http, s3
	httpGetter := &getter.HttpGetter{
		Client:                http.DefaultClient, // to avoid data race since (HttpGetter).Get(...) set Client with default value
		Netrc:                 true,
		XTerraformGetDisabled: true,
		HeadFirstTimeout:      10 * time.Second,
		ReadTimeout:           gc.timeout,
	}

	gc.client.Getters = []getter.Getter{httpGetter}
	gc.client.Decompressors = getter.Decompressors // to avoid data race since (getter.Client).Get(...) set member in getter.Client with default value

	return gc, nil
}

func (gc Getter) Get(ctx context.Context, src, dst string) error {
	req := &getter.Request{
		Src:     src,
		Dst:     dst,
		Pwd:     pwd,
		GetMode: getter.ModeFile,
	}
	var tryTimes int
	var err error
	for tryTimes <= gc.retryMax {
		if _, err = gc.client.Get(ctx, req); err == nil {
			break
		}
		tryTimes += 1
		time.Sleep(gc.backoff)
	}
	if err != nil {
		return fmt.Errorf("get err: %w after %d retries", err, gc.retryMax)
	}
	return nil
}
