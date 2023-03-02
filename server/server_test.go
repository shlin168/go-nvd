package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/shlin168/go-nvd/server/testutils"
)

func TestServer(t *testing.T) {
	reg := prometheus.NewRegistry()

	dbMock := &testutils.DBMock{}

	hdl, _ := NewNvdController("v1", dbMock)

	_, err := New(":8080", ":6060")
	assert.Error(t, err)

	s, err := New(":12678", ":0", Controllers(hdl), Registry(reg))
	assert.NoError(t, err)
	assert.NotEmpty(t, s.acsLogger)
	assert.NotEmpty(t, s.errLogger)

	ctx, cancel := context.WithCancel(context.Background())
	go s.Start(ctx)
	defer func() {
		cancel()
		s.FullyStopped()
	}()

	time.Sleep(1 * time.Second)

	rsp, err := http.Get("http://localhost:12678" + APIGroupNVD + "/v1" + APIPathReady)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rsp.StatusCode)

	// further tests for api are written in "github.com/shlin168/go-nvd/client"
}
