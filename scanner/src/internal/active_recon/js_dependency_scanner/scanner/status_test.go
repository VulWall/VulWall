package scanner

import (
	"errors"
	"net/http"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
)

func TestStatusErrorOnlyNotFoundIsDefinite(t *testing.T) {
	for code, gone := range map[int]bool{404: true, 410: true, 403: false, 429: false, 500: false, 503: false} {
		err := statusError(&http.Response{StatusCode: code, Status: http.StatusText(code)})
		if errors.Is(err, shared.ErrGone) != gone {
			t.Errorf("HTTP %d: ErrGone = %v, want %v", code, !gone, gone)
		}
		if (shared.ProbeError(err) == nil) != gone {
			t.Errorf("HTTP %d: complete = %v, want %v", code, !gone, gone)
		}
	}
}
