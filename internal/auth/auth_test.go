package auth

import (
	
	"errors"
	"net/http"
	"testing"
	"github.com/google/go-cmp/cmp"
	
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers http.Header
		want    string
		error   error
	}{
		"no authorization header": {
			headers: http.Header{},
			want:    "",
			error:   ErrNoAuthHeaderIncluded,
		},
		"malformed authorization header - missing ApiKey prefix": {
			headers: http.Header{"Authorization": []string{"Bearer abc123"}},
			want:    "",
			error:   errors.New("malformed authorization header"),
		},
		"malformed authorization header - missing API key": {
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			want:    "",
			error:   errors.New("malformed authorization header"),
		},
		"valid authorization header": {
			headers: http.Header{"Authorization": []string{"ApiKey abc123"}},
			want:    "abc123",
			error:   nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.headers)

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("unexpected API key (-want +got):\n%s", diff)
			}

			if !errors.Is(err, tc.error) {
				t.Errorf("expected error %v, got %v", tc.error, err)
			}
		})
	}
}
