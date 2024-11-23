package auth

import (
	"net/http"
	"testing"
	"errors"
)

func TestGetAPIKey(t *testing.T) {
	cases := []struct {
		name    string
		headers http.Header
		expected string
		err     error
	}{
		{
			name:    "No Authorization Header",
			headers: http.Header{},
			expected: "",
			err:     ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Malformed Authorization Header",
			headers: http.Header{"Authorization": []string{"MalformedHeader"}},
			expected: "",
			err:     errors.New("malformed authorization header"),
		},
		{
			name:    "Correct Authorization Header",
			headers: http.Header{"Authorization": []string{"ApiKey 123456789"}},
			expected: "123456789",
			err:     nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(c.headers)

			if apiKey != c.expected {
				t.Errorf("expected %v, got %v", c.expected, apiKey)
			}

			if err != nil && c.err == nil || err == nil && c.err != nil {
				t.Errorf("expected error %v, got %v", c.err, err)
			}

			if err != nil && c.err != nil && err.Error() != c.err.Error() {
				t.Errorf("expected error message %v, got %v", c.err.Error(), err.Error())
			}
		})
	}
} 
