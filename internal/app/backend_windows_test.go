//go:build windows

package app

import (
	"errors"
	"testing"
)

func TestIsRetryableDriverReinstallError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "service marked for deletion text",
			err:  errors.New("command failed: exit status 1072"),
			want: true,
		},
		{
			name: "explicit marked for deletion message",
			err:  errors.New("CreateService failed: service marked for deletion"),
			want: true,
		},
		{
			name: "different exit code",
			err:  errors.New("command failed: exit status 5"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRetryableDriverReinstallError(tt.err); got != tt.want {
				t.Fatalf("isRetryableDriverReinstallError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
