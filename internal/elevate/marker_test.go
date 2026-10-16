package elevate

import (
	"reflect"
	"slices"
	"testing"
)

func TestStripMarker(t *testing.T) {
	tests := []struct {
		name     string
		in       []string
		want     []string
		wantFind bool
	}{
		{
			name: "no marker",
			in:   []string{"obl.exe", "--enable-collect"},
			want: []string{"obl.exe", "--enable-collect"},
		},
		{
			name:     "marker appended by relaunch",
			in:       []string{"obl.exe", "--enable-collect", MarkerArg},
			want:     []string{"obl.exe", "--enable-collect"},
			wantFind: true,
		},
		{
			name:     "marker in the middle",
			in:       []string{"obl.exe", MarkerArg, "--enable-collect"},
			want:     []string{"obl.exe", "--enable-collect"},
			wantFind: true,
		},
		{
			name:     "only the marker",
			in:       []string{MarkerArg},
			want:     []string{},
			wantFind: true,
		},
		{
			name: "empty",
			in:   []string{},
			want: []string{},
		},
		{
			name:     "duplicate markers are all removed",
			in:       []string{"obl.exe", MarkerArg, MarkerArg},
			want:     []string{"obl.exe"},
			wantFind: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Copy so we can assert the input slice is never mutated.
			before := slices.Clone(tt.in)
			got, found := StripMarker(tt.in)
			if found != tt.wantFind {
				t.Errorf("found = %v, want %v", found, tt.wantFind)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("clean = %q, want %q", got, tt.want)
			}
			if !reflect.DeepEqual(tt.in, before) {
				t.Errorf("input mutated: %q, want %q", tt.in, before)
			}
		})
	}
}
