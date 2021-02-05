package kit

import (
	"reflect"
	"testing"
)

func TestRemoveSliceDuplicate(t *testing.T) {
	type args struct {
		s []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "数组切片去重",
			args: args{
				s: []string{"a", "b", "b"},
			},
			want: []string{"a", "b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RemoveSliceDuplicate(tt.args.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RemoveSliceDuplicate() = %v, want %v", got, tt.want)
			}
		})
	}
}
