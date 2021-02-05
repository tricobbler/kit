package kit

import (
	"reflect"
	"testing"
)

func TestPickUrlSubDomain(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "从网址中提取子域名",
			args: args{
				url: "http://www.xxx.com/xxx",
			},
			want: "http://www.xxx.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PickUrlSubDomain(tt.args.url); got != tt.want {
				t.Errorf("PickUrlSubDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPickUrlsSubDomains(t *testing.T) {
	type args struct {
		urls []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "从url数组中提取子域名",
			args: args{
				urls: []string{"http://www.xxx.com/xxx", "http://www.xxx.cn/xxx"},
			},
			want: []string{"http://www.xxx.com", "http://www.xxx.cn"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PickUrlsSubDomains(tt.args.urls); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PickUrlsSubDomains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsUrl(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "验证url http",
			args: args{
				url: "http://www.xxx.com",
			},
			want: true,
		},
		{
			name: "验证url https",
			args: args{
				url: "https://www.xxx.com",
			},
			want: true,
		},
		{
			name: "验证url 非url",
			args: args{
				url: "www.xxx.com",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsUrl(tt.args.url); got != tt.want {
				t.Errorf("IsUrl() = %v, want %v", got, tt.want)
			}
		})
	}
}
