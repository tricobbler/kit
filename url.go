package kit

import "strings"

//从网址中提取子域名
func PickUrlSubDomain(url string) string {
	ls := strings.Split(url, ".")
	if IsUrl(url) && len(ls) > 1 {
		for i := 1; i < len(ls); i++ {
			s := strings.Split(ls[i], "/")
			if len(s) > 1 {
				ls[i] = s[0]
				url = strings.Join(ls[:i+1], ".")
				break
			}
		}
		return url
	}
	return ""
}

//从url数组中提取子域名
func PickUrlSubDomains(urls []string) []string {
	var newUrls []string
	for _, v := range urls {
		url := PickUrlSubDomain(v)
		if url != "" {
			newUrls = append(newUrls, url)
		}
	}
	return newUrls
}

//验证url是否是包含http(s)://
func IsUrl(url string) bool {
	if len(url) < 10 {
		return false
	}
	url = strings.ToLower(url)
	prefix := url[:7]
	return prefix == "http://" || prefix == "https:/"
}
