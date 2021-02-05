package kit

//string数组去重
func RemoveSliceDuplicate(s []string) []string {
	var newS []string
	mu := make(map[string]int)
	for _, v := range s {
		if _, has := mu[v]; !has {
			mu[v] = 0
			newS = append(newS, v)
		}
	}
	return newS
}
