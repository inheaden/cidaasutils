package cidaasutils

func includesStrings(input []string, search []string) bool {
	for _, s := range search {
		if !includesString(input, s) {
			return false
		}
	}
	return true
}

func includesString(input []string, search string) bool {
	for _, i := range input {
		if i == search {
			return true
		}
	}
	return false
}
