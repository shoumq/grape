package handler

import "errors"

func normalizeRUPhone(input string) (string, error) {
	digits := make([]byte, 0, len(input))
	for i := 0; i < len(input); i++ {
		ch := input[i]
		if ch >= '0' && ch <= '9' {
			digits = append(digits, ch)
		}
	}
	switch len(digits) {
	case 10:
		digits = append([]byte{'7'}, digits...)
	case 11:
		if digits[0] == '8' {
			digits[0] = '7'
		} else if digits[0] != '7' {
			return "", errors.New("unsupported country code")
		}
	default:
		return "", errors.New("invalid length")
	}
	return "+" + string(digits), nil
}
