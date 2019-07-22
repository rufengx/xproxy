package utils

import (
	"github.com/spaolacci/murmur3"
)

func Murmur3hash(str string, maxval int) int {
	hash := murmur3.New64()
	hash.Write([]byte(str))
	value64 := hash.Sum64()

	return int(value64 % uint64(maxval))
}
