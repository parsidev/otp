package cache

import (
	goconcurrency "github.com/parsidev/go-concurrency"
)

var (
	cache goconcurrency.ConcurrentMap[string, uint64]
)

func Init() {
	cache = goconcurrency.NewMapNullableSort[string, uint64]()
}

func Set(key string, val uint64) {
	if cache.Length() == 0 {
		Init()
	}
	cache.Set(key, val)
}

func Get(key string) uint64 {
	if cache.Length() == 0 {
		return 0
	}

	val, ok := cache.Get(key)

	if !ok {
		return 0
	}

	return val
}
