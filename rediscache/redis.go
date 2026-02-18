package rediscache

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/gomodule/redigo/redis"
)

const RedisCertPrefix = "letsencrypt:cert:"

type RedisCertCache struct {
	Pool         *redis.Pool
	CacheTimeout time.Duration
	KeyPrefix    string
}

type certCacheEntry struct {
	Certificate []byte
	PrivateKey  []byte
}

func (r *RedisCertCache) GetCertificate(key string) ([]byte, []byte, error) {
	conn := r.Pool.Get()
	defer conn.Close()
	data, err := redis.Bytes(conn.Do("GET", r.KeyPrefix+key))
	if err != nil {
		return nil, nil, err
	}
	var entry certCacheEntry
	if err = json.Unmarshal(data, &entry); err != nil {
		return nil, nil, err
	}
	return entry.Certificate, entry.PrivateKey, nil
}

func (r *RedisCertCache) SetCertificate(key string, cert []byte, keyBytes []byte) error {
	conn := r.Pool.Get()
	defer conn.Close()
	key = r.KeyPrefix + key
	entry := certCacheEntry{Certificate: cert, PrivateKey: keyBytes}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if r.CacheTimeout <= 0 {
		_, err = conn.Do("SET", key, data)
	} else {
		_, err = conn.Do("SET", key, data, "EX", int(r.CacheTimeout.Seconds()))
	}
	return err
}

// GetUserJSON retrieves the JSON for a LegoUser from disk. If the user file does not exist, it returns (nil, nil).
func (r *RedisCertCache) GetUserJSON(key string) ([]byte, error) {
	conn := r.Pool.Get()
	defer conn.Close()
	data, err := redis.Bytes(conn.Do("GET", r.KeyPrefix+key+"_user"))
	if errors.Is(err, redis.ErrNil) {
		// key not found
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (r *RedisCertCache) SetUserJSON(key string, data []byte) error {
	var err error
	conn := r.Pool.Get()
	defer conn.Close()
	key = r.KeyPrefix + key
	if r.CacheTimeout <= 0 {
		_, err = conn.Do("SET", key+"_user", data)
	} else {
		_, err = conn.Do("SET", key+"_user", data, "EX", int(r.CacheTimeout.Seconds()))
	}
	return err
}
