package rawdb

import (
	"github.com/OCAX-labs/rfqrelayer/db"
	"github.com/OCAX-labs/rfqrelayer/db/pebble"
)

const PebbleEnabled = true

type dbLayer struct {
	db.KeyValueStore
}

// NewPebbleDBDatabase creates a persistent key-value database
func NewPebbleDBDatabase(file string, cache int, handles int, namespace string, readonly bool) (db.Database, error) {
	db, err := pebble.New(file, cache, handles, namespace, readonly)
	if err != nil {
		return nil, err
	}
	return NewDatabase(db), nil
}

// NewDatabase creates a high level database on top of a given key-value data
// store
func NewDatabase(db db.KeyValueStore) db.Database {
	return &dbLayer{KeyValueStore: db}
}
