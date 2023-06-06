package rawdb

import (
	"github.com/OCAX-labs/rfqrelayer/rfqdb"
	"github.com/OCAX-labs/rfqrelayer/rfqdb/memorydb"
	"github.com/OCAX-labs/rfqrelayer/rfqdb/pebble"
)

const PebbleEnabled = true

type dbLayer struct {
	rfqdb.KeyValueStore
}

// NewPebbleDBDatabase creates a persistent key-value database
func NewPebbleDBDatabase(file string, cache int, handles int, namespace string, readonly bool) (rfqdb.Database, error) {
	db, err := pebble.New(file, cache, handles, namespace, readonly)
	if err != nil {
		return nil, err
	}
	return NewDatabase(db), nil
}

// NewDatabase creates a high level database on top of a given key-value data
// store
func NewDatabase(db rfqdb.KeyValueStore) rfqdb.Database {
	return &dbLayer{KeyValueStore: db}
}

// NewMemoryDatabase creates an ephemeral in-memory key-value database without a
// freezer moving immutable chain segments into cold storage.
func NewMemoryDatabase() rfqdb.Database {
	return NewDatabase(memorydb.New())
}
