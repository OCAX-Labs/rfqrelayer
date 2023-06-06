package memorydb

import (
	"testing"

	"github.com/OCAX-labs/rfqrelayer/rfqdb"
	"github.com/OCAX-labs/rfqrelayer/rfqdb/dbtest"
)

func TestMemoryDB(t *testing.T) {
	t.Run("DatabaseSuite", func(t *testing.T) {
		dbtest.TestDatabaseSuite(t, func() rfqdb.KeyValueStore {
			return New()
		})
	})
}
