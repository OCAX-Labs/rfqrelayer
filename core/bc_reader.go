package core

// // GetBody retrieves a block body (transactions and uncles) from the database by
// // hash, caching it if found.
// func (bc *Blockchain) GetBody(hash common.Hash) *types.Body {
// 	// Short circuit if the body's already in the cache, retrieve otherwise
// 	if cached, ok := bc.bodyCache.Get(hash); ok {
// 		return cached
// 	}
// 	number := bc.dbGetBlockNumber(hash)
// 	if number == nil {
// 		return nil
// 	}
// 	body := rawdb.ReadBody(bc.db, hash, *number)
// 	if body == nil {
// 		return nil
// 	}
// 	// Cache the found body for next time and return
// 	bc.bodyCache.Add(hash, body)
// 	return body
// }
