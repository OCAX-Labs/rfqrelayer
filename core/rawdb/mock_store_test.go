package rawdb

import "errors"

type MockStore struct {
	data map[string][]byte
}

// NewMockStore creates a new mock key-value store.
func NewMockStore() *MockStore {
	return &MockStore{
		data: make(map[string][]byte),
	}
}

// Get retrieves the value for a key.
func (s *MockStore) Get(key []byte) ([]byte, error) {
	value, ok := s.data[string(key)]
	if !ok {
		return nil, errors.New("key not found")
	}
	return value, nil
}

// Put sets the value for a key.
func (s *MockStore) Put(key []byte, value []byte) error {
	s.data[string(key)] = value
	return nil
}

// Delete removes a key from the store.
func (s *MockStore) Delete(key []byte) error {
	delete(s.data, string(key))
	return nil
}
