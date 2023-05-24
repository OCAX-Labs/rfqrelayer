package common

import (
	"fmt"
	"reflect"
)

type List[T any] struct {
	Data []T
}

func (l *List[T]) Delete(index int) {
	if index > len(l.Data)-1 {
		panic("cannot delete an element at an index higher than the length of the list")
	}
	if index < 0 {
		panic("cannot delete an element at a negative index")
	}
	l.Data = append(l.Data[:index], l.Data[index+1:]...)
}

func (l *List[T]) Len() int {
	return len(l.Data)
}

func NewList[T any]() *List[T] {
	return &List[T]{
		Data: []T{},
	}
}

func (l *List[T]) Get(index int) T {
	// Get returns the element at the given index of the list.
	// The index must be less than the length of the list.
	if index > len(l.Data)-1 {
		err := fmt.Sprintf("the given index (%d) is higher than the length (%d)", index, len(l.Data))
		panic(err)
	}
	return l.Data[index]
}

func (l *List[T]) Insert(v T) {
	l.Data = append(l.Data, v)
}

func (l *List[T]) Clear() {
	l.Data = []T{}
}

// GetIndex will return the index of item. If the item is not found,
// -1 will be returned.
func (l *List[T]) GetIndex(item T) int {
	for i := 0; i < l.Len(); i++ {
		if reflect.DeepEqual(item, l.Data[i]) {
			return i
		}
	}
	return -1
}

func (l *List[T]) Remove(item T) {
	index := l.GetIndex(item)
	if index == -1 {
		return
	}
	l.Pop(index)
}

func (l *List[T]) Pop(index int) {
	l.Data = append(l.Data[:index], l.Data[index+1:]...)
}

// This function checks whether the list contains the given item.
// It loops through all the items in the list and checks if the item
// is the same as the given item.

func (l *List[T]) Contains(item T) bool {
	for i := 0; i < len(l.Data); i++ {
		if reflect.DeepEqual(l.Data[i], item) {
			return true
		}
	}
	return false
}

func (l List[T]) Last() T {
	return l.Data[l.Len()-1]
}
