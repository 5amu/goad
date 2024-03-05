package mstypes

import (
	"encoding/binary"
	"fmt"
	"reflect"
)

func next(b []byte, pattern []byte) int {
	for i := len(pattern); i < len(b); i++ {
		var ok bool = false
		for j := 0; j < len(pattern); j++ {
			if b[i-len(pattern)+j] == pattern[j] {
				if j == 0 {
					ok = true
				}
				ok = ok && true
			} else {
				ok = false
			}
		}
		if ok {
			return i - len(pattern)
		}
	}
	return 0
}

func UnmarshalBinary(s any, d []byte) error {
	t := reflect.TypeOf(s)
	v := reflect.ValueOf(s)

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("==> panic recovered: ", r)
		}
	}()

	if t.Kind() == reflect.Ptr {
		t = t.Elem()
		v = v.Elem()
	}

	var offset int = 0
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		ft := t.Field(i)

		switch ft.Type.Kind() {
		case reflect.Uint16:
			f.Set(reflect.ValueOf(binary.LittleEndian.Uint16(d[offset : offset+2])))
			offset += 2
		case reflect.Uint32:
			f.Set(reflect.ValueOf(binary.LittleEndian.Uint32(d[offset : offset+4])))
			offset += 4
		case reflect.Uint64:
			f.Set(reflect.ValueOf(binary.LittleEndian.Uint64(d[offset : offset+8])))
			offset += 8
		case reflect.Slice:
			delim, ok := ft.Tag.Lookup("delimiter")
			if ok {
				switch delim {
				case "16bitnull":
					end := next(d[offset:], []byte{0, 0})
					f.Set(reflect.ValueOf(d[offset : offset+end]))
					offset = offset + end
				default:
				}
			}
			padding, ok := ft.Tag.Lookup("padding")
			if ok {
				switch padding {
				case "null":
					var stop bool = false
					var end int
					for !stop {
						tmp := next(d[offset+end:], []byte{0})
						if tmp != 0 && tmp == end+1 {
							end = tmp
						} else {
							stop = true
						}
					}
					f.Set(reflect.ValueOf(d[offset : offset+end]))
					offset = offset + end
				default:
				}
			}
		}
	}
	return nil
}
