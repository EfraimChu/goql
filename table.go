package goql

import (
	"fmt"
	"strings"
	"sync"

	"goql/astdata"
)

// ValueType is an enum contain supported value type in system
type ValueType int

// String is the string type, like function name, file name and ...
type String struct {
	String string
	Null   bool
}

// Get return the actual value (and nil)
func (s String) Get() interface{} {
	if s.Null {
		return nil
	}

	return s.String
}

// Number is the number, only float64 is supported
type Number struct {
	Number float64
	Null   bool
}

// Get return the actual value (and nil)
func (n Number) Get() interface{} {
	if n.Null {
		return nil
	}

	return n.Number
}

// Bool is the boolean type
type Bool struct {
	Bool bool
	Null bool
}

// Get return the actual value (and nil)
func (b Bool) Get() interface{} {
	if b.Null {
		return nil
	}

	return b.Bool
}

// Definition is the type to handle type definition
type Definition struct {
	Definition astdata.Definition
}

// Get return the actual definition
func (d Definition) Get() interface{} {
	// since its an interface so it could be nil
	return d.Definition
}

const (
	// ValueTypeString is the string type
	ValueTypeString ValueType = iota
	// ValueTypeNumber is the number type
	ValueTypeNumber
	// ValueTypeBool is the bool type
	ValueTypeBool
	// ValueTypeDefinition is a definition special type
	ValueTypeDefinition
)

var (
	tables = make(map[string]*table)
	lock   = &sync.Mutex{}
)

// Getter is replacement to prevent using the interface{} it is used when the value is required
type Getter interface {
	Get() interface{}
}

// StringValuer is provider for a value for a table
type StringValuer interface {
	Value(interface{}) String
}

// NumberValuer is the number valuer (float64 is supported only )
type NumberValuer interface {
	Value(interface{}) Number
}

// BoolValuer is the Boolean valuer
type BoolValuer interface {
	Value(interface{}) Bool
}

// DefinitionValuer is used to handle definition column
type DefinitionValuer interface {
	Value(interface{}) Definition
}

// columnDef is the helper for column definition
type columnDef struct {
	name  string
	typ   interface{}
	order int
}

// Order return order of registration
func (c columnDef) Order() int {
	return c.order
}

// Type return the type of value of column
func (c columnDef) Type() ValueType {
	switch c.typ.(type) {
	case StringValuer:
		return ValueTypeString
	case NumberValuer:
		return ValueTypeNumber
	case BoolValuer:
		return ValueTypeBool
	case DefinitionValuer:
		return ValueTypeDefinition
	default:
		panic("invalid valuer!")
	}
}

// table is the single table in system
type table struct {
	name   string
	fields map[string]columnDef // interface is one of the Valuer interface and not anything else
	data   Table
	lock   *sync.Mutex
}

// Table is a interface for registration of a data
type Table interface {
	// the function argument is the object used as database. in our case it is the astdata.Package and the result
	// must be an array of items. items are depends on the table. for example on funcs table, the result
	// is a slice of astdata.Functions
	Provide(interface{}) []interface{}
}

// RegisterTable is the function to handle registration of a table, the name must be unique, and duplicate registration
// panics
func RegisterTable(name string, data Table) {
	lock.Lock()
	defer lock.Unlock()

	if _, ok := tables[name]; ok {
		panic(fmt.Sprintf("table with name %s is already registered", name))
	}
	tables[name] = &table{
		name:   name,
		data:   data,
		fields: make(map[string]columnDef),
		lock:   &sync.Mutex{},
	}
}

// getTable return the table definition
func getTable(t string) (map[string]columnDef, error) {
	tbl, ok := tables[t]
	if !ok {
		return nil, fmt.Errorf("table %s is not available", t)
	}

	return tbl.fields, nil
}

// RegisterField is the field registration for a table, table must registered before and the name must be unique in that table
// the value is one of the String/Bool/NumberValuer in any other case, it panics
func RegisterField(t string, name string, valuer interface{}) {
	lock.Lock()
	defer lock.Unlock()

	tbl, ok := tables[t]
	if !ok {
		panic(fmt.Sprintf("table %s is not available", t))
	}
	max := -1
	for i := range tbl.fields {
		if tbl.fields[i].order > max {
			max = tbl.fields[i].order
		}
	}
	max++
	if _, ok := tbl.fields[name]; ok {
		panic(fmt.Sprintf("table %s is already have field %s", t, name))
	}

	switch valuer.(type) {
	case BoolValuer:
	case NumberValuer:
	case StringValuer:
	case DefinitionValuer:
	default:
		panic(fmt.Sprintf("valuer is not a valid valuer, its is %T", valuer))
	}

	tbl.fields[name] = columnDef{
		typ:   valuer,
		name:  name,
		order: max,
	}
}

func checkTableFields(tbl *table, fields ...string) error {
	var invalid []string
	for i := range fields {
		if fields[i] == "" {
			continue
		}
		if _, ok := tbl.fields[fields[i]]; !ok {
			invalid = append(invalid, fields[i])
		}
	}
	if len(invalid) > 0 {
		return fmt.Errorf("invalid field(s) : %s", strings.Join(invalid, ", "))
	}
	return nil
}

// getTableFields is the get field for a table, empty field name is ignored, so the caller could fill
// calculated item
func getTableFields(p interface{}, t string, res chan<- []Getter, quit chan struct{}, fields ...string) error {
	lock.Lock()
	defer lock.Unlock()
	tbl, ok := tables[t]
	if !ok {
		return fmt.Errorf("invalid table name %s", t)
	}

	if len(fields) == 0 {
		return fmt.Errorf("no field selected")
	}

	if err := checkTableFields(tbl, fields...); err != nil {
		return err
	}

	// do concurrently
	go func() {
		defer close(res)
		cache := tbl.data.Provide(p)
		for i := range cache {
			n := make([]Getter, len(fields))
			for f := range fields {
				if fields[f] == "" {
					// this is a placeholder
					continue
				}
				switch t := tbl.fields[fields[f]].typ.(type) {
				case StringValuer:
					n[f] = t.Value(cache[i])
				case NumberValuer:
					n[f] = t.Value(cache[i])
				case BoolValuer:
					n[f] = t.Value(cache[i])
				case DefinitionValuer:
					n[f] = t.Value(cache[i])
				}
			}
			select {
			case res <- n:
			case <-quit:
				return // whenever catch a close signal, exit from loop
			}
		}
	}()
	return nil
}
