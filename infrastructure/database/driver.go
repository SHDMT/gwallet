package database

import (
	"fmt"
)

// driverList holds all of the registered database backends.
var dbDrivers = make(map[string]*Driver)

// Driver defines a structure for backend drivers to use when they registered
// themselves as a backend which implements the DB interface.
type Driver struct {
	// DbType is the identifier used to uniquely identify a specific
	// database driver.  There can be only one driver with the same name.
	DbName string

	// Create is the function that will be invoked with all user-specified
	// arguments to create the database.  This function must return
	// ErrDbExists if the database already exists.
	Create func(args ...interface{}) (DB, error)

	// Open is the function that will be invoked with all user-specified
	// arguments to open the database.  This function must return
	// ErrDbDoesNotExist if the database has not already been created.
	Open func(args ...interface{}) (DB, error)
}

// RegisterDriver adds a backend database driver to available interfaces.
// ErrDbTypeRegistered will be returned if the database type for the driver has
// already been registered.
func RegisterDriver(driver Driver) error {
	if _, exists := dbDrivers[driver.DbName]; exists {
		errDescription := fmt.Sprintf("driver %s is already registered", driver.DbName)
		return NewDBError(ErrDbAlreadyRegistered, errDescription, nil)
	}

	dbDrivers[driver.DbName] = &driver
	return nil
}

// DbList returns a slice of strings that represent the database
// drivers that have been registered and are therefore supported.
func DbList() []string {
	dbList := make([]string, len(dbDrivers))
	count := uint32(0)
	for dbName := range dbDrivers {
		dbList[count] = dbName
	}
	return dbList
}

// Create initializes and opens a database for the specified type.  The
// arguments are specific to the database type driver.  See the documentation
// for the database driver for further details.
//
// ErrDbNotRegisted will be returned if the the database type is not registered.
func Create(dbName string, args ...interface{}) (DB, error) {
	drv, exists := dbDrivers[dbName]
	if !exists {
		errDescription := fmt.Sprintf("driver %s is not registered", dbName)
		return nil, NewDBError(ErrDbNotRegistered, errDescription, nil)
	}

	return drv.Create(args...)
}

// Open opens an existing database for the specified type.  The arguments are
// specific to the database type driver.  See the documentation for the database
// driver for further details.
//
// ErrDbNotRegisted will be returned if the the database type is not registered.
func Open(dbName string, args ...interface{}) (DB, error) {
	drv, exists := dbDrivers[dbName]
	if !exists {
		errDescription := fmt.Sprintf("driver %s is not registered", dbName)
		return nil, NewDBError(ErrDbNotRegistered, errDescription, nil)
	}

	return drv.Open(args...)
}
