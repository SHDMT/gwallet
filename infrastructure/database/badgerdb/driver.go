package badgerdb

import (
	"fmt"
	"github.com/SHDMT/gwallet/infrastructure/database"
)

// parseArgs parses the arguments from the database Open/Create methods.
func parseArgs(operation string, args ...interface{}) (keyDir, valueDir string, err error) {
	if len(args) != 2 {
		errDescription := fmt.Sprintf("failed to parse the parameters on %s, wrong number", operation)
		return "", "", database.NewDBError(database.ErrInvalidPara, errDescription, nil)
	}

	keyDir, ok := args[0].(string)
	if !ok {
		errDescription := fmt.Sprintf("failed to parse the parameters on %s, "+
			"first parameters should be string", operation)
		err = database.NewDBError(database.ErrInvalidPara, errDescription, nil)
		keyDir = ""
		valueDir = ""
		return
	}

	valueDir, ok = args[1].(string)
	if !ok {
		errDescription := fmt.Sprintf("failed to parse the parameters on %s, "+
			"second parameters should be string", operation)
		err = database.NewDBError(database.ErrInvalidPara, errDescription, nil)
		keyDir = ""
		valueDir = ""
		return
	}
	err = nil
	return
}

// openDBDriver is the callback provided during driver registration that opens
// an existing database for use.
func openDBDriver(args ...interface{}) (database.DB, error) {
	keyDir, valueDir, err := parseArgs("Open", args...)
	if err != nil {
		return nil, err
	}

	db, err := openBadgerDb(keyDir, valueDir)
	if db == nil {
		return nil, err
	}
	return db, err
}

// createDBDriver is the callback provided during driver registration that
// creates, initializes, and opens a database for use.
func createDBDriver(args ...interface{}) (database.DB, error) {
	keyDir, valueDir, err := parseArgs("Create", args...)
	if err != nil {
		return nil, err
	}

	db, err := createBadgerDb(keyDir, valueDir)
	if db == nil {
		return nil, err
	}
	return db, err
}

func init() {
	// Register the driver.
	driver := database.Driver{
		DbName: dbName,
		Create: createDBDriver,
		Open:   openDBDriver,
	}

	err := database.RegisterDriver(driver)
	if err != nil {
		panic(fmt.Sprintf("Failed to regiser database driver '%s': %v", dbName, err))
	}
}
