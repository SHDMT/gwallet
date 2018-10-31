package dag

import (
	"fmt"
	"github.com/SHDMT/gwallet/infrastructure/database"
	_ "github.com/SHDMT/gwallet/infrastructure/database/badgerdb"
	"github.com/SHDMT/gwallet/platform/walletdb"
)

//func TestGetUnitTemplate(t *testing.T) {
//	log2.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel,
//		config.DefaultLogDir+"/", log.Stdout)
//	log.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel,
//		config.DefaultLogDir+"/", log.Stdout)
//	dbPath := "./~temp/TestGetUnitTemplate/"
//
//	os.RemoveAll(dbPath)
//	createDBAndBcuket(dbPath)
//	db, err := database.Open("badgerDB", dbPath, dbPath)
//	defer func() {
//		if db != nil {
//			db.Close()
//		}
//	}()
//	//start DAG RPC Server
//	addrMgr := walletrpc.NewAddrManager()
//	protocol := walletrpc.NewWalletRPCProtocol(addrMgr)
//	server := walletrpc.NewRPCServer(protocol)
//
//	server.Start()
//	defer server.Stop()
//
//	client := NewClient(db)
//	client.Start()
//
//	unit, err := client.GetUnitTemplate()
//
//	if err != nil {
//		t.Error("err:", err)
//		panic(t)
//	}
//	t.Log(unit)
//	t.Log("done!")
//}
//
//func TestNewAddress(t *testing.T) {
//
//	log2.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel,
//		config.DefaultLogDir+"/", log.Stdout)
//	log.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel,
//		config.DefaultLogDir+"/", log.Stdout)
//	log.Init(gconfig.Parameters.MaxLogSize, gconfig.Parameters.LogLevel, log.Stdout)
//
//	dbPath := "./~temp/TestNewAddress/"
//
//	os.RemoveAll(dbPath)
//	createDBAndBcuket(dbPath)
//	db, err := database.Open("badgerDB", dbPath, dbPath)
//	defer func() {
//		if db != nil {
//			db.Close()
//		}
//	}()
//	//start DAG RPC Server
//	addrMgr := walletrpc.NewAddrManager()
//	protocol := walletrpc.NewWalletRPCProtocol(addrMgr)
//	server := walletrpc.NewRPCServer(protocol)
//
//	server.Start()
//	defer server.Stop()
//
//	client := NewClient(db)
//	client.Start()
//
//	addr := new(addrmgr.Address)
//	err = client.UpdateAddress(*addr)
//
//	if err != nil {
//		t.Error("err:", err)
//		panic(t)
//	}
//	t.Log("done!")
//}
//
//func TestPostUnit(t *testing.T) {
//
//	log2.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel,
//		config.DefaultLogDir+"/", log.Stdout)
//	log.Init(config.Parameters.MaxLogSize, config.Parameters.LogLevel,
//		config.DefaultLogDir+"/", log.Stdout)
//	dbPath := "./~temp/TestPostUnit/"
//
//	os.RemoveAll(dbPath)
//	createDBAndBcuket(dbPath)
//	db, err := database.Open("badgerDB", dbPath, dbPath)
//	defer func() {
//		if db != nil {
//			db.Close()
//		}
//	}()
//	//start DAG RPC Server
//	addrMgr := walletrpc.NewAddrManager()
//	protocol := walletrpc.NewWalletRPCProtocol(addrMgr)
//	server := walletrpc.NewRPCServer(protocol)
//
//	server.Start()
//	defer server.Stop()
//
//	client := NewClient(db)
//	client.Start()
//
//	unit := new(structure.Unit)
//	err = client.PostUnit(unit)
//
//	if err != nil {
//		t.Error("err:", err)
//		panic(t)
//	}
//	t.Log("done!")
//}
//
////dag.started == false
//func TestDagClient_PostUnit(t *testing.T) {
//	dbPath := "./~temp/TestDagClient_PostUnit/"
//
//	os.RemoveAll(dbPath)
//	createDBAndBcuket(dbPath)
//	db, err := database.Open("badgerDB", dbPath, dbPath)
//	defer func() {
//		if db != nil {
//			db.Close()
//		}
//	}()
//	client := NewClient(db)
//	client.Start()
//	client.started=false
//	unit := new(structure.Unit)
//	err = client.PostUnit(unit)
//	if err != nil {
//		t.Log("测试通过")
//	}else {
//		t.Error("测试不通过")
//	}
//}
//
//func TestDagClient_InitAddress(t *testing.T) {
//
//}

func createDBAndBcuket(dbPath string) {

	db, err := database.Create("badgerDB", dbPath, dbPath)
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	if err != nil {
		fmt.Printf("Error %s\n", err)
		return
	}

	err = walletdb.CreateWalletBucket(db)
	fmt.Println("=====================>", err)
	if err != nil {
		fmt.Printf("Error %s\n", err)
	}
}
