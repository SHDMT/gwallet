package grpc

//
//import (
//	"context"
//	"github.com/SHDMT/gwallet/infrastructure/config"
//	"github.com/SHDMT/gwallet/platform"
//	"github.com/SHDMT/gwallet/platform/grpc/walletrpc"
//	"google.golang.org/grpc"
//	"path/filepath"
//	"sync"
//	"testing"
//	"os"
//	"fmt"
//	"time"
//)
//
//func TestStartServer(t *testing.T) {
//	//log init
//	//database init
//	dbfile := filepath.Join(config.Parameters.DataDir, "testnewwallet")
//	defer removePath(dbfile)
//	db, err := platform.CreateWalletDb(dbfile)
//	// defer db.Close()
//	if err != nil {
//		t.Error(" create new wallet database failed : ", err)
//		return
//	}
//	password:=[]byte("123")
//
//	// wallet init
//	wallet,err:= platform.NewWallet(config.Parameters, db,password)
//
//	//start server
//	wg:=sync.WaitGroup{}
//	StartServer(wallet)
//	wg.Add(1)
//
//	//start client
//	conn,err:=grpc.Dial("127.0.0.1:50052",grpc.WithInsecure())
//	if err!=nil{
//		t.Errorf("grpc client dial failed %v",err)
//		return
//	}
//	defer conn.Close()
//	client:=walletrpc.NewAccountServiceClient(conn)
//	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
//	defer cancel()
//
//	//Start Testing
//	//start wallet
//	//wallet.Start()
//
//	//2. GetNewAddress Testing
//	newAddr,err:=client.GetNewAddress(ctx,&walletrpc.AddressRequest{})
//	if err !=nil{
//		t.Error("client getnewaddress error ",err)
//		return
//	}
//	t.Logf("GetNewAddress Testing success,newAddr=%s\n",newAddr.AddressString)
//
//	//3.GetBalance Testing
//	_,err=client.GetBalance(ctx,&walletrpc.BalanceRequest{})
//	if err !=nil{
//		t.Error("client GetBalance error",err)
//		return
//	}
//
//
//	//4.GetPaymentHistory Testing
//	//TODO 功能尚未完善
//	_,err=client.GetPaymentHistory(ctx,&walletrpc.HistoryRequest{})
//	if err !=nil{
//		t.Error("client GetPaymentHistory error",err)
//		return
//	}
//	t.Log("GetPaymentHistory Testing success")
//
//	//5.GetTextHistory Testing
//	//TODO 功能尚未完善
//	_,err=client.GetTextHistory(ctx,&walletrpc.HistoryRequest{})
//	if err !=nil{
//		t.Error("client GetTextHistory error",err)
//		return
//	}
//	t.Log("GetTextHistory Testing success")
//
//	//6.GetPaymentMessageInfo Testing
//	// _,err=client.GetPaymentMessageInfo(ctx,&pb.MessageInfoRequest{})
//	// if err !=nil{
//	// 	t.Errorf("client GetPaymentMessageInfo error",err)
//	// 	return
//	// }
//
//	wg.Done()
//	wg.Wait()
//}
//
//func removePath(path string) error {
//	err := os.RemoveAll(path)
//	if err != nil {
//		fmt.Println("delet dir error:", err)
//		return err
//	}
//	return nil
//}
