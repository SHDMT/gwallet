package dag

import (
	"context"
	"sync"

	"github.com/SHDMT/gravity/platform/consensus/structure"
	"github.com/SHDMT/gravity/platform/proto"
	"github.com/SHDMT/gwallet/infrastructure/database"
	"github.com/SHDMT/gwallet/infrastructure/log"
	"github.com/SHDMT/gwallet/platform/addrmgr"
	"google.golang.org/grpc"
)

const (
	address = "localhost:50051"
)

// GravityClient all the information needed to support gRPCClient
type GravityClient struct {
	started bool
	client  proto.DAGClient
	conn    *grpc.ClientConn
	db      database.DB
	lock    sync.RWMutex
}

// PostUnit post new unit to gravity network
func (gc *GravityClient) PostUnit(unit *structure.Unit) error {
	if !gc.started {
		return ErrClientClosed
	}
	entry := proto.UnitToUnitEntry(unit)
	_, err := gc.client.SendUnit(context.Background(), &entry)

	return err
}

// UpdateAddress  post new wallet address to connected gravity
func (gc *GravityClient) UpdateAddress(address addrmgr.Address) error {
	if !gc.started {
		return ErrClientClosed
	}

	entry := new(proto.AddressEntry)
	entry.Address = address.Address

	_, err := gc.client.UpdateAddress(context.Background(), entry)

	return err
}

// InitAddress post all known addresses to connected gravity , gravity will filter message with wallet address
func (gc *GravityClient) InitAddress(addrList []addrmgr.Address, mci uint64) error {
	if !gc.started {
		return ErrClientClosed
	}
	addrEntryList := make([]*proto.AddressEntry, 0)
	for _, v := range addrList {
		entry := new(proto.AddressEntry)
		entry.Address = v.Address
		addrEntryList = append(addrEntryList, entry)
	}
	requestEntry := &proto.RequestEntry{
		AddressEntryList: addrEntryList,
		Mci:              mci,
	}
	_, err := gc.client.InitAddress(context.Background(), requestEntry)

	return err
}

// GetUnitTemplate get a unit template from connected gravity when create new transaction
func (gc *GravityClient) GetUnitTemplate() (*structure.Unit, error) {
	if !gc.started {
		return nil, ErrClientClosed
	}
	request := new(proto.UnitTemplateRequest)
	entry, err := gc.client.NewUnitTemplate(context.Background(), request)
	if err != nil {
		log.Error("Get template failed : ", err)
		return nil, err
	}
	unit := proto.UnitEntryToUnit(entry)

	return unit, err
}

// GetAssetName get asset name from specified assetID
func (gc *GravityClient) GetAssetName(asset []byte) (string, error) {
	if !gc.started {
		return "", ErrClientClosed
	}
	request := &proto.AssetNameRequest{Asset: asset}
	res, err := gc.client.GetAssetName(context.Background(), request)
	if err != nil {
		return "", err
	}

	return res.AssetName, nil
}

// FindAddress Check if the address used on the DAG
func (gc *GravityClient) FindAddress(addresses []*addrmgr.Address, mci uint64) (bool, uint32, error) {
	if !gc.started {
		return false, 0, ErrClientClosed
	}
	var addrs [][]byte
	for _, addr := range addresses {
		addrs = append(addrs, addr.Address)
	}
	request := &proto.FindAddressRequest{Address: addrs, Mci: mci}
	res, err := gc.client.FindAddress(context.Background(), request)
	if err != nil {
		return false, 0, err
	}

	return res.Used, res.Index, nil
}

// Start gRPC client
func (gc *GravityClient) Start() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	gc.client = proto.NewDAGClient(conn)
	gc.conn = conn
	gc.started = true
}

// Stop gRPC Client
func (gc *GravityClient) Stop() {
	gc.conn.Close()
	gc.started = false
}

// NewClient create a new gRPCClient
func NewClient(db database.DB) *GravityClient {
	return &GravityClient{
		db:      db,
		started: false,
	}
}
