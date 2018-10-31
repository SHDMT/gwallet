package dag

import (
	"encoding/json"
	"net"

	"github.com/SHDMT/gravity/infrastructure/crypto/hash"
	"github.com/SHDMT/gravity/platform/consensus/structure"
	"github.com/SHDMT/gwallet/infrastructure/log"
	"github.com/SHDMT/gwallet/platform/message"
	"github.com/SHDMT/gwallet/platform/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	port            = ":50050"
	// ResponseSuccess success
	ResponseSuccess = 200
	// ResponseErr failed
	ResponseErr     = 400
)

// RPCServer all the information needed to support a rpcServer
type RPCServer struct {
	dagClient *GravityClient
	msgMgr    *message.TXManager
	lis       net.Listener
	server    *grpc.Server
}

// ReceiveMessage Handle the message associated with wallet
func (server *RPCServer) ReceiveMessage(ctx context.Context, msg *proto.Message) (*proto.Response, error) {
	response := new(proto.Response)

	log.Debug(" received message : ", msg.Message)
	message := server.msgBinaryToMessage(msg.Message)
	server.msgMgr.ReceiveMessage(message, msg.UnitHash, msg.MessageID, func(asset []byte) (string, error) {
		return server.dagClient.GetAssetName(asset)
	})

	response.Response = ResponseSuccess

	return response, nil
}

// UpdateStates change wallet uTXO states
func (server *RPCServer) UpdateStates(ctx context.Context, state *proto.State) (*proto.Response, error) {
	response := new(proto.Response)

	validUnitHashes := make([]hash.HashType, 0)
	invalidUnitHashes := make([]hash.HashType, 0)
	feeUTXOs := make([]structure.Utxo, 0)
	for _, v := range state.ValidUnits {
		validUnitHashes = append(validUnitHashes, v)
	}
	for _, v := range state.InvalidUnits {
		invalidUnitHashes = append(invalidUnitHashes, v)
	}
	for _, utxoBinary := range state.FeeUTXOs {
		utxo := server.utxoBinaryToUTXO(utxoBinary)
		feeUTXOs = append(feeUTXOs, utxo)
	}
	server.msgMgr.UpdateStates(state.Mci, validUnitHashes, invalidUnitHashes, feeUTXOs)

	response.Response = ResponseSuccess

	return response, nil
}

func (server *RPCServer) msgBinaryToMessage(msgBinary []byte) structure.Message {
	switch msgBinary[0] {
	case structure.PaymentMessageType:
		paymentMessage := new(structure.PaymentMessage)
		paymentMessage.Deserialize(msgBinary)
		return paymentMessage
	case structure.TextMessageType:
		textMessage := new(structure.TextMessage)
		textMessage.Deserialize(msgBinary)
		return textMessage
	case structure.KeyMessageType:
		keyMessage := new(structure.KeyMessage)
		keyMessage.Deserialize(msgBinary)
		return keyMessage
	case structure.IssueMessageType:
		issueMessage := new(structure.IssueMessage)
		issueMessage.Deserialize(msgBinary)
		return issueMessage
	case structure.InvokeMessageType:
		invokeMessage := new(structure.InvokeMessage)
		invokeMessage.Deserialize(msgBinary)
		return invokeMessage
	}
	return nil
}

func (server *RPCServer) utxoBinaryToUTXO(utxoBinary []byte) structure.Utxo {
	switch utxoBinary[0] {
	case structure.TxUtxoType:
		txutxo := new(structure.TxUtxo)
		txutxo.Deserialize(utxoBinary)
		return txutxo
	case structure.CommissionUtxoType:
		commissionutxo := new(structure.CommissionUtxo)
		commissionutxo.Deserialize(utxoBinary)
		return commissionutxo
	case structure.ExternalUtxoType:
		externalutxo := new(structure.ExternalUtxo)
		externalutxo.Deserialize(utxoBinary)
		return externalutxo
	}
	return nil
}

// UpdateMCI change wallet uTXO states when DAG stable point increase
func (server *RPCServer) UpdateMCI(ctx context.Context, bucket *proto.MsgBucket) (*proto.Response, error) {
	response := new(proto.Response)
	stableMsgs := make([]structure.Message, 0)
	stableMsgIds := make([]uint32, 0)
	stableMsgUnits := make([]hash.HashType, 0)
	utxos := make([]structure.Utxo, 0)

	log.Debug(" stable message count : ", len(bucket.StableMessages))
	jsonData, _ := json.Marshal(bucket)
	log.Debugf(" -update mci : %x \n ", jsonData)

	for _, msgBinary := range bucket.StableMessages {
		log.Debugf(" stable message : %x \n", msgBinary)
		msg := server.msgBinaryToMessage(msgBinary)
		stableMsgs = append(stableMsgs, msg)
	}
	for _, utxoBinary := range bucket.FeeUTXOs {
		utxo := server.utxoBinaryToUTXO(utxoBinary)
		utxos = append(utxos, utxo)
	}
	for _, unitHash := range bucket.StableMessagesUnit {
		stableMsgUnits = append(stableMsgUnits, unitHash)
	}
	for _, mid := range bucket.StableMessagesID {
		stableMsgIds = append(stableMsgIds, mid)
	}

	server.msgMgr.UpdateMCI(bucket.Mci, stableMsgs, stableMsgUnits, stableMsgIds, utxos, bucket.Completed)
	response.Response = ResponseSuccess
	return response, nil
}

func (server *RPCServer) startServer() {
	var err error
	server.lis, err = net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	server.server = grpc.NewServer()
	proto.RegisterWalletServer(server.server, server)
	// Register reflection service on gRPC server.
	reflection.Register(server.server)
	if err := server.server.Serve(server.lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

// Start gRPC server
func (server *RPCServer) Start() {
	go server.startServer()
}

// Stop gRPC server
func (server *RPCServer) Stop() {
	server.lis.Close()
	server.server.Stop()
}

// NewRPCServer create a new rpcServer instance
func NewRPCServer(msgMgr *message.TXManager, dag *GravityClient) *RPCServer {
	return &RPCServer{
		dagClient: dag,
		msgMgr:    msgMgr,
	}
}
