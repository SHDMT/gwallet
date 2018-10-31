package grpc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/SHDMT/gravity/platform/consensus/structure"
	"github.com/SHDMT/gwallet/infrastructure/log"
	"github.com/SHDMT/gwallet/platform"
	pb "github.com/SHDMT/gwallet/platform/grpc/walletrpc"
	"github.com/SHDMT/gwallet/platform/message"
	"google.golang.org/grpc"
	"net"
)

const (
	port = ":50052"
)

type accountService struct {
	wallet *platform.Wallet
}

// PaymentMessageInfo normal payment transaction
type PaymentMessageInfo struct {
	TimeStamp      int64
	MessageKey     []byte
	MessageContent structure.Message
}

// GetNewAddress generate the address under the specified account
func (s *accountService) GetNewAddress(ctx context.Context, in *pb.AddressRequest) (*pb.AddressResponse, error) {
	address, err := s.wallet.Addrmgr.NewAddress(in.AccountNameString, false)
	if err != nil {
		return nil, err
	}
	if s.wallet.DagClient != nil {
		err = s.wallet.DagClient.UpdateAddress(*address)
		if err != nil {
			log.Warn(" can't notification new address to gravity : ", err)
		}
	}

	base64Address := base64.StdEncoding.EncodeToString(address.Address)
	log.Infof("new address: %s \n", base64Address)
	return &pb.AddressResponse{AddressString: base64Address}, nil
}

// GetBalance View the wallet asset details, and filter the designated asset details under designated
// accounts via account name and asset name
func (s *accountService) GetBalance(ctx context.Context, in *pb.BalanceRequest) (*pb.BalanceResponse, error) {

	balance, err := s.wallet.Messagemgr.GetBalance(in.AccountInfoName, in.AccountInfoAssetHash)
	if err != nil {
		return nil, err
	}

	return &pb.BalanceResponse{Balances: balance}, nil
}

// GetPaymentHistory list payment transaction history
func (s *accountService) GetPaymentHistory(ctx context.Context, in *pb.HistoryRequest) (*pb.PaymentHistoryResponse, error) {
	timeStemps, messageKeys, messagees, err := s.wallet.Messagemgr.
		ListMessagesHistory(int64(in.FromMCI),
			int64(in.Count))
	if err != nil {
		log.Error("get Payment Messages failed ")
		return nil, fmt.Errorf("get Payment Messages failed: %s ", err)
	}
	if len(timeStemps) != len(messageKeys) || len(timeStemps) != len(
		messagees) || len(messageKeys) != len(messagees) {
		log.Error("get Payment Messages failed ")
		return nil, fmt.Errorf("get Payment Messages failed")
	}
	messageResponse := make([]PaymentMessageInfo, 0)
	for i, timeStamp := range timeStemps {
		messageInfo := &PaymentMessageInfo{
			TimeStamp:      timeStamp,
			MessageKey:     messageKeys[i].Serialize(),
			MessageContent: messagees[i],
		}
		messageResponse = append(messageResponse, *messageInfo)
	}

	historyData, err := json.MarshalIndent(messageResponse, "", " ")
	if err != nil {
		log.Debug(" json marshal failed ")
		return nil, errors.New(" json marshal failed ")
	}

	return &pb.PaymentHistoryResponse{PaymentHistory: historyData}, nil
}

// GetPaymentMessageInfo get payment transaction information with specified transaction ID
func (s *accountService) GetPaymentMessageInfo(ctx context.Context, in *pb.MessageInfoRequest) (*pb.PaymentMessageInfoResponse, error) {
	fmt.Println("test GetPaymentMessageInfo")
	payment, err := s.wallet.Messagemgr.GetPaymentMessageInfo(in.UnitHash, in.MessageId)
	if err != nil {
		return nil, err
	}
	paymentBytes, err := json.Marshal(payment)
	if err != nil {
		log.Error(" json marshaling message failed : ", err)
		return nil, err
	}
	return &pb.PaymentMessageInfoResponse{PaymentInfo: paymentBytes}, nil
}

// SendText send a text message
func (s *accountService) SendText(ctx context.Context, in *pb.SendTextRequest) (*pb.SendTextResponse, error) {
	args := message.TextARGS{
		AccountName: in.SendTextAccount,
		Text:        in.TextContent,
	}
	if in.Send {
		unitHash, err := s.wallet.UnitAssemble.CreateUnit(&args)
		if err != nil {
			return nil, err
		}
		return &pb.SendTextResponse{SendTextResult: unitHash}, nil
	}
	commission, err := s.wallet.UnitAssemble.CalculateCommission(&args)
	if err != nil {
		return nil, err
	}
	return &pb.SendTextResponse{Commission: commission}, nil

}

// SendToMany send payment message
func (s *accountService) SendToMany(ctx context.Context, in *pb.SendToManyRequest) (*pb.SendPaymentResponse, error) {

	args := message.PaymentARGS{
		AccountName: in.SendPaymentAccount,
		SendPairs:   in.SendPairs,
	}
	if in.Send {
		unitHash, err := s.wallet.UnitAssemble.CreateUnit(&args)
		if err != nil {
			return nil, err
		}
		return &pb.SendPaymentResponse{SendPaymentResult: unitHash}, nil
	}
	commission, err := s.wallet.UnitAssemble.CalculateCommission(&args)
	if err != nil {
		return nil, err
	}
	return &pb.SendPaymentResponse{Commission: commission}, nil
}

// InvokeContract execute the specified smart contract
func (s *accountService) InvokeContract(ctx context.Context, in *pb.InvokeContractRequest) (*pb.InvokeContractResponse, error) {

	args := &message.InvokeARGS{
		AccountName:     in.Account,
		Asset:           in.Asset,
		ContractAddress: in.Contract,
		AmountList:      in.AmountList,
		Params:          in.Params,
	}
	log.Debugf(" invoke param grpc : %x \n", in.Params)
	if in.Send {
		unitHash, err := s.wallet.UnitAssemble.CreateUnit(args)
		if err != nil {
			return nil, err
		}
		return &pb.InvokeContractResponse{UnitHash: unitHash}, nil
	}
	commission, err := s.wallet.UnitAssemble.CalculateCommission(args)
	if err != nil {
		return nil, err
	}
	return &pb.InvokeContractResponse{Commission: commission}, nil
}

// IssueContract issue a new asset
func (s *accountService) IssueContract(ctx context.Context, in *pb.IssueContractRequest) (*pb.IssueContractResponse, error) {
	assetCap := int64(in.AssetCap)

	contracts := make([]*structure.ContractDef, len(in.Contracts))
	for i, contractDef := range in.Contracts {
		contract := new(structure.ContractDef)
		contract.Deserialize(contractDef)
		contracts[i] = contract
	}

	args := &message.IssueARGS{
		AssetName:          in.AssetName,
		Cap:                assetCap,
		FixedDenominations: in.FixedDenominations,
		Denominations:      in.Denominations,
		Contracts:          contracts,
		AllocationAddr:     in.AllocationAddr,
		AllocationAmount:   in.AllocationAmount,
		PublisherAddress:   in.PublisherAddress,
		Note:               in.Note,
	}
	if in.Send {
		unitHash, err := s.wallet.UnitAssemble.CreateUnit(args)
		if err != nil {
			return nil, err
		}
		return &pb.IssueContractResponse{UnitHash: unitHash}, nil
	}
	commission, err := s.wallet.UnitAssemble.CalculateCommission(args)
	if err != nil {
		return nil, err
	}
	return &pb.IssueContractResponse{Commission: commission}, nil
}

// DeployContract deploy new smart contracts
func (s *accountService) DeployContract(ctx context.Context, in *pb.DeployContractRequest) (*pb.DeployContractResponse, error) {

	args := &message.DeployARGS{
		Contracts: in.Contracts,
	}

	if in.Send {
		unitHash, err := s.wallet.UnitAssemble.CreateUnit(args)
		if err != nil {
			return nil, err
		}
		return &pb.DeployContractResponse{UnitHash: unitHash}, nil
	}
	commission, err := s.wallet.UnitAssemble.CalculateCommission(args)
	if err != nil {
		return nil, err
	}
	return &pb.DeployContractResponse{Commission: commission}, nil
}

// SendRawUnit send a raw unit to gravity network
func (s *accountService) SendRawUnit(ctx context.Context,
	in *pb.SendRawUnitRequest) (*pb.SendRawUnitResponse, error) {


	return &pb.SendRawUnitResponse{SendRawUnitResult: nil}, nil
}

// ValidateAddress verify that the address is valid
func (s *accountService) ValidateAddress(ctx context.Context, in *pb.ValidateAddressRequest) (*pb.ValidateAddressResponse, error) {

	result := s.wallet.Addrmgr.ValidateAddress(in.Address)

	return result, nil
}

// CreateNewAccount create  a new account
func (s *accountService) CreateNewAccount(ctx context.Context,
	in *pb.CreateNewAccountRequest) (*pb.CreateNewAccountResponse, error) {

	account, address, err := s.wallet.Addrmgr.CreateNewAccount(s.wallet.CryptoKey,
		in.Account, int(in.AcctType))
	if err != nil {
		return nil, fmt.Errorf(" Failed to create new account , "+
			"please try again: %s ", err.Error())
	}
	s.wallet.DagClient.UpdateAddress(*address)
	s.wallet.Messagemgr.LoadAccounts()
	s.wallet.Utxomgr.AddNewAccount(account)

	addressString := base64.StdEncoding.EncodeToString(address.Address)
	log.Infof(" [your account first address is : ] %s \n", addressString)
	return &pb.CreateNewAccountResponse{Address: addressString}, nil
}

// DumpPrivateKey dump private key for the specified address
func (s *accountService) DumpPrivateKey(ctx context.Context,
	in *pb.DumpPrivateKeyRequest) (*pb.DumpPrivateKeyResponse, error) {

	privKey, err := s.wallet.DumpPrivateKey(in.Address)
	if err != nil {
		return nil, err
	}

	return &pb.DumpPrivateKeyResponse{PrivKey: privKey}, nil
}

// ImportPrivateKey import a private key in WIF format
func (s *accountService) ImportPrivateKey(ctx context.Context,
	in *pb.ImportPrivateKeyRequest) (*pb.ImportPrivateKeyResponse, error) {

	importedAddress, err := s.wallet.ImportPrivKey(in.PrivKey)
	if err != nil {
		return nil, errors.New("import private key failed")
	}

	return &pb.ImportPrivateKeyResponse{Address: importedAddress}, nil
}

// UpdatePassword update wallet password
func (s *accountService) UpdatePassword(ctx context.Context,
	in *pb.UpdatePasswordRequest) (*pb.UpdatePasswordResponse, error) {

	err := s.wallet.UpdatePassword(in.OldPassword, in.NewPassword)
	if err != nil {
		return nil, fmt.Errorf(" can't change new password ")
	}
	return &pb.UpdatePasswordResponse{}, nil
}

// RescanWallet rescan DAG and filter message used wallet addresses
func (s *accountService) RescanWallet(ctx context.Context, in *pb.RescanWalletRequest) (*pb.RescanWalletResponse, error) {

	s.wallet.Rescan(in.Start)

	return &pb.RescanWalletResponse{}, nil
}

//GetAllAssets list all assets held by wallet
func (s *accountService)GetAllAssets(ctx context.Context, in *pb.AllAssetsRequest)(*pb.AllAssetsResponse,error){

	assets,err:=s.wallet.GetAllAsset()

	return &pb.AllAssetsResponse{Assets:assets},err
}

// IsOfficial check  if the current wallet is an official wallet
func (s *accountService) IsOfficial(ctx context.Context, in *pb.IsOfficialRequest) (*pb.IsOfficialResponse, error){
	isOfficial := s.wallet.Addrmgr.IsOfficial()
	return &pb.IsOfficialResponse{IsOfficial:isOfficial}, nil
}

// InvokeContractWithJson
func (s *accountService)InvokeContractWithJson(ctx context.Context, request *pb.InvokeContractWithJsonRequest)(*pb.InvokeContractWithJsonResponse, error){

	log.Debugf("%x \n ", request.InvokeJson)
	args := &message.InvokeWithJsonArgs{
		PaymentAccount:request.PaymentAccount,
		InvokeJson:request.InvokeJson,
		InvokeAmount:request.Amount,
		Send:request.Send,
	}

	if request.Send {
		unitHash, err := s.wallet.UnitAssemble.CreateUnit(args)
		if err != nil {
			return nil, err
		}
		return &pb.InvokeContractWithJsonResponse{UnitHash: unitHash}, nil
	}
	commission, err := s.wallet.UnitAssemble.CalculateCommission(args)
	if err != nil {
		return nil, err
	}
	return &pb.InvokeContractWithJsonResponse{Commission: commission}, nil
}

// IssueAssetWithJson
func (s *accountService)IssueAssetWithJson(ctx context.Context, request *pb.IssueAssetWithJsonRequest)(*pb.IssueAssetWithJsonResponse, error){

	args := &message.IssueWithJsonArgs{
		PaymentAccount: request.PaymentAccount,
		IssueJson: request.IssueJson,
		Send: request.Send,
	}
	if request.Send {
		unitHash, err := s.wallet.UnitAssemble.CreateUnit(args)
		if err != nil {
			return nil, err
		}
		return &pb.IssueAssetWithJsonResponse{UnitHash: unitHash}, nil
	}
	commission, err := s.wallet.UnitAssemble.CalculateCommission(args)
	if err != nil {
		return nil, err
	}
	return &pb.IssueAssetWithJsonResponse{Commission: commission}, nil
}

// DeployContractWithJson
func (s *accountService)DeployContractWithJson(ctx context.Context, request *pb.DeployContractWithJsonRequest)(*pb.DeployContractWithJsonResponse, error){

	args := &message.DeployWithJsonArgs{
		PaymentAccount: request.PaymentAccount,
		DeployJson: request.DeployJson,
		Send: request.Send,
	}
	if request.Send {
		unitHash, err := s.wallet.UnitAssemble.CreateUnit(args)
		if err != nil {
			return nil, err
		}
		return &pb.DeployContractWithJsonResponse{UnitHash: unitHash}, nil
	}
	commission, err := s.wallet.UnitAssemble.CalculateCommission(args)
	if err != nil {
		return nil, err
	}
	return &pb.DeployContractWithJsonResponse{Commission: commission}, nil
}

// StartServer start gRPC server
func StartServer(wallet *platform.Wallet) {
	go startServer(wallet)
}

func startServer(wallet *platform.Wallet) {
	server := grpc.NewServer()
	pb.RegisterAccountServiceServer(server, &accountService{wallet: wallet})
	lis, err := net.Listen("tcp", port)
	if err != nil {
		fmt.Printf("grpc lisen failed %s\n", err)
	}
	err = server.Serve(lis)
	if err != nil {
		fmt.Printf("grpc serve failed %s\n", err)
	}
	log.Debug(" rpc server listen on : ", port)
}
