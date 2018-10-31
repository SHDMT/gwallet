package proto

//go:generate protoc -I=./ ./wallet.proto --go_out=plugins=grpc:./
