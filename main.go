package main

import (
	"bufio"
	"fmt"
	"github.com/SHDMT/gwallet/infrastructure/config"
	"github.com/SHDMT/gwallet/infrastructure/log"
	"github.com/SHDMT/gwallet/infrastructure/utils"
	"github.com/SHDMT/gwallet/platform"
	"github.com/SHDMT/gwallet/platform/grpc"
	"github.com/SHDMT/gwallet/platform/walletseed"
	_ "github.com/SHDMT/gwallet/infrastructure/database/badgerdb"
	"os"
	"os/signal"
	"strings"
)

var shutdownRequestChannel = make(chan struct{})

// interruptChannel is used to receive SIGINT (Ctrl+C) signals.
var interruptChannel chan os.Signal

// addHandlerChannel is used to add an interrupt handler to the list of handlers
// to be invoked on SIGINT (Ctrl+C) signals.
var addHandlerChannel = make(chan func())

// interruptHandlersDone is closed after all interrupt handlers run the first
// time an interrupt is signaled.
var interruptHandlersDone = make(chan struct{})

var simulateInterruptChannel = make(chan struct{}, 1)

// signals defines the signals that are handled to do a clean shutdown.
// Conditional compilation is used to also include SIGTERM on Unix.
var signals = []os.Signal{os.Interrupt}

// mainInterruptHandler listens for SIGINT (Ctrl+C) signals on the
// interruptChannel and invokes the registered interruptCallbacks accordingly.
// It also listens for callback registration.  It must be run as a goroutine.
func mainInterruptHandler() {
	// interruptCallbacks is a list of callbacks to invoke when a
	// SIGINT (Ctrl+C) is received.
	var interruptCallbacks []func()
	invokeCallbacks := func() {
		// run handlers in LIFO order.
		for i := range interruptCallbacks {
			idx := len(interruptCallbacks) - 1 - i
			interruptCallbacks[idx]()
		}
		close(interruptHandlersDone)
	}

	for {
		select {
		case sig := <-interruptChannel:
			log.Infof("Received signal (%s).  Shutting down...", sig)
			invokeCallbacks()
			return
		case <-shutdownRequestChannel:
			log.Info("Shutdown requested.  Shutting down...")
			invokeCallbacks()
			return

		case <-simulateInterruptChannel:
			log.Info("Received shutdown request.  Shutting down...")
			invokeCallbacks()
			return

		case handler := <-addHandlerChannel:
			interruptCallbacks = append(interruptCallbacks, handler)
		}
	}
}

// addInterruptHandler adds a handler to call when a SIGINT (Ctrl+C) is
// received.
func addInterruptHandler(handler func()) {
	// Create the channel and start the main interrupt handler which invokes
	// all other callbacks and exits if not already done.
	if interruptChannel == nil {
		interruptChannel = make(chan os.Signal, 1)
		signal.Notify(interruptChannel, signals...)
		go mainInterruptHandler()
	}

	addHandlerChannel <- handler
}

func main() {
	var seed  = ""
	var pass  = ""
	if len(os.Args) > 1 {
		if strings.HasPrefix(os.Args[1], "--pass=") {
			pass = os.Args[1][7:]
			config.Parameters.Password = pass

		} else if strings.HasPrefix(os.Args[1], "--create") {
			if len(os.Args) > 2 {
				if strings.HasPrefix(os.Args[2], "--pass=") {
					pass = os.Args[2][7:]
					config.Parameters.Password = pass
				}

				if len(os.Args) > 3 {
					if strings.HasPrefix(os.Args[3], "--seed=") {
						seed = os.Args[3][7:]
					}
				}
			}
			seed = replace(seed)
			defaultAddress, err := platform.NewWalletTips(config.Parameters.
				DataDir, pass, seed)
			if err != nil {
				log.Error(" wallet create err: ", err)
				return
			}

			fmt.Print("=======result>>>>>>>")
			fmt.Print(defaultAddress)
			fmt.Println("<<<<<<<result=======")
			return
		} else if strings.HasPrefix(os.Args[1], "--generateseed") {
			wordList, err := walletseed.GeneratorWalletSeed()
			if err != nil {
				return
			}
			fmt.Print("=======result>>>>>>>")
			fmt.Print(strings.Join(wordList, " "))
			fmt.Println("<<<<<<<result=======")
			return
		} else if strings.HasPrefix(os.Args[1], "--validateseed=") {
			worldList := os.Args[1][15:]
			worldList = replace(worldList)
			_, err := walletseed.SeedValidate(worldList)
			if err != nil {
				fmt.Println("ERROR : ", err)
				return
			}
			fmt.Print("=======result>>>>>>>")
			fmt.Print(true)
			fmt.Println("<<<<<<<result=======")
			return
		}
	}

	exist, err := utils.FileExists(config.Parameters.DataDir)
	if err != nil {
		log.Error(" check wallet exist failed : ", err)
		return
	}
	if !exist {
		log.Error(" The wallet does not exist. " +
			"please run with the --create option to create it. ")
		return
	}

	var password = []byte{}
	var reader *bufio.Reader

	if pass == "" || len(pass) == 0 {
		for {
			reader = bufio.NewReader(os.Stdin)
			password, err = platform.InputPrompt(reader,
				"[ Please Enter wallet password ]", false)
			if err != nil {
				log.Errorf("[ Failed to enter password : %s, please try again ]",
					err.Error())
				continue
			}
			break
		}
	} else {
		password = []byte(pass)
	}

	wallet, err := platform.OpenWallet(config.Parameters.DataDir, password)
	if err != nil {
		log.Error(" can't open wallet ")
		return
	}

	log.Debug(" will start grpc server ...")
	grpc.StartServer(wallet)

	log.Debug(" will start wallet ...")
	wallet.Start()

	addInterruptHandler(func() {
		wallet.Stop()
		log.Debug("received a interrupt signal ... ")
	})

	<-interruptHandlersDone
}

func replace(seed string) string {
	seedBytes := []byte(seed)
	seedBytesLen := len(seedBytes)
	if seedBytesLen < 1 {
		return seed
	}

	for i := 0; i < seedBytesLen; i++ {
		if seedBytes[i] == 44 {
			seedBytes[i] = 32
		}
	}

	seed = string(seedBytes)
	return seed
}
