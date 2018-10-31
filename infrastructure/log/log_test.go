package log

import (
	"io"
	stdlog "log"
	"os"
	"testing"
	"time"
)

func TestDebug(t *testing.T) {
	file, err := os.OpenFile("test.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		stdlog.Panic(err)
	}
	var log *Logger
	writers := []io.Writer{}
	writers = append(writers, os.Stdout)
	writers = append(writers, file)
	fileAndStdoutWrite := io.MultiWriter(writers...)
	log = New(fileAndStdoutWrite, "", stdlog.Ldate|stdlog.Lmicroseconds, DebugLvl, file)
	log.Trace("===================")
	log.Debug("test debug")
	log.Info("test info")
	log.Warn("test warn")
	log.Error("test error")
	log.Fatal("test fatal")
	log.Trace("test trace")
	log.Tracef("===================")
	log.Debugf("test debug")
	log.Infof("test info")
	log.Warnf("test warn")
	log.Errorf("test error")
	log.Fatalf("test fatal")
	log.Tracef("test trace")
	file.Close()
	os.Remove("test.log")
}

func TestInfo(t *testing.T) {
	file, err := os.OpenFile(".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		stdlog.Panic(err)
	}
	var log *Logger
	writers := []io.Writer{}
	writers = append(writers, os.Stdout)
	writers = append(writers, file)
	fileAndStdoutWrite := io.MultiWriter(writers...)
	log = New(fileAndStdoutWrite, "", stdlog.Ldate|stdlog.Lmicroseconds, InfoLvl, file)
	log.Trace("===================")
	log.Debug("test debug")
	log.Info("test info")
	log.Warn("test warn")
	log.Error("test error")
	log.Fatal("test fatal")
	log.Trace("test trace")
	log.Tracef("===================")
	log.Debugf("test debug")
	log.Infof("test info")
	log.Warnf("test warn")
	log.Errorf("test error")
	log.Fatalf("test fatal")
	log.Tracef("test trace")
	file.Close()
	os.Remove("test.log")
}

func TestWarn(t *testing.T) {
	file, err := os.OpenFile("test.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		stdlog.Panic(err)
	}
	var log *Logger
	writers := []io.Writer{}
	writers = append(writers, os.Stdout)
	writers = append(writers, file)
	fileAndStdoutWrite := io.MultiWriter(writers...)
	log = New(fileAndStdoutWrite, "", stdlog.Ldate|stdlog.Lmicroseconds, WarnLvl, file)
	log.Trace("===================")
	log.Debug("test debug")
	log.Info("test info")
	log.Warn("test warn")
	log.Error("test error")
	log.Fatal("test fatal")
	log.Trace("test trace")
	file.Close()
	os.Remove("test.log")
}

func TestError(t *testing.T) {
	file, err := os.OpenFile("test.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		stdlog.Panic(err)
	}
	var log *Logger
	writers := []io.Writer{}
	writers = append(writers, os.Stdout)
	writers = append(writers, file)
	fileAndStdoutWrite := io.MultiWriter(writers...)
	log = New(fileAndStdoutWrite, "", stdlog.Ldate|stdlog.Lmicroseconds, WarnLvl, file)
	log.Trace("===================")
	log.Debug("test debug")
	log.Info("test info")
	log.Warn("test warn")
	log.Error("test error")
	log.Fatal("test fatal")
	log.Trace("test trace")
	file.Close()
	os.Remove("test.log")
}

func TestFatal(t *testing.T) {
	file, err := os.OpenFile("test.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		stdlog.Panic(err)
	}
	var log *Logger
	writers := []io.Writer{}
	writers = append(writers, os.Stdout)
	writers = append(writers, file)
	fileAndStdoutWrite := io.MultiWriter(writers...)
	log = New(fileAndStdoutWrite, "", stdlog.Ldate|stdlog.Lmicroseconds, FatalLvl, file)
	log.Trace("===================")
	log.Debug("test debug")
	log.Info("test info")
	log.Warn("test warn")
	log.Error("test error")
	log.Fatal("test fatal")
	log.Trace("test trace")
	file.Close()
	os.Remove("test.log")
}

func TestTrace(t *testing.T) {
	file, err := os.OpenFile("test.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		stdlog.Panic(err)
	}
	var log *Logger
	writers := []io.Writer{}
	writers = append(writers, os.Stdout)
	writers = append(writers, file)
	fileAndStdoutWrite := io.MultiWriter(writers...)
	log = New(fileAndStdoutWrite, "", stdlog.Ldate|stdlog.Lmicroseconds, TraceLvl, file)
	log.Trace("===================")
	log.Debug("test debug")
	log.Info("test info")
	log.Warn("test warn")
	log.Error("test error")
	log.Fatal("test fatal")
	log.Trace("test trace")
	file.Close()
	log.SetLogLevel(10)
	log.SetLogLevel(1)
	logLevelName := LevelName(1)
	log.Tracef("log level name: %v", logLevelName)
	os.Remove("test.log")
}

func TestInit1(t *testing.T) {
	Init(100, DebugLvl, Stdout, "test1.log")
	defer os.RemoveAll("test1.log")
	Trace("===================")
	Debug("test debug")
	Info("test info")
	Warn("test warn")
	Error("test error")
	Fatal("test fatal")
	Trace("test trace")
	Tracef("===================")
	Debugf("test debug")
	Infof("test info")
	Warnf("test warn")
	Errorf("test error")
	Fatalf("test fatal")
	Tracef("test trace")
	size, _ := getLogFileSize()
	Tracef("Log File Size: %v", size)
	Tracef("Get Max Log Change Interval: %v", getMaxLogChangeInterval())
	Tracef("Check if need new file: %v", checkIfNeedNewFile())
	closePrintLog()

}

func TestInit2(t *testing.T) {
	Init(100, -1, Stdout, "test2.log")
	closePrintLog()
	defer os.RemoveAll("test2.log")
}

func TestInit3(t *testing.T) {
	Init(100, 10, Stdout, "test3.log")
	closePrintLog()
	defer os.RemoveAll("test3.log")
}

func TestInit4(t *testing.T) {
	Init(100, 1)
	FileOpen("abc")
	closePrintLog()
	defer os.RemoveAll("abc")
}

func TestInit5(t *testing.T) {
	Init(1, DebugLvl, Stdout,"test4.log")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	defer os.RemoveAll("test4.log")

	go func() {
		for {
			Debugf("test")
		}
	}()

	out:
	for {
		select {
		case <-ticker.C:
			break out
		}
	}
	closePrintLog()
}
