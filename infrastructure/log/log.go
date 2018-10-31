package log

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"os/user"
)

// const - Define color for different level message
const (
	Blue   = "0;34"
	Red    = "0;31"
	Green  = "0;32"
	Yellow = "0;33"
	Cyan   = "0;36"
	Pink   = "1;35"
)

// const - Define different level
const (
	DebugLvl = iota
	InfoLvl
	WarnLvl
	ErrorLvl
	FatalLvl
	TraceLvl
	MaxLvl
)

// const - Define time interval for log size checking
const (
	CheckTime = 100 //milliseconds
)

// ColorFmt - format output string
func ColorFmt(color, msg string) string {
	return fmt.Sprintf("\033[%sm%s\033[m", color, msg)
}

var (
	levels = map[int]string{
		DebugLvl: ColorFmt(Green, "[DEBUG]"),
		InfoLvl:  ColorFmt(Green, "[INFO ]"),
		WarnLvl:  ColorFmt(Yellow, "[WARN ]"),
		ErrorLvl: ColorFmt(Red, "[ERROR]"),
		FatalLvl: ColorFmt(Red, "[FATAL]"),
		TraceLvl: ColorFmt(Pink, "[TRACE]"),
	}
	// Stdout define the standard output for log
	Stdout = os.Stdout
)

// const
const (
	NamePrefix          = "LEVEL"
	CallPath           = 2
	DefaultMaxLogSize = 20
	ByteToMB           = 1000 * 1000
)

//var MaxLogSize int64
//var LogLevel int
var (
	maxLogSize int64
	logLevel   int
	logPath    string
	logWriter  []*os.File
)

// Logger is the basic data structure for log
type Logger struct {
	level   int
	logger  *log.Logger
	logFile *os.File
}

// Log is the global logger
var Log *Logger

// New - get a new Logger
func New(out io.Writer, prefix string, flag, level int, file *os.File) *Logger {
	return &Logger{
		level:   level,
		logger:  log.New(out, prefix, flag),
		logFile: file,
	}
}

// SetLogLevel - set log level
func (l *Logger) SetLogLevel(level int) error {
	if level > MaxLvl || level < 0 {
		return errors.New("invalid log level")
	}

	l.level = level
	return nil
}

// GetGID - get routine GID
func GetGID() uint64 {
	var buf [64]byte
	b := buf[:runtime.Stack(buf[:], false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

// LevelName - get log level name
func LevelName(level int) string {
	if name, ok := levels[level]; ok {
		return name
	}
	return NamePrefix + strconv.Itoa(level)
}

// Output - out put string for a log level
func (l *Logger) Output(level int, a ...interface{}) error {
	if level >= l.level {
		gid := GetGID()
		gidStr := strconv.FormatUint(gid, 10)

		a = append([]interface{}{LevelName(level), "GID",
			gidStr + ","}, a...)

		return l.logger.Output(CallPath, fmt.Sprintln(a...))
	}
	return nil
}

// Outputf - out put string with a specific format string for a log level
func (l *Logger) Outputf(level int, format string, v ...interface{}) error {
	if level >= l.level {
		gid := GetGID()
		v = append([]interface{}{LevelName(level), "GID",
			gid}, v...)

		return l.logger.Output(CallPath, fmt.Sprintf("%s %s %d, "+format+"\n", v...))
	}
	return nil
}

// Trace - trace level output of logger
func (l *Logger) Trace(a ...interface{}) {
	l.Output(TraceLvl, a...)
}

// Tracef - trace level output with format of logger
func (l *Logger) Tracef(format string, a ...interface{}) {
	l.Outputf(TraceLvl, format, a...)
}

// Debug - debug level output of logger
func (l *Logger) Debug(a ...interface{}) {
	l.Output(DebugLvl, a...)
}

// Debugf - debug level output format of logger
func (l *Logger) Debugf(format string, a ...interface{}) {
	l.Outputf(DebugLvl, format, a...)
}

// Info - info level output of logger
func (l *Logger) Info(a ...interface{}) {
	l.Output(InfoLvl, a...)
}

// Infof - info level output format of logger
func (l *Logger) Infof(format string, a ...interface{}) {
	l.Outputf(InfoLvl, format, a...)
}

// Warn - warn level output of logger
func (l *Logger) Warn(a ...interface{}) {
	l.Output(WarnLvl, a...)
}

// Warnf - warn level output format of logger
func (l *Logger) Warnf(format string, a ...interface{}) {
	l.Outputf(WarnLvl, format, a...)
}

// Error - error level output of logger
func (l *Logger) Error(a ...interface{}) {
	l.Output(ErrorLvl, a...)
}

// Errorf - error level output format of logger
func (l *Logger) Errorf(format string, a ...interface{}) {
	l.Outputf(ErrorLvl, format, a...)
}

// Fatal - fatal level output of logger
func (l *Logger) Fatal(a ...interface{}) {
	l.Output(FatalLvl, a...)
}

// Fatalf - fatal level output format of logger
func (l *Logger) Fatalf(format string, a ...interface{}) {
	l.Outputf(FatalLvl, format, a...)
}

// Trace - trace level output
func Trace(a ...interface{}) {
	if TraceLvl < Log.level {
		return
	}

	pc := make([]uintptr, 10)
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	file, line := f.FileLine(pc[0])
	fileName := filepath.Base(file)

	nameFull := f.Name()
	nameEnd := filepath.Ext(nameFull)
	funcName := strings.TrimPrefix(nameEnd, ".")

	a = append([]interface{}{funcName + "()", fileName + ":" + strconv.Itoa(line)}, a...)

	Log.Trace(a...)
}

// Tracef - trace level output format
func Tracef(format string, a ...interface{}) {
	if TraceLvl < Log.level {
		return
	}

	pc := make([]uintptr, 10)
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	file, line := f.FileLine(pc[0])
	fileName := filepath.Base(file)

	nameFull := f.Name()
	nameEnd := filepath.Ext(nameFull)
	funcName := strings.TrimPrefix(nameEnd, ".")

	a = append([]interface{}{funcName, fileName, line}, a...)

	Log.Tracef("%s() %s:%d "+format, a...)
}

// Debug - debug level output
func Debug(a ...interface{}) {
	if DebugLvl < Log.level {
		return
	}

	pc := make([]uintptr, 10)
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	file, line := f.FileLine(pc[0])
	fileName := filepath.Base(file)

	a = append([]interface{}{f.Name(), fileName + ":" + strconv.Itoa(line)}, a...)

	Log.Debug(a...)
}

// Debugf - debug level output format
func Debugf(format string, a ...interface{}) {
	if DebugLvl < Log.level {
		return
	}

	pc := make([]uintptr, 10)
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	file, line := f.FileLine(pc[0])
	fileName := filepath.Base(file)

	a = append([]interface{}{f.Name(), fileName, line}, a...)

	Log.Debugf("%s %s:%d "+format, a...)
}

// Info - info level output
func Info(a ...interface{}) {
	Log.Info(a...)
}

// Warn - warn level output
func Warn(a ...interface{}) {
	Log.Warn(a...)
}

// Error - error level output
func Error(a ...interface{}) {
	Log.Error(a...)
}

// Fatal - fatal level output
func Fatal(a ...interface{}) {
	Log.Fatal(a...)
}

// Infof - info level output forma
func Infof(format string, a ...interface{}) {
	Log.Infof(format, a...)
}

// Warnf - warn level output format
func Warnf(format string, a ...interface{}) {
	Log.Warnf(format, a...)
}

// Errorf - error level output format
func Errorf(format string, a ...interface{}) {
	Log.Errorf(format, a...)
}

// Fatalf - fatal level output format
func Fatalf(format string, a ...interface{}) {
	Log.Fatalf(format, a...)
}

// FileOpen - open the specific path file
func FileOpen(path string) (*os.File, error) {
	if fi, err := os.Stat(path); err == nil {
		if !fi.IsDir() {
			return nil, fmt.Errorf("open %s: not a directory", path)
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0766); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}

	var currentTime = time.Now().Format("2006-01-02_15.04.05")

	logfile, err := os.OpenFile(filepath.Join(logPath, currentTime+"_LOG.log"), os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return nil, err
	}
	return logfile, nil
}

// Init - log使用之前，必须执行Init函数
// log.Init()参数说明
// 第一个参数指定log文件大小，以M为单位，示例表示如果log文件超过100M，则自动切割，分割为多个100M的日志, 并对切割后的文件进行压缩
// 第二个参数设置日志的输出级别，log一共定义了DebugLvl、InfoLvl、WarnLvl、ErrorLvl、FatalLvl、TraceLvl 6个级别，对应整数分别是0、1、2、3、4、5，
//     设定了日志级别后，日志只输出大于或等于该级别的日志。
//     例如，设置日志级别为ErrorLvl，那么只会输出log.Error、log.Errorf、Log.Fatal、Log.Fatalf、log.Trace、log.Tracef的日志
//  第三个参数开始，是不定长度的参数，指定日志输出的文件目录、io。日志可以输出多个地方。注意：只支持输出到1个文件
//      log.Init(100, log.DebugLvl, log.Stdout) 该示例这里只把日志输出到标准输出，缺省logPath，则表示输出到当前目录
//      log.Init(100, log.DebugLvl, logPath, log.Stdout) 该示例这里只把日志输出到文件file和标准输出
func Init(maxSize int, level int, a ...interface{}) {
	maxLogSize = int64(maxSize)
	logLevel = level
	if logLevel >= MaxLvl {
		log.Printf("Log level exceeds defined max level, will set to trace level")
		logLevel = TraceLvl
	}
	if logLevel < DebugLvl {
		log.Printf("Log level is less than debug level, will set to debug level")
		logLevel = DebugLvl
	}
	var logFileCount int
	if len(a) > 0 {
		for _, o := range a {
			switch o.(type) {
			case string:
				logPath = o.(string)
				logFileCount++
				if logFileCount > 1 {
					log.Printf("log file number should not be more than one")
					os.Exit(1)
				}
			case *os.File:
				logWriter = append(logWriter, o.(*os.File))
			default:
				log.Printf("error: invalid log location")
				os.Exit(1)
			}
		}
	}
	startLog()
	go rotate()
}

func startLog() {
	writers := make([]io.Writer, 0)
	var logFile *os.File
	var err error
	if logPath == "" && len(logWriter) == 0 {
		writers = append(writers, ioutil.Discard)
	} else {
		if logPath != "" {
			logFile, err = FileOpen(logPath)
			if err != nil {
				log.Printf("error: open log file failed")
				os.Exit(1)
			}
			writers = append(writers, logFile)
		}
	}
	for _, writer := range logWriter {
		writers = append(writers, writer)
	}
	fileAndStdoutWrite := io.MultiWriter(writers...)
	Log = New(fileAndStdoutWrite, "", log.Ldate|log.Lmicroseconds, logLevel, logFile)
}

func rotate() {
	ticker := time.NewTicker(CheckTime * time.Millisecond)
	for {
		select {
		case <-ticker.C:
			needNewFile := checkIfNeedNewFile()
			if needNewFile {
				fileName := Log.logFile.Name()
				closePrintLog()
				startLog()
				go archiveFile(fileName)
			}
		}
	}
}

func archiveFile(fileName string) {
	log.Printf("archive log file: %v", fileName)
	zipFileName := fileName + ".zip"
	log.Printf("archive log file: %v", zipFileName)
	_, unzipFileName := filepath.Split(fileName)
	zipFile, err := os.Create(zipFileName)
	if err != nil {
		log.Printf("create zip file failed %v", err)
		return
	}
	zw := zip.NewWriter(zipFile)
	defer zw.Close()
	f, err := zw.Create(unzipFileName) // log file name after unzip
	if err != nil {
		log.Printf("%v", err)
		return
	}
	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Printf("read file error: %v", err)
		return
	}
	_, err = f.Write(content)
	if err != nil {
		log.Printf("%v", err)
		return
	}
	err = os.Remove(fileName)
	if err != nil {
		log.Printf("remove file failed: %v", err)
	}
}

func getLogFileSize() (int64, error) {
	f, e := Log.logFile.Stat()
	if e != nil {
		return 0, e
	}
	return f.Size(), nil
}

func getMaxLogChangeInterval() int64 {
	if maxLogSize != 0 {
		return (maxLogSize * ByteToMB)
	}
	maxLogSize = int64(DefaultMaxLogSize)
	return (maxLogSize * ByteToMB)
}

func checkIfNeedNewFile() bool {
	logFileSize, err := getLogFileSize()
	maxLogFileSize := getMaxLogChangeInterval()
	if err != nil {
		return false
	}
	if logFileSize > maxLogFileSize {
		return true
	}
	return false
}

func closePrintLog() error {
	var err error
	if Log.logFile != nil {
		err = Log.logFile.Close()
	}
	return err
}

func dataPath(goos, appName string) string {
	if appName == "" || appName == "." {
		return "."
	}

	// remove "prefix ."
	for {
		if strings.HasPrefix(appName, ".") {
			appName = appName[1:]
		} else {
			break
		}
	}

	var homeDir string
	currentUser, err := user.Current()
	if err == nil {
		homeDir = currentUser.HomeDir
	}

	if err != nil || homeDir == "" {
		homeDir = os.Getenv("HOME")
	}

	switch goos {
	// Attempt to use the LOCALAPPDATA or APPDATA environment variable on
	// Windows.
	case "windows":
		// Windows XP and before didn't have a LOCALAPPDATA, so fallback
		// to regular APPDATA when LOCALAPPDATA is not set.
		appData := os.Getenv("LOCALAPPDATA")
		if appData == "" {
			appData = os.Getenv("APPDATA")
		}

		if appData != "" {
			return filepath.Join(appData, appName)
		}

	case "darwin":
		if homeDir != "" {
			return filepath.Join(homeDir, "Library",
				"Application Support", appName)
		}

	case "plan9":
		if homeDir != "" {
			return filepath.Join(homeDir, appName)
		}

	default:
		if homeDir != "" {
			return filepath.Join(homeDir, "."+appName)
		}
	}

	// Fall back to the current directory if all else fails.
	return "."

}

func appDataPath(appName string) string {
	return dataPath(runtime.GOOS, appName)
}


var defaultMaxLogSize = 2000
var defalutLogLevel = DebugLvl
var defaultLogDir = filepath.Join(appDataPath("gwallet"), "log")
func init() {
	Init(defaultMaxLogSize, defalutLogLevel, defaultLogDir, Stdout)
}
