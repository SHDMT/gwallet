package utils

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

func appDataPath(goos, appName string) string {
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

// AppDataPath return the full path for application data
// Example:
//   POSIX (Linux/BSD): ~/.myapp
//   Mac OS: $HOME/Library/Application Support/Myapp
//   Windows: %LOCALAPPDATA%\Myapp
//   Plan 9: $home/myapp
func AppDataPath(appName string) string {
	return appDataPath(runtime.GOOS, appName)
}

// FileExists Checks if the specified file exists
func FileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// CopyFile copy specified file from 'src' to 'des'
func CopyFile(src, des string) (w int64, err error) {
	srcFile, err := os.Open(src)
	if err != nil {
		fmt.Println(err)
	}
	defer srcFile.Close()

	desFile, err := os.Create(des)
	if err != nil {
		fmt.Println(err)
	}
	defer desFile.Close()

	return io.Copy(desFile, srcFile)
}
