package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/fatih/color"
	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows/registry"
)

func main() {
	processList, err := process.Processes()
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	for _, proc := range processList {
		name, _ := proc.Name()
		if strings.EqualFold(name, "HTTPDebuggerUI.exe") {
			if err := proc.Terminate(); err != nil {
				fmt.Println("Error:", err)
				os.Exit(1)
			}
			break
		}
	}

	color.NoColor = false
	log.SetFlags(0)

	k, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\MadeForNet\HTTPDebuggerPro`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		log.Fatalf("[%s] OpenKey: %s\n", color.RedString("-"), err)
	}
	defer k.Close()

	av, sn, key, err := crack(k)
	if err != nil {
		log.Fatalf("[%s] Crack: %s\n", color.RedString("-"), err)
	}

	fmt.Println("Crack Successful!")
	fmt.Println("----------------------------")
	fmt.Printf("[%s] App Version   : %s\n", color.GreenString("+"), av)
	fmt.Printf("[%s] Serial Number : %s\n", color.GreenString("+"), sn)
	fmt.Printf("[%s] Key           : %s\n", color.GreenString("+"), key)
	fmt.Println("----------------------------")
	fmt.Println("Please open HTTP Debugger Pro to apply changes.")

	for {
		if isProcessRunning("HTTPDebuggerUI.exe") {
			break
		}
		time.Sleep(time.Millisecond * 500)
	}

	fmt.Println("\n\n\nThank you for using this! Make sure to star it if you found it useful! c:")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()

}

func isProcessRunning(processName string) bool {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("tasklist")
	} else {
		cmd = exec.Command("ps", "aux")
	}

	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error checking processes:", err)
		return false
	}

	return strings.Contains(string(output), processName)
}

func getAppVersion(k registry.Key) (string, error) {
	version, _, err := k.GetStringValue("AppVer")
	if err != nil {
		return "", err
	}

	verRx := regexp.MustCompile(`(\d+.*)`)
	parsedVersion := verRx.FindString(version)
	parsedVersion = strings.ReplaceAll(parsedVersion, ".", "")

	return parsedVersion, nil
}

func getSerialNumber(appVersion string) string {
	var volumeInfo uint32
	volumeName := "C:\\"

	r, _, err := syscall.NewLazyDLL("kernel32.dll").NewProc("GetVolumeInformationW").Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(volumeName))),
		0, 0, uintptr(unsafe.Pointer(&volumeInfo)), 0, 0, 0, 0,
	)
	if r == 0 {
		log.Fatal(err)
	}

	serialNumber := uint32(mustAtoi(appVersion)) ^ ((^volumeInfo >> 1) + 0x2E0) ^ 0x590D4

	return strconv.Itoa(int(serialNumber))
}

func createKey() string {
	var keyBuilder strings.Builder
	for keyBuilder.Len() != 16 {
		v1, v2, v3 := generateRandomBytes()
		fmt.Fprintf(&keyBuilder, "%02X%02X%02X7C%02X%02X%02X%02X", v1, v2^0x7C, 0xFF^v1, v2, v3%255, v3%255^7, v1^(0xFF^(v3%255)))
	}

	return keyBuilder.String()
}

func generateRandomBytes() (byte, byte, byte) {
	b := make([]byte, 3)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}

	return b[0], b[1], b[2]
}

func writeKey(k registry.Key, sn string, key string) error {
	return k.SetStringValue("SN"+sn, key)
}

func crack(k registry.Key) (string, string, string, error) {
	av, err := getAppVersion(k)
	if err != nil {
		return "", "", "", err
	}

	sn := getSerialNumber(av)
	key := createKey()

	err = writeKey(k, sn, key)
	if err != nil {
		return "", "", "", err
	}

	return av, sn, key, nil
}

func mustAtoi(s string) int {
	value, err := strconv.Atoi(s)
	if err != nil {
		log.Fatal(err)
	}
	return value
}
