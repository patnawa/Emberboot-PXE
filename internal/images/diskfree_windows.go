//go:build windows

package images

import "golang.org/x/sys/windows"

func diskFreeGB(dir string) (float64, error) {
	var free, total, totalFree uint64
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return 0, err
	}
	return float64(free) / (1 << 30), nil
}
