//go:build !windows

package images

import "golang.org/x/sys/unix"

func diskFreeGB(dir string) (float64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return float64(st.Bavail) * float64(st.Bsize) / (1 << 30), nil
}
