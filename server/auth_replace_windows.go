package server

import "golang.org/x/sys/windows"

// Windows does not support fsync on a directory opened by os.Open. The
// temporary file is already flushed; request write-through for its replacement.
func replaceAuthFile(source, destination string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
