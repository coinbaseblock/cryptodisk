package cache

// ReadExtent implements mount.ExtentStore via the cache.
func (w *WriteBack) ReadExtent(extent uint64) ([]byte, error) {
	return w.Read(extent)
}

// WriteExtent implements mount.ExtentStore via the cache.
func (w *WriteBack) WriteExtent(extent uint64, plain []byte) error {
	return w.Write(extent, plain)
}
