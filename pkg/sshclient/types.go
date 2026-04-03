package sshclient

type Options struct {
	Port             *int
	ConfigPath       string
	IdentityFiles    []string
	RawOptions       []string
	IgnoreKnownHosts bool
}

type UploadProgress struct {
	LocalPath  string
	RemotePath string
	Sent       int64
	Total      int64
	Done       bool
}

type UploadOptions struct {
	OnProgress func(UploadProgress)
}

type Session interface {
	Run(cmd string) ([]byte, error)
	Upload(localPath, remotePath string, opts UploadOptions) error
	Close() error
}
