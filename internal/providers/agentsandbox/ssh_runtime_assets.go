package agentsandbox

import (
	"compress/gzip"
	"embed"
	"fmt"
	"io"
)

// Built reproducibly by scripts/build-agent-sandbox-runtime.sh. The payload is
// carried in the CLI: remote containers never need a package manager or network
// access to install the private runtime.
//
//go:embed assets/initializer-linux-amd64.gz
var sshInitializerAssets embed.FS

type sshInitializerReader struct {
	*gzip.Reader
	file io.Closer
}

func (r *sshInitializerReader) Close() error {
	gzipErr := r.Reader.Close()
	fileErr := r.file.Close()
	if gzipErr != nil {
		return gzipErr
	}
	return fileErr
}

func openSSHInitializer(architecture string) (io.ReadCloser, error) {
	if architecture != "x86_64" && architecture != "amd64" {
		return nil, fmt.Errorf("agent-sandbox-ssh static runtime does not support architecture %q; only amd64 (x86_64) is supported", architecture)
	}
	file, err := sshInitializerAssets.Open("assets/initializer-linux-amd64.gz")
	if err != nil {
		return nil, fmt.Errorf("agent-sandbox-ssh embedded amd64 initializer unavailable: %w", err)
	}
	reader, err := gzip.NewReader(file)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("agent-sandbox-ssh invalid embedded initializer: %w", err)
	}
	return &sshInitializerReader{Reader: reader, file: file}, nil
}
