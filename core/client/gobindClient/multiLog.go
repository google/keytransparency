package gobindClient

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/keytransparency/core/client/kt"
)

var multiLogWriter = MultiIoWriter{[]io.Writer{os.Stderr}}

func init() {
	kt.Vlog = log.New(&multiLogWriter, "", log.LstdFlags)
}

// Local copy of io.Writer interface which can be implemented in Java. Used to redirect logs.
type LogWriter interface {
	Write(p []byte) (n int, err error)
}

type MultiIoWriter struct {
	writers []io.Writer
}

func (m *MultiIoWriter) Write(p []byte) (n int, err error) {
	if len(m.writers) == 0 {
		return 0, fmt.Errorf("Tried to use a MultiIoWriter which does not contain any writers")
	}
	multiError := ""
	minBytesWritten := len(p)
	log.Printf("There are %v writers", len(m.writers))
	for i, w := range m.writers {
		log.Printf("Write to %v made", i)
		n, err = w.Write(p)
		if err != nil {
			multiError = multiError + fmt.Sprintf("%v bytes written to %v: %v", n, w, err)
		}
		minBytesWritten = min(n, minBytesWritten)
	}

	return minBytesWritten, errors.New(multiError)
}

func (m *MultiIoWriter) AddWriter(w io.Writer) {
	if m.writers == nil {
		m.writers = []io.Writer{}
	}
	log.Printf("Added writer: %v", w)
	m.writers = append(m.writers, w)
	log.Printf("New size: %v", len(m.writers))
}

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}

func AddVerboseLogsDestination(writer LogWriter) {
	multiLogWriter.AddWriter(writer)
}
