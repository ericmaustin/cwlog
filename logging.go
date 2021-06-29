// Package log is an extension to github.com/sirupsen/logrus that includes a cloudwatch logs logger
package cwlog

import (
	"io"

	"github.com/sirupsen/logrus"
)

const (
	// TRACE represents a Trace Level log event
	TRACE = logrus.TraceLevel
	// DEBUG represents a Debug level log event
	DEBUG = logrus.DebugLevel
	// INFO represents an info level log event
	INFO = logrus.InfoLevel
	// WARNING represents an warning level log event
	WARNING = logrus.WarnLevel
	// ERROR represents an error level log event
	ERROR = logrus.ErrorLevel
	// FATAL represents an fatal level log event, will kill the current process
	FATAL = logrus.FatalLevel
	// PANIC represents a panic level log event, will kill the current process
	PANIC = logrus.PanicLevel
)

// StandardLogger is used in place of a standard logger instance to ensure compatibility with any logger
type StandardLogger interface {
	// standard log methods

	Debug(...interface{})
	Info(...interface{})
	Warn(...interface{})
	Error(...interface{})
	Fatal(...interface{})
	Panic(...interface{})

	// format log methods
	Debugf(string, ...interface{})
	Infof(string, ...interface{})
	Warnf(string, ...interface{})
	Errorf(string, ...interface{})
	Fatalf(string, ...interface{})
	Panicf(string, ...interface{})
}

// Logrus allows passing of a logger or entry
type Logrus interface {
	StandardLogger
	WithFields(fields logrus.Fields) *logrus.Entry
	WithField(key string, value interface{}) *logrus.Entry
}

// Writer represents a single Logger handler that implements the logrus hook interface
type Writer struct {
	Writer    io.Writer
	LogLevels []logrus.Level
	Format    logrus.Formatter
}

// Levels returns the log levels for this Writer. If none were set, the default levels are passed
// which includes all levels
func (w *Writer) Levels() []logrus.Level {
	if w.LogLevels == nil || len(w.LogLevels) == 0 {
		w.LogLevels = []logrus.Level{TRACE, DEBUG, INFO, WARNING, ERROR, FATAL, PANIC}
	}
	return w.LogLevels
}

// Fire will format the text and then write to the writer
func (w *Writer) Fire(entry *logrus.Entry) error {
	if w.Format == nil {
		w.Format = &logrus.TextFormatter{
			FullTimestamp: true,
		}
	}
	bt, err := w.Format.Format(entry)
	if err != nil {
		return err
	}

	// write the formatted output
	_, err = w.Writer.Write(bt)

	return err
}

// AddLevels adds levels to this handler
func (w *Writer) AddLevels(levels ...logrus.Level) *Writer {
	if w.LogLevels == nil {
		w.LogLevels = levels
	} else {
		w.LogLevels = append(w.LogLevels, levels...)
	}

	return w
}

// NewWriter returns a new handler with the required writer and log level
func NewWriter(writer io.Writer, levels ...logrus.Level) *Writer {
	return &Writer{
		Writer:    writer,
		LogLevels: levels,
	}
}

// SetFormat sets the logging handler's formatter as a string
func (w *Writer) SetFormat(format logrus.Formatter) *Writer {
	w.Format = format
	return w
}

// New returns a new logrus logger and adds all the hooks
func New(hooks ...logrus.Hook) (logger *logrus.Logger) {
	logger = logrus.New()
	logger.SetReportCaller(true)

	// add all the hooks, if any as hooks to this log
	for _, writer := range hooks {
		logger.AddHook(writer)
	}

	return
}
