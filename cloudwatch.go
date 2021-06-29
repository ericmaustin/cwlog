package cwlog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

const (
	defaultCWLogsMaxEntries = 10000
	defaultCWLogsWaitTime   = time.Minute
)

// CWLogsWriter used as a writer for putting events into cloudwatch logs
type CWLogsWriter struct {
	groupName   *string // log group name
	streamName  *string // log stream to write to
	groupTags   map[string]string
	kmsKeyID    *string       // the KMS key to use
	waitTime    time.Duration // amount of time to wait until writing logs to cloudwatch
	maxEntries  int           // max number of cloud watch entries to save in each batch
	client      *cwl.Client
	seq         *string
	ctx         context.Context // context that closing will kill the worker
	mu          *sync.Mutex
	eventBuffer []types.InputLogEvent
	running     bool
	eventChan   chan types.InputLogEvent
	rejectHandler func(rejects *types.RejectedLogEventsInfo)
}

// CWLogsOpt is a option passed to NewCWLogWriter
type CWLogsOpt func(cw *CWLogsWriter)

// CWOptMaxEntries sets the log writer's max entries param
func CWOptMaxEntries(maxEntries int) CWLogsOpt {
	return func(cw *CWLogsWriter) {
		cw.maxEntries = maxEntries
	}
}

// CWOptWaitTime sets the log writer's max wait time
func CWOptWaitTime(waitTime time.Duration) CWLogsOpt {
	return func(cw *CWLogsWriter) {
		cw.waitTime = waitTime
	}
}

// CWOptKMSKeyID sets the log writer's kms KEY id
func CWOptKMSKeyID(kmsKeyID string) CWLogsOpt {
	return func(cw *CWLogsWriter) {
		cw.kmsKeyID = &kmsKeyID
	}
}

// CWOptGroupTags sets the log writer's  group tags
func CWOptGroupTags(tags map[string]string) CWLogsOpt {
	return func(cw *CWLogsWriter) {
		for name, tag := range tags {
			cw.groupTags[name] = tag
		}
	}
}

// CWOptEventChanBuffer sets the log writer's event input buffer
func CWOptEventChanBuffer(buffer int) CWLogsOpt {
	return func(cw *CWLogsWriter) {
		cw.eventChan = make(chan types.InputLogEvent, buffer)
	}
}

// CWOptRejectHandler sets the log writer's reject handler
func CWOptRejectHandler(h func(rejects *types.RejectedLogEventsInfo)) CWLogsOpt {
	return func(cw *CWLogsWriter) {
		cw.rejectHandler = h
	}
}

// NewCWLogWriter creates a new CWLogsWriter with given aws session, group name
// and stream name
func NewCWLogWriter(ctx context.Context, cnf aws.Config, groupName, streamName string, opts ...CWLogsOpt) *CWLogsWriter {
	cw := &CWLogsWriter{
		ctx:        ctx,
		groupName:  &groupName,
		streamName: &streamName,
		client:     cwl.NewFromConfig(cnf),
		mu:         &sync.Mutex{},
		waitTime:   defaultCWLogsWaitTime,
		maxEntries: defaultCWLogsMaxEntries,
	}

	// get the seq token
	cw.loadSeqToken()

	// apply opts
	for _, opt := range opts {
		opt(cw)
	}

	if cw.eventChan == nil {
		// no buffer provided in opts so set it to the max entries value
		cw.eventChan = make(chan types.InputLogEvent, cw.maxEntries)
	}

	// start the processor routine
	go cw.processor()

	return cw
}

// loadSeqToken gets the next seq token from cw
func (c *CWLogsWriter) loadSeqToken() {
	c.mu.Lock()
	defer c.mu.Unlock()

	limit := int32(1)
	// describe the event stream
	cwDescribeInput := &cwl.DescribeLogStreamsInput{
		LogGroupName:        c.groupName,
		LogStreamNamePrefix: c.streamName,
		Limit:               &limit,
	}
	streamDesc, err := c.client.DescribeLogStreams(c.ctx, cwDescribeInput)

	if err != nil {
		panic(err)
	}

	if len(streamDesc.LogStreams) < 1 {
		return
	}

	c.seq = streamDesc.LogStreams[0].UploadSequenceToken
}

// addEvent adds an event to the event buffer
func (c *CWLogsWriter) addEvent(event types.InputLogEvent) {
	c.mu.Lock()
	c.eventBuffer = append(c.eventBuffer, event)
	c.mu.Unlock()
}

// setRunning sets the flag if the processor running
func (c *CWLogsWriter) setRunning(running bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running = running
}

//processor runs in a go routine and handles pushing events to CW or adding events to the buffer
func (c *CWLogsWriter) processor() {
	c.setRunning(true)
	defer func() {
		c.setRunning(false)
		// put remaining events
		err := c.putEvents(0)
		if err != nil {
			panic(err)
		}
	}()

	// register a signal handler
	osSignal := make(chan os.Signal, 1)
	signal.Notify(osSignal, syscall.SIGTERM, syscall.SIGINT, os.Interrupt)

	go func() {
		// if we get an os signal then try to write all the events in the buffer
		s := <-osSignal
		fmt.Printf("got os signal %s, attempting to write buffered events to cloudwatch\n", s)

		if err := c.putEvents(0); err != nil {
			panic(err)
		}
	}()

	ticker := time.NewTicker(c.waitTime)

	var err error

	for {
		select {
		case <-ticker.C:
			// ticked off!
			err = c.putEvents(0)
			if err != nil {
				panic(err)
			}
		case e, ok := <-c.eventChan:
			if !ok {
				// channel closed
				return
			}

			c.addEvent(e)

			if len(c.eventBuffer) >= c.maxEntries {
				// we're at capacity to put the event and...
				if err = c.putEvents(0); err != nil {
					panic(err)
				}
				//... reset the ticker
				ticker = time.NewTicker(c.waitTime)
			}
		case <-c.ctx.Done():
			// DONE with this S@#%
			return
		}
	}
}

// cwPutLogEvents calls the PutLogEvents func and clears the buffer if successful
func (c *CWLogsWriter) cwPutLogEvents() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.eventBuffer) < 1 {
		// do nothing if eventBuffer is empty
		return nil
	}

	// sort the buffer by timestamp to prevent out of order issues
	sort.Slice(c.eventBuffer, func(i, j int) bool {
		return *c.eventBuffer[i].Timestamp < *c.eventBuffer[j].Timestamp
	})

	out, err := c.client.PutLogEvents(c.ctx, &cwl.PutLogEventsInput{
		LogEvents:     c.eventBuffer,
		LogGroupName:  c.groupName,
		LogStreamName: c.streamName,
		SequenceToken: c.seq,
	})

	if err == nil {
		c.seq = out.NextSequenceToken
		if out.RejectedLogEventsInfo != nil {
			if c.rejectHandler != nil {
				c.rejectHandler(out.RejectedLogEventsInfo)
			}
		}
		// clear the event buffer
		c.eventBuffer = []types.InputLogEvent{}

		return nil
	}

	return err
}

// putEvents puts the events from the buffer
func (c *CWLogsWriter) putEvents(attempt int) error {
	// check if seq is not set
	if c.seq == nil || len(*c.seq) < 1 {
		// get the sequence token from the stream
		c.loadSeqToken()
	}

	err := c.cwPutLogEvents()

	var (
		resourceNotFoundException *types.ResourceNotFoundException
		invalidSequenceTokenException *types.InvalidSequenceTokenException
	)

	if err != nil {
		switch {
		case errors.As(err, &resourceNotFoundException):
			// the group or stream was not found
			if err = c.createStream(0); err != nil {
				// error trying to create the stream
				return err
			}
		case errors.As(err, &invalidSequenceTokenException):
			c.loadSeqToken()
		default:
			// unknown error
			return err
		}
	}

	// try again
	attempt++
	if attempt < 3 {
		time.Sleep(time.Second * time.Duration(attempt))
		return c.putEvents(attempt)
	}

	return err
}

// createStream creates the cloudwatch stream
func (c *CWLogsWriter) createStream(attempt int) error {
	createStreamInput := &cwl.CreateLogStreamInput{
		LogGroupName:  c.groupName,
		LogStreamName: c.streamName,
	}

	// attempt to create the missing stream
	_, err := c.client.CreateLogStream(c.ctx, createStreamInput)

	if err == nil {
		return nil
	}

	var (
		resourceAlreadyExistsException *types.ResourceAlreadyExistsException
		resourceNotFoundException *types.ResourceNotFoundException
	)

	switch {
	case errors.As(err, &resourceAlreadyExistsException):
		// already exists!
		return nil
	case errors.As(err, &resourceNotFoundException):
		if err = c.createGroup(0); err != nil {
			return err
		}
	}

	attempt++
	if attempt < 3 {
		time.Sleep(time.Second * time.Duration(attempt))
		return c.createStream(attempt)
	}

	return err
}

// createGroup creates the cloudwatch group
func (c *CWLogsWriter) createGroup(attempt int) error {
	// attempt to create the missing cloudwatch log group
	_, err := c.client.CreateLogGroup(c.ctx, &cwl.CreateLogGroupInput{
		KmsKeyId:     c.kmsKeyID,
		LogGroupName: c.groupName,
		Tags:         c.groupTags,
	})

	if err == nil {
		return nil
	}

	var resourceAlreadyExistsException *types.ResourceAlreadyExistsException

	if errors.As(err, &resourceAlreadyExistsException) {
		// already exists!
		return nil
	}

	attempt++
	if attempt < 3 {
		time.Sleep(time.Second * time.Duration(attempt))
		return c.createGroup(attempt)
	}

	return err
}

// Write puts new event into CWLogsWriter buffer
func (c *CWLogsWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	ts := time.Now().UnixNano() / int64(time.Millisecond)
	// push the event into the event channel
	c.eventChan <- types.InputLogEvent{
		Message:   &msg,
		Timestamp: &ts,
	}

	return len(p), nil
}
