package alerter

import (
	"log/slog"
	"sync"
	"time"

	"github.com/voltagebots/vigilo/internal/collector"
)

type queuedAlert struct {
	event   collector.Event
	afterFn func()
}

// DeliveryQueue bounds concurrent outbound alert work. A full queue drops the
// newest delivery attempt and increments the dispatcher's dropped counter.
type DeliveryQueue struct {
	dispatcher *Dispatcher
	queue      chan queuedAlert
	workers    sync.WaitGroup
	closeOnce  sync.Once
	mu         sync.Mutex
	closed     bool
}

func NewDeliveryQueue(dispatcher *Dispatcher, workers, capacity int) *DeliveryQueue {
	if workers < 1 {
		workers = 1
	}
	if capacity < 1 {
		capacity = 1
	}
	q := &DeliveryQueue{dispatcher: dispatcher, queue: make(chan queuedAlert, capacity)}
	q.workers.Add(workers)
	for range workers {
		go func() {
			defer q.workers.Done()
			for item := range q.queue {
				q.dispatcher.Fire(item.event)
				if item.afterFn != nil {
					item.afterFn()
				}
			}
		}()
	}
	return q
}

func (q *DeliveryQueue) Submit(event collector.Event, afterFn func()) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		q.dispatcher.recordQueueDrop()
		return false
	}
	select {
	case q.queue <- queuedAlert{event: event, afterFn: afterFn}:
		return true
	default:
		q.dispatcher.recordQueueDrop()
		slog.Error("alert delivery queue full; event dropped", "source", event.Source, "action", event.Action, "resource", event.Resource)
		return false
	}
}

// Close rejects later submissions and waits up to 30 seconds for delivery
// workers. Channel sends have their own deadlines; this final bound prevents a
// misbehaving custom channel from holding daemon shutdown forever.
func (q *DeliveryQueue) Close() bool {
	return q.closeWithin(30 * time.Second)
}

func (q *DeliveryQueue) closeWithin(timeout time.Duration) bool {
	q.closeOnce.Do(func() {
		q.mu.Lock()
		q.closed = true
		close(q.queue)
		q.mu.Unlock()
	})
	done := make(chan struct{})
	go func() {
		q.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		slog.Error("alert delivery workers did not stop before shutdown deadline")
		return false
	}
}
