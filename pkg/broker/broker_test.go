package broker

import (
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
)

func TestNewBroker(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{"Valid Broker", "localhost:6379", false},
		{"Empty Address", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBroker(tt.address, "", "", "")
			if (err != nil) != tt.wantErr {
				t.Errorf("NewBroker() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBroker_Produce(t *testing.T) {
	db, mock := redismock.NewClientMock()
	broker := &Broker{redisClient: db}

	mock.ExpectPublish("test_topic", "test_message").SetVal(1)

	err := broker.Produce("test_topic", []byte("test_message"))
	if err != nil {
		t.Errorf("Broker.Produce() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestBroker_Consume(t *testing.T) {
	db, mock := redismock.NewClientMock()
	broker := &Broker{redisClient: db}

	mock.ExpectSubscribe("test_topic")
	pubsub := mock.NewPubSub()
	mock.ExpectPSubscribe("test_topic").SetVal(pubsub)

	go func() {
		time.Sleep(100 * time.Millisecond)
		pubsub.Publish("test_topic", "test_message")
	}()

	messageReceived := make(chan struct{})
	err := broker.Consume("test_topic", func(msg []byte) error {
		if string(msg) != "test_message" {
			t.Errorf("Broker.Consume() got = %v, want %v", string(msg), "test_message")
		}
		close(messageReceived)
		return nil
	})

	select {
	case <-messageReceived:
		// Message was received successfully
	case <-time.After(1 * time.Second):
		t.Error("Timed out waiting for message")
	}

	if err != nil {
		t.Errorf("Broker.Consume() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestBroker_Close(t *testing.T) {
	db, mock := redismock.NewClientMock()
	broker := &Broker{redisClient: db}

	mock.ExpectClose().SetVal(nil)

	err := broker.Close()
	if err != nil {
		t.Errorf("Broker.Close() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}
