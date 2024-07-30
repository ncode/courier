package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log/slog"
	"os"

	"github.com/redis/go-redis/v9"
)

var logger *slog.Logger

func init() {
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

type Broker struct {
	address     string
	cert        tls.Certificate
	caCert      *x509.CertPool
	redisClient *redis.Client
}

func NewBroker(address, certFile, keyFile, caFile string) (*Broker, error) {
	var cert tls.Certificate
	var caCertPool *x509.CertPool
	var err error

	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %w", err)
		}
	}

	if caFile != "" {
		caCert, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %w", err)
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr: address,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		},
	})

	return &Broker{
		address:     address,
		cert:        cert,
		caCert:      caCertPool,
		redisClient: redisClient,
	}, nil
}

func (b *Broker) Produce(topic string, message []byte) error {
	ctx := context.Background()
	err := b.redisClient.Publish(ctx, topic, message).Err()
	if err != nil {
		return fmt.Errorf("failed to publish message: %w", err)
	}
	logger.Info("Message produced", "topic", topic)
	return nil
}

func (b *Broker) Consume(topic string, callback func([]byte) error) error {
	ctx := context.Background()
	pubsub := b.redisClient.Subscribe(ctx, topic)
	defer pubsub.Close()

	ch := pubsub.Channel()

	logger.Info("Consumer started", "topic", topic)
	for msg := range ch {
		err := callback([]byte(msg.Payload))
		if err != nil {
			logger.Error("Callback error", "error", err)
		}
	}

	return nil
}

func (b *Broker) Close() error {
	return b.redisClient.Close()
}
