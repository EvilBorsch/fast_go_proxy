package main

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Repository struct {
	proxyCollection *mongo.Collection
}

func NewRepository() (Repository, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		return Repository{}, nil
	}
	proxyCollection := client.Database("local").Collection("proxy")
	return Repository{
		proxyCollection: proxyCollection,
	}, nil

}

func (r Repository) AddProxyInfo(ctx context.Context, info ProxyInfo) error {
	res, err := r.proxyCollection.InsertOne(ctx, info)
	if err != nil {
		return err
	}
	log.Info().Msgf("Добавил новую запись для проксей %s", res)
	return nil
}
