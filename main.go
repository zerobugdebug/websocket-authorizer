package main

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func handleRequest(ctx context.Context, event events.APIGatewayWebsocketProxyRequest) (events.APIGatewayV2CustomAuthorizerSimpleResponse, error) {
	// Extract the auth key from Sec-WebSocket-Protocol header
	authKey, ok := event.Headers["Sec-WebSocket-Protocol"]
	if !ok {
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{IsAuthorized: false}, nil
		//return events.APIGatewayCustomAuthorizerResponse{}, errors.New("missing Sec-WebSocket-Protocol header")
	}

	// If multiple protocols are specified, use the first one as the auth key
	authKey = strings.Split(authKey, ",")[0]
	authKey = strings.TrimSpace(authKey)

	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{IsAuthorized: false}, err
	}

	client := dynamodb.NewFromConfig(cfg)

	// Check if the auth key exists in DynamoDB
	tableName := os.Getenv("AUTH_TABLE_NAME")
	result, err := client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]types.AttributeValue{
			"key": &types.AttributeValueMemberS{Value: authKey},
		},
	})

	if err != nil {
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{IsAuthorized: false}, err
	}

	if result.Item == nil {
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{IsAuthorized: false}, errors.New("unauthorized")
	}

	// If auth key is valid, return an "Allow" policy
	return events.APIGatewayV2CustomAuthorizerSimpleResponse{IsAuthorized: true}, nil
}

func main() {
	lambda.Start(handleRequest)
}
