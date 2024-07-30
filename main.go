package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	defaultTableName = "AUTH"
)

func handleRequest(ctx context.Context, event events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayV2CustomAuthorizerSimpleResponse, error) {
	fmt.Printf("event: %+v\n", event)
	// Extract the auth key from Sec-WebSocket-Protocol header
	authKey := event.AuthorizationToken
	if authKey == "" {
		fmt.Println("Sec-WebSocket-Protocol not found")
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{IsAuthorized: false}, nil
		//return events.APIGatewayCustomAuthorizerResponse{}, errors.New("missing Sec-WebSocket-Protocol header")
	}

	fmt.Printf("authKey before split: %v\n", authKey)
	// If multiple protocols are specified, use the first one as the auth key
	authKey = strings.Split(authKey, ",")[0]
	authKey = strings.TrimSpace(authKey)
	fmt.Printf("authKey: %v\n", authKey)
	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		fmt.Printf("Can't connect to DynamoDB: %s\n", err)
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{IsAuthorized: false}, err
	}

	client := dynamodb.NewFromConfig(cfg)

	// Check if the auth key exists in DynamoDB
	tableName := os.Getenv("AUTH_TABLE_NAME")
	if tableName == "" {
		tableName = defaultTableName
	}
	fmt.Printf("tableName: %v\n", tableName)

	result, err := client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]types.AttributeValue{
			"key": &types.AttributeValueMemberS{Value: authKey},
		},
	})

	if err != nil {
		fmt.Printf("Can't query DynamoDB: %s\n", err)
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{IsAuthorized: false}, err
	}

	if result.Item == nil {
		fmt.Printf("Can't find auth key: %s\n", err)
		return events.APIGatewayV2CustomAuthorizerSimpleResponse{IsAuthorized: false}, errors.New("unauthorized")
	}

	// If auth key is valid, return an "Allow" policy
	return events.APIGatewayV2CustomAuthorizerSimpleResponse{IsAuthorized: true}, nil
}

func main() {
	lambda.Start(handleRequest)
}
