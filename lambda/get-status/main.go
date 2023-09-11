package main

import (
	"context"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/ksuid"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	invocationId := ksuid.New().String()
	log := log.With().
		Str("invocationId", invocationId).Logger()

	h := handler{&log}

	lambda.Start(h.handleRequest)
}

type handler struct {
	log *zerolog.Logger
}

func (h handler) handleRequest(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	user, ok := event.RequestContext.Authorizer.JWT.Claims["username"]
	if ok {
		h.log.Info().Msgf("Got user %s from claims", user)
	} else {
		h.log.Error().Msgf("Cannot get userid from JWT claims: %+v", event.RequestContext.Authorizer.JWT.Claims)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       "Internal Server Error",
		}, nil
	}

	return events.APIGatewayV2HTTPResponse{
		StatusCode: http.StatusOK,
	}, nil
}
