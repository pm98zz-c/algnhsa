package algnhsa

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

type lambdaRequest struct {
	HTTPMethod                      string              `json:"httpMethod"`
	Path                            string              `json:"path"`
	QueryStringParameters           map[string]string   `json:"queryStringParameters,omitempty"`
	MultiValueQueryStringParameters map[string][]string `json:"multiValueQueryStringParameters,omitempty"`
	Headers                         map[string]string   `json:"headers,omitempty"`
	MultiValueHeaders               map[string][]string `json:"multiValueHeaders,omitempty"`
	IsBase64Encoded                 bool                `json:"isBase64Encoded"`
	Body                            string              `json:"body"`
	SourceIP                        string
	Context                         context.Context
}

func newLambdaRequest(ctx context.Context, payload []byte, opts *Options) (lambdaRequest, error) {
	switch opts.RequestType {
	case RequestTypeAPIGateway:
		return newAPIGatewayRequest(ctx, payload, opts)
	case RequestTypeALB:
		return newALBRequest(ctx, payload, opts)
	}

	// The request type wasn't specified.
	// Try to decode the payload as APIGatewayProxyRequest, if it fails try ALBTargetGroupRequest.
	req, err := newAPIGatewayRequest(ctx, payload, opts)
	if err != nil && err != errAPIGatewayUnexpectedRequest {
		return lambdaRequest{}, err
	}
	if err == nil {
		return req, nil
	}

	req, err = newALBRequest(ctx, payload, opts)
	if err != nil && err != errALBUnexpectedRequest {
		return lambdaRequest{}, err
	}
	if err == nil {
		return req, nil
	}

	return lambdaRequest{}, errors.New("neither APIGatewayProxyRequest nor ALBTargetGroupRequest received")
}

func newHTTPRequest(event lambdaRequest) (*http.Request, error) {
	decodedBody := []byte(event.Body)
	if event.IsBase64Encoded {
		base64Body, err := base64.StdEncoding.DecodeString(event.Body)
		if err != nil {
			return nil, err
		}
		decodedBody = base64Body
	}
	path := event.Path
	if len(event.MultiValueQueryStringParameters) > 0 {
		queryString := ""
		for q, l := range event.MultiValueQueryStringParameters {
			for _, v := range l {
				if queryString != "" {
					queryString += "&"
				}
				queryString += q + "=" + v
			}
		}
		path += "?" + queryString
	}
	httpRequest, err := http.NewRequest(
		strings.ToUpper(event.HTTPMethod),
		path,
		bytes.NewReader(decodedBody),
	)
	if err != nil {
		return nil, err
	}

	for k, values := range event.MultiValueHeaders {
		for _, value := range values {
			httpRequest.Header.Add(k, value)
		}
	}
	httpRequest.RequestURI = httpRequest.URL.RequestURI()
	return httpRequest.WithContext(event.Context), nil
}
