package oidc

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// HttpClient Methods needed to make HTTP request.
type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// SendWithRetry Make an HTTP request, retrying up to so many times.
// NOTE: Response will be nil when the expected status code is not met, be
// careful to set the correct code, this function does not work if multiple HTTP
// status codes are acceptable.
//
// Also, you can have an error returned with a valid response. This is due to
// the fact that any errors caused by previous attempts are compiled into a
// single error and returned along with the valid response.
func SendWithRetry(
	httpClient HttpClient,
	method, url string,
	data []byte,
	headers http.Header,
	code,
	retries int,
) (*http.Response, error) {
	body := bytes.NewBuffer(data)

	req, e1 := http.NewRequest(method, url, body)
	if e1 != nil {
		return nil, fmt.Errorf(stderr.BuildRequest, e1.Error())
	}

	req.Header = headers
	var lastResponse *http.Response
	var errMessage string

	for attempt := 1; attempt <= retries; attempt++ {
		res, err := httpClient.Do(req)
		if err != nil {
			errMessage += fmt.Sprintf(stderr.RetryRequest, err.Error())
			continue
		}

		if res.StatusCode == code {
			lastResponse = res
			break
		}

		// condition where response is not the expected status code but err is
		// nil
		// We throw this back at the app to let the dev know they should handle
		// this particular case.
		resBody, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()

		errMessage += fmt.Sprintf(stderr.UnexpectedCode, attempt, url, res.StatusCode, string(resBody))

		res = nil
	}

	var lastErr error
	if errMessage != "" {
		lastErr = fmt.Errorf("%v", errMessage)
	}

	if lastResponse == nil {
		return nil, lastErr
	}

	return lastResponse, lastErr
}
