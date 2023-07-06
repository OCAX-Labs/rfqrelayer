package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OCAX-labs/rfqrelayer/common"
	cryptoocax "github.com/OCAX-labs/rfqrelayer/crypto/ocax"

	"github.com/OCAX-labs/rfqrelayer/core/mocks/chainmocks"
	"github.com/OCAX-labs/rfqrelayer/core/types"
	"github.com/labstack/echo/v4"
)

func TestHandlePostRFQRequest(t *testing.T) {
	// Initialize a new echo instance
	e := echo.New()
	// Initialize an instance of your Server type (replace with your actual initialization code)
	privateKey := cryptoocax.GeneratePrivateKey()

	mockChain := &chainmocks.ChainInterface{}

	txChan := make(chan *types.Transaction)
	defer close(txChan)
	s := NewServer(ServerConfig{PrivateKey: &privateKey}, mockChain, txChan)

	// Start a goroutine to read from the channel
	go func() {
		for tx := range txChan {
			// Here you can add assertions about the transaction
			// For example, check that it's not nil
			if tx == nil {
				t.Error("expected transaction to be not nil")
			}
		}
	}()

	// rest of your test code
	baseToken := types.Token{
		Symbol:   "ETH",
		Decimals: 18,
		Address:  common.HexToAddress("0x0d1d4e623D10F9FBA5Db95830F7d3839406C6AF2"),
	}

	quoteToken := types.Token{
		Symbol:   "DAI",
		Decimals: 18,
		Address:  common.HexToAddress("0x0d1d4e623D10F9FBA5Db95830F7d3839406C6AF2"),
	}

	signableData := types.SignableData{
		// Fill with sample data
		RequestorId:     "0x0d1d4e623D10F9FBA5Db95830F7d3839406C6AF2",
		BaseTokenAmount: big.NewInt(1000000000000000000),
		BaseToken:       &baseToken,
		QuoteToken:      &quoteToken,
		RFQDurationMs:   10_000,
	}

	// Prepare the request body
	body, _ := json.Marshal(RFQRequestBody{
		From: "0x0d1d4e623D10F9FBA5Db95830F7d3839406C6AF2",
		Data: &signableData,
	})
	req := httptest.NewRequest(http.MethodPost, "/rfqs", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	// Record the response
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Run the handler function
	if err := s.handlePostRFQRequest(c); err != nil {
		t.Fatalf("handlePostRFQRequest failed with %s", err.Error())
	}

	// Check the status code
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected status code %d but got %d", http.StatusAccepted, rec.Code)
	}

	// Check the response body (you may need to adjust this according to the actual expected response)
	var resp types.Transaction
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %s", err.Error())
	}

	fmt.Println("RESPONSE: ", resp)
	// Add more assertions based on your response structure
	// For example:
	// if resp.SomeField != someExpectedValue {
	//     t.Fatalf("expected SomeField to be %v but got %v", someExpectedValue, resp.SomeField)
	// }
}
