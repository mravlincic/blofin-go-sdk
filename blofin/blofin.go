package blofin

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

type Client struct {
	ApiKey     string
	ApiSecret  string
	Passphrase string
	BaseURL    string
	client     *http.Client
}

func NewClient(apiKey, apiSecret, passphrase, baseURL string) *Client {
	return &Client{
		ApiKey:     apiKey,
		ApiSecret:  apiSecret,
		Passphrase: passphrase,
		BaseURL:    baseURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) signRequest(path, method, nonce, timestamp, body string) string {
	prehash := path + method + timestamp + nonce + body
	mac := hmac.New(sha256.New, []byte(c.ApiSecret))
	mac.Write([]byte(prehash))
	hexStr := hex.EncodeToString(mac.Sum(nil))
	return base64.StdEncoding.EncodeToString([]byte(hexStr))
}

// Example response structure (simplified; expand as needed)
type BalanceResponse struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Details []struct {
			Currency  string `json:"currency"`
			Available string `json:"available"`
			Balance   string `json:"balance"`
			Equity    string `json:"equity"`
			Frozen    string `json:"frozen"`
		} `json:"details"`
		TotalEquity string `json:"totalEquity"`
		Ts          string `json:"ts"`
	} `json:"data"`
}

// Inside your blofin.Client implementation:
func (c *Client) GetBalance() (*BalanceResponse, error) {
	// Step 1: Setup
	path := "/api/v1/account/balance"
	method := "GET"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()
	body := "" // GET requests use empty body

	// Step 2: Generate signature
	signature := c.signRequest(path, method, nonce, timestamp, body)

	// Step 3: Build request
	req, err := http.NewRequest(method, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("ACCESS-KEY", c.ApiKey)
	req.Header.Set("ACCESS-SIGN", signature)
	req.Header.Set("ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("ACCESS-NONCE", nonce)
	req.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)

	// Step 4: Make HTTP call
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Step 5: Read/parse
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Unmarshal to struct
	var br BalanceResponse
	if err := json.Unmarshal(respBytes, &br); err != nil {
		return nil, err
	}
	return &br, nil
}

type Position struct {
	PositionID         string `json:"positionId"`
	InstID             string `json:"instId"`
	InstType           string `json:"instType"`
	MarginMode         string `json:"marginMode"`
	PositionSide       string `json:"positionSide"`
	ADL                string `json:"adl"`
	Positions          string `json:"positions"`
	AvailablePositions string `json:"availablePositions"`
	AveragePrice       string `json:"averagePrice"`
	Margin             string `json:"margin,omitempty"`        // Not always present
	InitialMargin      string `json:"initialMargin,omitempty"` // For cross margin only
	MarkPrice          string `json:"markPrice"`
	MarginRatio        string `json:"marginRatio"`
	LiquidationPrice   string `json:"liquidationPrice"`
	UnrealizedPnl      string `json:"unrealizedPnl"`
	UnrealizedPnlRatio string `json:"unrealizedPnlRatio"`
	MaintenanceMargin  string `json:"maintenanceMargin"`
	CreateTime         string `json:"createTime"`
	UpdateTime         string `json:"updateTime"`
	Leverage           string `json:"leverage"`
}

type PositionsResponse struct {
	Code string     `json:"code"`
	Msg  string     `json:"msg"`
	Data []Position `json:"data"`
}

// GetPositions fetches position info with optional instId parameter.
// Pass empty string for instId to fetch all positions.
func (c *Client) GetPositions(instId string) (*PositionsResponse, error) {
	basePath := "/api/v1/account/positions"
	var path string

	if instId != "" {
		// Add query param ?instId=BTC-USDT
		v := url.Values{}
		v.Set("instId", instId)
		path = fmt.Sprintf("%s?%s", basePath, v.Encode())
	} else {
		path = basePath
	}

	method := "GET"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()
	body := "" // GET has empty body

	signature := c.signRequest(path, method, nonce, timestamp, body)

	req, err := http.NewRequest(method, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}

	// Set required headers exactly as BloFin docs specify
	req.Header.Set("ACCESS-KEY", c.ApiKey)
	req.Header.Set("ACCESS-SIGN", signature)
	req.Header.Set("ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("ACCESS-NONCE", nonce)
	req.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var positionsResp PositionsResponse
	if err := json.Unmarshal(respBytes, &positionsResp); err != nil {
		return nil, err
	}

	if positionsResp.Code != "0" {
		return &positionsResp, fmt.Errorf("api error: %v", positionsResp)
	}

	return &positionsResp, nil
}

type MarginModeData struct {
	MarginMode string `json:"marginMode"`
}

type MarginModeResponse struct {
	Code string         `json:"code"`
	Msg  string         `json:"msg"`
	Data MarginModeData `json:"data"`
}

// GetMarginMode fetches the current margin mode of the account.
func (c *Client) GetMarginMode() (*MarginModeResponse, error) {
	path := "/api/v1/account/margin-mode"
	method := "GET"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()
	body := "" // GET request has empty body

	signature := c.signRequest(path, method, nonce, timestamp, body)

	req, err := http.NewRequest(method, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("ACCESS-KEY", c.ApiKey)
	req.Header.Set("ACCESS-SIGN", signature)
	req.Header.Set("ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("ACCESS-NONCE", nonce)
	req.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var marginResp MarginModeResponse
	if err := json.Unmarshal(respBytes, &marginResp); err != nil {
		return nil, err
	}

	if marginResp.Code != "0" {
		return &marginResp, fmt.Errorf("api error: %v", marginResp)
	}

	return &marginResp, nil
}

type OrderHistory struct {
	OrderID            string  `json:"orderId"`
	ClientOrderID      string  `json:"clientOrderId"`
	InstID             string  `json:"instId"`
	MarginMode         string  `json:"marginMode"`
	PositionSide       string  `json:"positionSide"`
	Side               string  `json:"side"`
	OrderType          string  `json:"orderType"`
	Price              string  `json:"price"`
	Size               string  `json:"size"`
	ReduceOnly         string  `json:"reduceOnly"`
	Leverage           string  `json:"leverage"`
	State              string  `json:"state"`
	FilledSize         string  `json:"filledSize"`
	PNL                string  `json:"pnl"`
	AveragePrice       string  `json:"averagePrice"`
	Fee                string  `json:"fee"`
	CreateTime         string  `json:"createTime"`
	UpdateTime         string  `json:"updateTime"`
	OrderCategory      string  `json:"orderCategory"`
	TPTriggerPrice     *string `json:"tpTriggerPrice"` // nullable
	TPOrderPrice       *string `json:"tpOrderPrice"`   // nullable
	SLTriggerPrice     *string `json:"slTriggerPrice"` // nullable
	SLOrderPrice       *string `json:"slOrderPrice"`   // nullable
	CancelSource       string  `json:"cancelSource"`
	CancelSourceReason string  `json:"cancelSourceReason"`
	AlgoClientOrderID  string  `json:"algoClientOrderId"`
	AlgoID             string  `json:"algoId"`
	BrokerID           string  `json:"brokerId"`
}

type OrdersHistoryResponse struct {
	Code string         `json:"code"`
	Msg  string         `json:"msg"`
	Data []OrderHistory `json:"data"`
}

// GetOrdersHistory fetches completed order history with optional filters.
// Pass empty strings ("") for parameters you don't want to specify.
func (c *Client) GetOrdersHistory(
	instId, orderType, state, after, before, begin, end, limit string,
) (*OrdersHistoryResponse, error) {
	basePath := "/api/v1/trade/orders-history"
	// Build query parameters
	v := url.Values{}
	if instId != "" {
		v.Set("instId", instId)
	}
	if orderType != "" {
		v.Set("orderType", orderType)
	}
	if state != "" {
		v.Set("state", state)
	}
	if after != "" {
		v.Set("after", after)
	}
	if before != "" {
		v.Set("before", before)
	}
	if begin != "" {
		v.Set("begin", begin)
	}
	if end != "" {
		v.Set("end", end)
	}
	if limit != "" {
		v.Set("limit", limit)
	}

	path := basePath
	if len(v) > 0 {
		path = path + "?" + v.Encode()
	}

	method := "GET"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()
	body := "" // GET request has empty body

	signature := c.signRequest(path, method, nonce, timestamp, body)

	req, err := http.NewRequest(method, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}

	// Set required headers per BloFin API docs
	req.Header.Set("ACCESS-KEY", c.ApiKey)
	req.Header.Set("ACCESS-SIGN", signature)
	req.Header.Set("ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("ACCESS-NONCE", nonce)
	req.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var orderResp OrdersHistoryResponse
	if err := json.Unmarshal(respBytes, &orderResp); err != nil {
		return nil, err
	}

	if orderResp.Code != "0" {
		return &orderResp, fmt.Errorf("api error: %v", orderResp)
	}

	return &orderResp, nil
}

type PositionModeData struct {
	PositionMode string `json:"positionMode"`
}

type PositionModeResponse struct {
	Code string           `json:"code"`
	Msg  string           `json:"msg"`
	Data PositionModeData `json:"data"`
}

// GetPositionMode retrieves the user's position mode (e.g. net_mode or long_short_mode)
func (c *Client) GetPositionMode() (*PositionModeResponse, error) {
	path := "/api/v1/account/position-mode"
	method := "GET"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()
	body := "" // GET requests have empty body

	signature := c.signRequest(path, method, nonce, timestamp, body)

	req, err := http.NewRequest(method, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("ACCESS-KEY", c.ApiKey)
	req.Header.Set("ACCESS-SIGN", signature)
	req.Header.Set("ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("ACCESS-NONCE", nonce)
	req.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var positionModeResp PositionModeResponse
	if err := json.Unmarshal(respBytes, &positionModeResp); err != nil {
		return nil, err
	}

	if positionModeResp.Code != "0" {
		return &positionModeResp, fmt.Errorf("api error: %v", positionModeResp)
	}

	return &positionModeResp, nil
}

type ActiveOrder struct {
	OrderID           string  `json:"orderId"`
	ClientOrderID     string  `json:"clientOrderId"`
	InstID            string  `json:"instId"`
	MarginMode        string  `json:"marginMode"`
	PositionSide      string  `json:"positionSide"`
	Side              string  `json:"side"`
	OrderType         string  `json:"orderType"`
	Price             string  `json:"price"`
	Size              string  `json:"size"`
	ReduceOnly        string  `json:"reduceOnly"`
	Leverage          string  `json:"leverage"`
	State             string  `json:"state"`
	FilledSize        string  `json:"filledSize"`
	FilledAmount      string  `json:"filled_amount"`
	AveragePrice      string  `json:"averagePrice"`
	Fee               string  `json:"fee"`
	PNL               string  `json:"pnl"`
	CreateTime        string  `json:"createTime"`
	UpdateTime        string  `json:"updateTime"`
	OrderCategory     string  `json:"orderCategory"`
	TPTriggerPrice    *string `json:"tpTriggerPrice"` // nullable
	TPOrderPrice      *string `json:"tpOrderPrice"`   // nullable
	SLTriggerPrice    *string `json:"slTriggerPrice"` // nullable
	SLOrderPrice      *string `json:"slOrderPrice"`   // nullable
	AlgoClientOrderID string  `json:"algoClientOrderId"`
	AlgoID            string  `json:"algoId"`
	BrokerID          string  `json:"brokerId"`
}

type ActiveOrdersResponse struct {
	Code string        `json:"code"`
	Msg  string        `json:"msg"`
	Data []ActiveOrder `json:"data"`
}

// GetActiveOrders fetches all incomplete (pending) orders with optional filters.
// Pass empty string "" for any filter you want to skip.
func (c *Client) GetActiveOrders(
	instId, orderType, state, after, before, limit string,
) (*ActiveOrdersResponse, error) {
	basePath := "/api/v1/trade/orders-pending"

	// Build query parameters
	v := url.Values{}
	if instId != "" {
		v.Set("instId", instId)
	}
	if orderType != "" {
		v.Set("orderType", orderType)
	}
	if state != "" {
		v.Set("state", state)
	}
	if after != "" && before != "" {
		// According to docs, before and after cannot be simultaneous
		return nil, fmt.Errorf("parameters 'after' and 'before' cannot be used simultaneously")
	}
	if after != "" {
		v.Set("after", after)
	}
	if before != "" {
		v.Set("before", before)
	}
	if limit != "" {
		v.Set("limit", limit)
	}

	path := basePath
	if len(v) > 0 {
		path = path + "?" + v.Encode()
	}

	method := "GET"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()
	body := "" // GET request has empty body

	signature := c.signRequest(path, method, nonce, timestamp, body)

	req, err := http.NewRequest(method, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("ACCESS-KEY", c.ApiKey)
	req.Header.Set("ACCESS-SIGN", signature)
	req.Header.Set("ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("ACCESS-NONCE", nonce)
	req.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var activeOrdersResp ActiveOrdersResponse
	if err := json.Unmarshal(respBytes, &activeOrdersResp); err != nil {
		return nil, err
	}

	if activeOrdersResp.Code != "0" {
		return &activeOrdersResp, fmt.Errorf("api error: %v", activeOrdersResp)
	}

	return &activeOrdersResp, nil
}

type ActiveTPSLOrder struct {
	TpslID         string  `json:"tpslId"`
	ClientOrderID  string  `json:"clientOrderId"`
	InstID         string  `json:"instId"`
	MarginMode     string  `json:"marginMode"`
	PositionSide   string  `json:"positionSide"`
	Side           string  `json:"side"`
	TpTriggerPrice *string `json:"tpTriggerPrice"` // nullable
	TpOrderPrice   *string `json:"tpOrderPrice"`   // nullable
	SlTriggerPrice *string `json:"slTriggerPrice"` // nullable
	SlOrderPrice   *string `json:"slOrderPrice"`   // nullable
	Size           string  `json:"size"`
	State          string  `json:"state"`
	Leverage       string  `json:"leverage"`
	ReduceOnly     string  `json:"reduceOnly"`
	ActualSize     *string `json:"actualSize"` // nullable
	CreateTime     string  `json:"createTime"`
	BrokerID       string  `json:"brokerId"`
}

type ActiveTPSLOrdersResponse struct {
	Code string            `json:"code"`
	Msg  string            `json:"msg"`
	Data []ActiveTPSLOrder `json:"data"`
}

// GetActiveTPSLOrders retrieves a list of untriggered TP/SL orders under the current account.
// Pass empty string "" for any filter you want to skip.
// Note: The before and after parameters cannot be used simultaneously.
func (c *Client) GetActiveTPSLOrders(
	instId, tpslId, clientOrderId, after, before, limit string,
) (*ActiveTPSLOrdersResponse, error) {
	basePath := "/api/v1/trade/orders-tpsl-pending"

	// Build query parameters
	v := url.Values{}
	if instId != "" {
		v.Set("instId", instId)
	}
	if tpslId != "" {
		v.Set("tpslId", tpslId)
	}
	if clientOrderId != "" {
		v.Set("clientOrderId", clientOrderId)
	}
	if after != "" && before != "" {
		// According to docs, before and after cannot be simultaneous
		return nil, fmt.Errorf("parameters 'after' and 'before' cannot be used simultaneously")
	}
	if after != "" {
		v.Set("after", after)
	}
	if before != "" {
		v.Set("before", before)
	}
	if limit != "" {
		v.Set("limit", limit)
	}

	path := basePath
	if len(v) > 0 {
		path = path + "?" + v.Encode()
	}

	method := "GET"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()
	body := "" // GET request has empty body

	signature := c.signRequest(path, method, nonce, timestamp, body)

	req, err := http.NewRequest(method, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("ACCESS-KEY", c.ApiKey)
	req.Header.Set("ACCESS-SIGN", signature)
	req.Header.Set("ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("ACCESS-NONCE", nonce)
	req.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var activeTPSLOrdersResp ActiveTPSLOrdersResponse
	if err := json.Unmarshal(respBytes, &activeTPSLOrdersResp); err != nil {
		return nil, err
	}

	if activeTPSLOrdersResp.Code != "0" {
		return &activeTPSLOrdersResp, fmt.Errorf("api error: %v", activeTPSLOrdersResp)
	}

	return &activeTPSLOrdersResp, nil
}

type CancelTPSLOrderRequest struct {
	InstID        string `json:"instId"`
	TpslID        string `json:"tpslId"`
	ClientOrderID string `json:"clientOrderId"`
}

type CancelTPSLOrdersRequest []CancelTPSLOrderRequest

type CancelTPSLOrderData struct {
	TpslID        string  `json:"tpslId"`
	ClientOrderID *string `json:"clientOrderId"` // nullable
	Code          string  `json:"code"`
	Msg           string  `json:"msg"`
}

type CancelTPSLOrdersResponse struct {
	Code string                `json:"code"`
	Msg  string                `json:"msg"`
	Data []CancelTPSLOrderData `json:"data"`
}

// CancelTPSLOrders cancels one or more TP/SL orders.
// Each cancel request should specify either tpslId or clientOrderId (or both).
// instId is optional but recommended for better performance.
func (c *Client) CancelTPSLOrders(orders CancelTPSLOrdersRequest) (*CancelTPSLOrdersResponse, error) {
	if len(orders) == 0 {
		return nil, fmt.Errorf("orders slice cannot be empty")
	}

	path := "/api/v1/trade/cancel-tpsl"
	method := "POST"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()

	bodyBytes, err := json.Marshal(orders)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}
	bodyStr := string(bodyBytes)

	signature := c.signRequest(path, method, nonce, timestamp, bodyStr)

	httpReq, err := http.NewRequest(method, c.BaseURL+path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("ACCESS-KEY", c.ApiKey)
	httpReq.Header.Set("ACCESS-SIGN", signature)
	httpReq.Header.Set("ACCESS-TIMESTAMP", timestamp)
	httpReq.Header.Set("ACCESS-NONCE", nonce)
	httpReq.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var cancelResp CancelTPSLOrdersResponse
	if err := json.Unmarshal(respBytes, &cancelResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if cancelResp.Code != "0" {
		return &cancelResp, fmt.Errorf("API error: %s", cancelResp.Msg)
	}

	return &cancelResp, nil
}

// CancelTPSLOrder is a convenience method to cancel a single TP/SL order.
// You can specify either tpslId or clientOrderId (or both).
// instId is optional but recommended for better performance.
func (c *Client) CancelTPSLOrder(instId, tpslId, clientOrderId string) (*CancelTPSLOrdersResponse, error) {
	if tpslId == "" && clientOrderId == "" {
		return nil, fmt.Errorf("either tpslId or clientOrderId must be provided")
	}

	orders := CancelTPSLOrdersRequest{
		{
			InstID:        instId,
			TpslID:        tpslId,
			ClientOrderID: clientOrderId,
		},
	}

	return c.CancelTPSLOrders(orders)
}

type Fill struct {
	InstID       string `json:"instId"`
	TradeID      string `json:"tradeId"`
	OrderID      string `json:"orderId"`
	FillPrice    string `json:"fillPrice"`
	FillSize     string `json:"fillSize"`
	FillPnl      string `json:"fillPnl"`
	PositionSide string `json:"positionSide"`
	Side         string `json:"side"`
	Fee          string `json:"fee"`
	Ts           string `json:"ts"`
	BrokerID     string `json:"brokerId"`
}

type FillsHistoryResponse struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
	Data []Fill `json:"data"`
}

// GetFillsHistory fetches recent filled trades with optional filters.
// Pass empty strings for parameters you want to omit.
func (c *Client) GetFillsHistory(
	instId, orderId, after, before, begin, end, limit string,
) (*FillsHistoryResponse, error) {
	basePath := "/api/v1/trade/fills-history"

	// Build query parameters
	v := url.Values{}
	if instId != "" {
		v.Set("instId", instId)
	}
	if orderId != "" {
		v.Set("orderId", orderId)
	}
	if after != "" && before != "" {
		return nil, fmt.Errorf("parameters 'after' and 'before' cannot be used simultaneously")
	}
	if after != "" {
		v.Set("after", after)
	}
	if before != "" {
		v.Set("before", before)
	}
	if begin != "" {
		v.Set("begin", begin)
	}
	if end != "" {
		v.Set("end", end)
	}
	if limit != "" {
		v.Set("limit", limit)
	}

	path := basePath
	if len(v) > 0 {
		path = path + "?" + v.Encode()
	}

	method := "GET"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()
	body := "" // GET request has empty body

	signature := c.signRequest(path, method, nonce, timestamp, body)

	req, err := http.NewRequest(method, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}

	// BloFin required headers
	req.Header.Set("ACCESS-KEY", c.ApiKey)
	req.Header.Set("ACCESS-SIGN", signature)
	req.Header.Set("ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("ACCESS-NONCE", nonce)
	req.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var fillsResp FillsHistoryResponse
	if err := json.Unmarshal(respBytes, &fillsResp); err != nil {
		return nil, err
	}

	if fillsResp.Code != "0" {
		return &fillsResp, fmt.Errorf("api error: %v", fillsResp)
	}

	return &fillsResp, nil
}

type Instrument struct {
	InstID         string `json:"instId"`
	BaseCurrency   string `json:"baseCurrency"`
	QuoteCurrency  string `json:"quoteCurrency"`
	ContractValue  string `json:"contractValue"`
	ListTime       string `json:"listTime"`
	ExpireTime     string `json:"expireTime"`
	MaxLeverage    string `json:"maxLeverage"`
	MinSize        string `json:"minSize"`
	LotSize        string `json:"lotSize"`
	TickSize       string `json:"tickSize"`
	InstType       string `json:"instType"`
	ContractType   string `json:"contractType"`
	MaxLimitSize   string `json:"maxLimitSize"`
	MaxMarketSize  string `json:"maxMarketSize"`
	State          string `json:"state"`
	SettleCurrency string `json:"settleCurrency"`
}

type InstrumentsResponse struct {
	Code string       `json:"code"`
	Msg  string       `json:"msg"`
	Data []Instrument `json:"data"`
}

// GetInstruments retrieves a list of instruments with open contracts.
// Pass empty string "" for instId to fetch all instruments.
func (c *Client) GetInstruments(instId string) (*InstrumentsResponse, error) {
	basePath := "/api/v1/market/instruments"

	// Build the query parameters
	v := url.Values{}
	if instId != "" {
		v.Set("instId", instId)
	}

	path := basePath
	if len(v) > 0 {
		path = path + "?" + v.Encode()
	}

	method := "GET"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()
	body := "" // GET requests have empty body

	signature := c.signRequest(path, method, nonce, timestamp, body)

	req, err := http.NewRequest(method, c.BaseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set required headers as per BloFin authentication scheme
	req.Header.Set("ACCESS-KEY", c.ApiKey)
	req.Header.Set("ACCESS-SIGN", signature)
	req.Header.Set("ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("ACCESS-NONCE", nonce)
	req.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var instrResp InstrumentsResponse
	if err := json.Unmarshal(respBytes, &instrResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if instrResp.Code != "0" {
		return &instrResp, fmt.Errorf("api error: %v", instrResp)
	}

	return &instrResp, nil
}

type Ticker struct {
	InstID         string `json:"instId"`
	Last           string `json:"last"`           // Last traded price
	LastSize       string `json:"lastSize"`       // Last traded size
	AskPrice       string `json:"askPrice"`       // Best ask price
	AskSize        string `json:"askSize"`        // Best ask size
	BidPrice       string `json:"bidPrice"`       // Best bid price
	BidSize        string `json:"bidSize"`        // Best bid size
	High24h        string `json:"high24h"`        // Highest price in 24h
	Open24h        string `json:"open24h"`        // Open price in 24h
	Low24h         string `json:"low24h"`         // Lowest price in 24h
	VolCurrency24h string `json:"volCurrency24h"` // 24h volume in base currency
	Vol24h         string `json:"vol24h"`         // 24h volume in contracts
	Ts             string `json:"ts"`             // Timestamp of ticker data in milliseconds
}

type TickersResponse struct {
	Code string   `json:"code"`
	Msg  string   `json:"msg"`
	Data []Ticker `json:"data"`
}

// GetTickers retrieves the latest tickers data for all instruments or a specific instrument if instId is provided.
// Pass empty string "" to fetch all tickers.
func (c *Client) GetTickers(instId string) (*TickersResponse, error) {
	basePath := "/api/v1/market/tickers"

	// Build query parameters
	v := url.Values{}
	if instId != "" {
		v.Set("instId", instId)
	}

	path := basePath
	if len(v) > 0 {
		path = path + "?" + v.Encode()
	}

	method := "GET"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10) // milliseconds
	nonce := uuid.NewString()
	body := "" // GET requests have empty body

	// Generate signature per BloFin requirements
	signature := c.signRequest(path, method, nonce, timestamp, body)

	req, err := http.NewRequest(method, c.BaseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set authentication headers required by BloFin API
	req.Header.Set("ACCESS-KEY", c.ApiKey)
	req.Header.Set("ACCESS-SIGN", signature)
	req.Header.Set("ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("ACCESS-NONCE", nonce)
	req.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var tickersResp TickersResponse
	if err := json.Unmarshal(respBytes, &tickersResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if tickersResp.Code != "0" {
		return &tickersResp, fmt.Errorf("api error: %v", tickersResp)
	}

	return &tickersResp, nil
}

type SetLeverageRequest struct {
	InstID       string `json:"instId"`                 // Required
	Leverage     string `json:"leverage"`               // Required
	MarginMode   string `json:"marginMode"`             // Required: "cross" or "isolated"
	PositionSide string `json:"positionSide,omitempty"` // Optional; required only if marginMode is isolated & long/short mode
}

type SetLeverageData struct {
	InstID       string `json:"instId"`
	Leverage     string `json:"leverage"`
	MarginMode   string `json:"marginMode"`
	PositionSide string `json:"positionSide"`
}

type SetLeverageResponse struct {
	Code string          `json:"code"`
	Msg  string          `json:"msg"`
	Data SetLeverageData `json:"data"`
}

// SetLeverage sets the leverage for a given instrument.
// positionSide is optional and required only if marginMode is "isolated" in hedge mode (long/short).
func (c *Client) SetLeverage(instID, leverage, marginMode, positionSide string) (*SetLeverageResponse, error) {
	path := "/api/v1/account/set-leverage"
	method := "POST"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10) // milliseconds
	nonce := uuid.NewString()

	reqBody := SetLeverageRequest{
		InstID:     instID,
		Leverage:   leverage,
		MarginMode: marginMode,
	}

	// Only include PositionSide if provided (needed for isolated margin hedge mode)
	if positionSide != "" {
		reqBody.PositionSide = positionSide
	}

	// Marshal the request body as JSON
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}
	bodyStr := string(bodyBytes)

	// Sign the request
	signature := c.signRequest(path, method, nonce, timestamp, bodyStr)

	req, err := http.NewRequest(method, c.BaseURL+path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set authentication headers per BloFin requirements
	req.Header.Set("ACCESS-KEY", c.ApiKey)
	req.Header.Set("ACCESS-SIGN", signature)
	req.Header.Set("ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("ACCESS-NONCE", nonce)
	req.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var leverageResp SetLeverageResponse
	if err := json.Unmarshal(respBytes, &leverageResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if leverageResp.Code != "0" {
		return &leverageResp, fmt.Errorf("API error: %v", leverageResp)
	}

	return &leverageResp, nil
}

type CancelBatchOrderRequest struct {
	InstID        string `json:"instId,omitempty"`
	OrderID       string `json:"orderId"`
	ClientOrderID string `json:"clientOrderId,omitempty"`
}

type CancelBatchOrderData struct {
	OrderID       string  `json:"orderId"`
	ClientOrderID *string `json:"clientOrderId"`
	Code          string  `json:"code,omitempty"`
	Msg           *string `json:"msg,omitempty"`
}

type CancelBatchOrderResponse struct {
	Code string                 `json:"code"`
	Msg  string                 `json:"msg"`
	Data []CancelBatchOrderData `json:"data"`
}

// CancelBatchOrders cancels multiple orders in a single request.
// Pass a slice of CancelBatchOrderRequest, one per cancel action.
func (c *Client) CancelBatchOrders(batchReqs []CancelBatchOrderRequest) (*CancelBatchOrderResponse, error) {
	path := "/api/v1/trade/cancel-batch-orders"
	method := "POST"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()

	// Marshal the request body as a JSON array.
	bodyBytes, err := json.Marshal(batchReqs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch cancel body: %w", err)
	}
	bodyStr := string(bodyBytes)

	signature := c.signRequest(path, method, nonce, timestamp, bodyStr)

	req, err := http.NewRequest(method, c.BaseURL+path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("ACCESS-KEY", c.ApiKey)
	req.Header.Set("ACCESS-SIGN", signature)
	req.Header.Set("ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("ACCESS-NONCE", nonce)
	req.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var batchResp CancelBatchOrderResponse
	if err := json.Unmarshal(respBytes, &batchResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if batchResp.Code != "0" {
		return &batchResp, fmt.Errorf("API error: %v", batchResp)
	}

	return &batchResp, nil
}

type CancelOrderRequest struct {
	OrderID       string `json:"orderId"`                 // required
	InstID        string `json:"instId,omitempty"`        // optional
	ClientOrderID string `json:"clientOrderId,omitempty"` // optional
}

type CancelOrderData struct {
	OrderID       string  `json:"orderId"`
	ClientOrderID *string `json:"clientOrderId"` // nullable
	Code          string  `json:"code"`
	Msg           *string `json:"msg"` // nullable
}

type CancelOrderResponse struct {
	Code string            `json:"code"`
	Msg  string            `json:"msg"`
	Data []CancelOrderData `json:"data"` // Change from struct to slice
}

// CancelOrder cancels an existing order by orderId.
// instId and clientOrderId are optional; pass "" if not used.
func (c *Client) CancelOrder(orderId, instId, clientOrderId string) (*CancelOrderResponse, error) {
	path := "/api/v1/trade/cancel-order"
	method := "POST"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()

	// Build request body
	reqBody := CancelOrderRequest{
		OrderID: orderId,
	}

	if instId != "" {
		reqBody.InstID = instId
	}
	if clientOrderId != "" {
		reqBody.ClientOrderID = clientOrderId
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	bodyStr := string(bodyBytes)

	signature := c.signRequest(path, method, nonce, timestamp, bodyStr)

	req, err := http.NewRequest(method, c.BaseURL+path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, err
	}

	req.Header.Set("ACCESS-KEY", c.ApiKey)
	req.Header.Set("ACCESS-SIGN", signature)
	req.Header.Set("ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("ACCESS-NONCE", nonce)
	req.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var cancelResp CancelOrderResponse
	if err := json.Unmarshal(respBytes, &cancelResp); err != nil {
		return nil, err
	}

	if cancelResp.Code != "0" {
		return &cancelResp, fmt.Errorf("api error: %v", cancelResp)
	}

	return &cancelResp, nil
}

type PlaceTPSLOrderRequest struct {
	InstID         string `json:"instId"`                   // required
	MarginMode     string `json:"marginMode"`               // required: "cross" or "isolated"
	PositionSide   string `json:"positionSide"`             // required: "net"(one-way) or "long"/"short"(hedge)
	Side           string `json:"side"`                     // required: "buy" or "sell"
	TPTriggerPrice string `json:"tpTriggerPrice"`           // required if setting TP
	TPOrderPrice   string `json:"tpOrderPrice,omitempty"`   // optional; must be set if tpTriggerPrice is set
	SLTriggerPrice string `json:"slTriggerPrice,omitempty"` // optional; must be set if slOrderPrice is set
	SLOrderPrice   string `json:"slOrderPrice,omitempty"`   // optional; must be set if slTriggerPrice is set
	Size           string `json:"size"`                     // required; quantity or "-1" for entire position
	ReduceOnly     string `json:"reduceOnly,omitempty"`     // optional; "true" or "false"; default "false"
	ClientOrderID  string `json:"clientOrderId,omitempty"`  // optional; up to 32 chars
	BrokerID       string `json:"brokerId,omitempty"`       // optional; up to 16 chars
}

type PlaceTPSLOrderData struct {
	TPSLID        string  `json:"tpslId"`
	ClientOrderID *string `json:"clientOrderId"` // nullable
	Code          string  `json:"code"`
	Msg           *string `json:"msg"` // nullable
}

type PlaceTPSLOrderResponse struct {
	Code string             `json:"code"`
	Msg  string             `json:"msg"`
	Data PlaceTPSLOrderData `json:"data"`
}

// PlaceTPSLOrder places a Take-Profit / Stop-Loss order.
// Required fields: instId, marginMode, positionSide, side, tpTriggerPrice, size.
// Optional fields: tpOrderPrice, slTriggerPrice, slOrderPrice, reduceOnly, clientOrderId, brokerId.
//
// Note: If you set tpTriggerPrice, you should also set tpOrderPrice (can be empty string).
// Similarly for slTriggerPrice and slOrderPrice.
func (c *Client) PlaceTPSLOrder(req PlaceTPSLOrderRequest) (*PlaceTPSLOrderResponse, error) {
	path := "/api/v1/trade/order-tpsl"
	method := "POST"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()

	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}
	bodyStr := string(bodyBytes)

	signature := c.signRequest(path, method, nonce, timestamp, bodyStr)

	httpReq, err := http.NewRequest(method, c.BaseURL+path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("ACCESS-KEY", c.ApiKey)
	httpReq.Header.Set("ACCESS-SIGN", signature)
	httpReq.Header.Set("ACCESS-TIMESTAMP", timestamp)
	httpReq.Header.Set("ACCESS-NONCE", nonce)
	httpReq.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var tpslResp PlaceTPSLOrderResponse
	if err := json.Unmarshal(respBytes, &tpslResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if tpslResp.Code != "0" {
		return &tpslResp, fmt.Errorf("API error: %v", tpslResp)
	}

	return &tpslResp, nil
}

type ClosePositionRequest struct {
	InstID        string `json:"instId"`                  // required
	MarginMode    string `json:"marginMode"`              // required: "cross" or "isolated"
	PositionSide  string `json:"positionSide"`            // required: "net", "long", or "short"
	ClientOrderID string `json:"clientOrderId,omitempty"` // optional
	BrokerID      string `json:"brokerId,omitempty"`      // optional
}

type ClosePositionData struct {
	InstID        string `json:"instId"`
	PositionSide  string `json:"positionSide"`
	ClientOrderID string `json:"clientOrderId"`
}

type ClosePositionResponse struct {
	Code string            `json:"code"`
	Msg  string            `json:"msg"`
	Data ClosePositionData `json:"data"`
}

// ClosePosition closes the position of an instrument via a market order.
// clientOrderId and brokerId are optional; pass "" if not used.
func (c *Client) ClosePosition(instId, marginMode, positionSide, clientOrderId, brokerId string) (*ClosePositionResponse, error) {
	path := "/api/v1/trade/close-position"
	method := "POST"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()

	reqBody := ClosePositionRequest{
		InstID:       instId,
		MarginMode:   marginMode,
		PositionSide: positionSide,
	}
	if clientOrderId != "" {
		reqBody.ClientOrderID = clientOrderId
	}
	if brokerId != "" {
		reqBody.BrokerID = brokerId
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}
	bodyStr := string(bodyBytes)

	signature := c.signRequest(path, method, nonce, timestamp, bodyStr)

	req, err := http.NewRequest(method, c.BaseURL+path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("ACCESS-KEY", c.ApiKey)
	req.Header.Set("ACCESS-SIGN", signature)
	req.Header.Set("ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("ACCESS-NONCE", nonce)
	req.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var closeResp ClosePositionResponse
	if err := json.Unmarshal(respBytes, &closeResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if closeResp.Code != "0" {
		return &closeResp, fmt.Errorf("API error: %v", closeResp)
	}

	return &closeResp, nil
}

type PlaceOrderRequest struct {
	InstID         string `json:"instId"`                   // required
	MarginMode     string `json:"marginMode"`               // required: "cross" or "isolated"
	PositionSide   string `json:"positionSide"`             // required: "net", "long", or "short"
	Side           string `json:"side"`                     // required: "buy" or "sell"
	OrderType      string `json:"orderType"`                // required: "market", "limit", "post_only", "fok", "ioc"
	Price          string `json:"price"`                    // required (not applicable to market orders)
	Size           string `json:"size"`                     // required
	ReduceOnly     string `json:"reduceOnly,omitempty"`     // optional: "true" or "false"
	ClientOrderID  string `json:"clientOrderId,omitempty"`  // optional: max 32 alphanumeric characters
	TpTriggerPrice string `json:"tpTriggerPrice,omitempty"` // optional: take-profit trigger price
	TpOrderPrice   string `json:"tpOrderPrice,omitempty"`   // optional: take-profit order price
	SlTriggerPrice string `json:"slTriggerPrice,omitempty"` // optional: stop-loss trigger price
	SlOrderPrice   string `json:"slOrderPrice,omitempty"`   // optional: stop-loss order price
	BrokerID       string `json:"brokerId,omitempty"`       // optional: max 16 alphanumeric characters
}

type PlaceOrderData struct {
	OrderID       string  `json:"orderId"`
	ClientOrderID *string `json:"clientOrderId"` // nullable
	Code          string  `json:"code"`
	Msg           string  `json:"msg"`
}

type PlaceOrderResponse struct {
	Code string           `json:"code"`
	Msg  string           `json:"msg"`
	Data []PlaceOrderData `json:"data"`
}

// PlaceOrder places a regular trading order.
// Required fields: instId, marginMode, positionSide, side, orderType, price, size.
// Optional fields: reduceOnly, clientOrderId, tpTriggerPrice, tpOrderPrice, slTriggerPrice, slOrderPrice, brokerId.
//
// Note: price is not applicable for market orders but still required in the request structure.
// For take-profit and stop-loss orders, if you fill in trigger price, you must also fill in order price.
// If order price is -1, the order will be executed at market price.
func (c *Client) PlaceOrder(req PlaceOrderRequest) (*PlaceOrderResponse, error) {
	path := "/api/v1/trade/order"
	method := "POST"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()

	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}
	bodyStr := string(bodyBytes)

	signature := c.signRequest(path, method, nonce, timestamp, bodyStr)

	httpReq, err := http.NewRequest(method, c.BaseURL+path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("ACCESS-KEY", c.ApiKey)
	httpReq.Header.Set("ACCESS-SIGN", signature)
	httpReq.Header.Set("ACCESS-TIMESTAMP", timestamp)
	httpReq.Header.Set("ACCESS-NONCE", nonce)
	httpReq.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var orderResp PlaceOrderResponse
	if err := json.Unmarshal(respBytes, &orderResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if orderResp.Code != "0" {
		return &orderResp, fmt.Errorf("API error: %v", orderResp)
	}

	return &orderResp, nil
}

// PlaceBatchOrdersRequest represents a slice of individual order requests
type PlaceBatchOrdersRequest []PlaceOrderRequest

type PlaceBatchOrderData struct {
	OrderID       string `json:"orderId"`
	ClientOrderID string `json:"clientOrderId"`
}

type PlaceBatchOrdersResponse struct {
	Code string                `json:"code"`
	Msg  string                `json:"msg"`
	Data []PlaceBatchOrderData `json:"data"`
}

// PlaceBatchOrders places multiple orders in a single API call.
// Each order in the slice should contain the same parameters as a single order:
// Required fields: instId, marginMode, positionSide, side, orderType, price, size.
// Optional fields: reduceOnly, clientOrderId, tpTriggerPrice, tpOrderPrice, slTriggerPrice, slOrderPrice, brokerId.
//
// Maximum 20 orders can be placed in a single batch request.
func (c *Client) PlaceBatchOrders(orders PlaceBatchOrdersRequest) (*PlaceBatchOrdersResponse, error) {
	if len(orders) == 0 {
		return nil, fmt.Errorf("orders slice cannot be empty")
	}

	if len(orders) > 20 {
		return nil, fmt.Errorf("maximum 20 orders allowed per batch request, got %d", len(orders))
	}

	path := "/api/v1/trade/batch-orders"
	method := "POST"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	nonce := uuid.NewString()

	bodyBytes, err := json.Marshal(orders)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}
	bodyStr := string(bodyBytes)

	signature := c.signRequest(path, method, nonce, timestamp, bodyStr)

	httpReq, err := http.NewRequest(method, c.BaseURL+path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("ACCESS-KEY", c.ApiKey)
	httpReq.Header.Set("ACCESS-SIGN", signature)
	httpReq.Header.Set("ACCESS-TIMESTAMP", timestamp)
	httpReq.Header.Set("ACCESS-NONCE", nonce)
	httpReq.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var batchResp PlaceBatchOrdersResponse
	if err := json.Unmarshal(respBytes, &batchResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if batchResp.Code != "0" {
		return &batchResp, fmt.Errorf("API error: %vs", batchResp)
	}

	return &batchResp, nil
}

type FundingRate struct {
	InstID      string `json:"instId"`
	FundingRate string `json:"fundingRate"`
	FundingTime string `json:"fundingTime"`
}

type FundingRateResponse struct {
	Code string        `json:"code"`
	Msg  string        `json:"msg"`
	Data []FundingRate `json:"data"`
}

// GetFundingRate retrieves funding rate data for all instruments or a specific instrument if instId is provided.
// Pass empty string "" to fetch funding rates for all instruments.
func (c *Client) GetFundingRate(instId string) (*FundingRateResponse, error) {
	basePath := "/api/v1/market/funding-rate"

	// Build query parameters
	v := url.Values{}
	if instId != "" {
		v.Set("instId", instId)
	}

	path := basePath
	if len(v) > 0 {
		path = path + "?" + v.Encode()
	}

	method := "GET"
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10) // milliseconds
	nonce := uuid.NewString()
	body := "" // GET requests have empty body

	// Generate signature per BloFin requirements
	signature := c.signRequest(path, method, nonce, timestamp, body)

	req, err := http.NewRequest(method, c.BaseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set authentication headers required by BloFin API
	req.Header.Set("ACCESS-KEY", c.ApiKey)
	req.Header.Set("ACCESS-SIGN", signature)
	req.Header.Set("ACCESS-TIMESTAMP", timestamp)
	req.Header.Set("ACCESS-NONCE", nonce)
	req.Header.Set("ACCESS-PASSPHRASE", c.Passphrase)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var fundingResp FundingRateResponse
	if err := json.Unmarshal(respBytes, &fundingResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if fundingResp.Code != "0" {
		return &fundingResp, fmt.Errorf("api error: %v", fundingResp)
	}

	return &fundingResp, nil
}

// WebSocket message types
type WSLoginRequest struct {
	Op   string      `json:"op"`
	Args []LoginArgs `json:"args"`
}

type LoginArgs struct {
	ApiKey     string `json:"apiKey"`
	Passphrase string `json:"passphrase"`
	Timestamp  string `json:"timestamp"`
	Sign       string `json:"sign"`
	Nonce      string `json:"nonce"`
}

type WSResponse struct {
	Event string      `json:"event"`
	Code  string      `json:"code"`
	Msg   string      `json:"msg"`
	Data  interface{} `json:"data,omitempty"`
}

type WSSubscribeRequest struct {
	Op   string                `json:"op"`
	Args []SubscriptionChannel `json:"args"`
}

type SubscriptionChannel struct {
	Channel string `json:"channel"`
	InstId  string `json:"instId,omitempty"`
}

// WebSocket client structure
type WSClient struct {
	ApiKey     string
	ApiSecret  string
	Passphrase string
	BaseURL    string
	conn       *websocket.Conn
	msgChan    chan []byte
	errChan    chan error
	closeChan  chan bool
	isAuth     bool
}

// NewWSClient creates a new WebSocket client
func NewWSClient(apiKey, apiSecret, passphrase, wsURL string) *WSClient {
	return &WSClient{
		ApiKey:     apiKey,
		ApiSecret:  apiSecret,
		Passphrase: passphrase,
		BaseURL:    wsURL,
		msgChan:    make(chan []byte, 1000),
		errChan:    make(chan error, 100),
		closeChan:  make(chan bool),
		isAuth:     false,
	}
}

// signWebSocketLogin generates signature for WebSocket authentication
func (ws *WSClient) signWebSocketLogin(timestamp, nonce string) string {
	// Fixed components for WebSocket auth as per documentation
	path := "/users/self/verify"
	method := "GET"

	// Create signature string: path + method + timestamp + nonce
	prehash := path + method + timestamp + nonce

	// Generate HMAC-SHA256
	mac := hmac.New(sha256.New, []byte(ws.ApiSecret))
	mac.Write([]byte(prehash))

	// Convert to hex and encode with Base64
	hexStr := hex.EncodeToString(mac.Sum(nil))
	return base64.StdEncoding.EncodeToString([]byte(hexStr))
}

// Connect establishes WebSocket connection and authenticates
func (ws *WSClient) Connect() error {
	// Establish WebSocket connection
	conn, _, err := websocket.DefaultDialer.Dial(ws.BaseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}
	ws.conn = conn

	// Start message handling goroutines
	go ws.readMessages()
	go ws.handlePing()

	// Authenticate
	if err := ws.login(); err != nil {
		ws.Close()
		return fmt.Errorf("authentication failed: %w", err)
	}

	return nil
}

// login performs WebSocket authentication
func (ws *WSClient) login() error {
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	nonce := uuid.NewString()
	signature := ws.signWebSocketLogin(timestamp, nonce)

	loginReq := WSLoginRequest{
		Op: "login",
		Args: []LoginArgs{{
			ApiKey:     ws.ApiKey,
			Passphrase: ws.Passphrase,
			Timestamp:  timestamp,
			Sign:       signature,
			Nonce:      nonce,
		}},
	}

	if err := ws.conn.WriteJSON(loginReq); err != nil {
		return fmt.Errorf("failed to send login request: %w", err)
	}

	// Wait for login response with timeout
	select {
	case msg := <-ws.msgChan:
		var resp WSResponse
		if err := json.Unmarshal(msg, &resp); err != nil {
			return fmt.Errorf("failed to parse login response: %w", err)
		}

		if resp.Event == "login" && resp.Code == "0" {
			ws.isAuth = true
			log.Println("WebSocket authentication successful")
			return nil
		} else {
			return fmt.Errorf("login failed: code=%s, msg=%s", resp.Code, resp.Msg)
		}

	case err := <-ws.errChan:
		return fmt.Errorf("login error: %w", err)

	case <-time.After(10 * time.Second):
		return fmt.Errorf("login timeout")
	}
}

// Subscribe subscribes to specified channels
func (ws *WSClient) Subscribe(channels []SubscriptionChannel) error {
	if !ws.isAuth {
		return fmt.Errorf("WebSocket not authenticated")
	}

	subReq := WSSubscribeRequest{
		Op:   "subscribe",
		Args: channels,
	}

	return ws.conn.WriteJSON(subReq)
}

// Unsubscribe unsubscribes from specified channels
func (ws *WSClient) Unsubscribe(channels []SubscriptionChannel) error {
	if !ws.isAuth {
		return fmt.Errorf("WebSocket not authenticated")
	}

	unsubReq := WSSubscribeRequest{
		Op:   "unsubscribe",
		Args: channels,
	}

	return ws.conn.WriteJSON(unsubReq)
}

// readMessages handles incoming WebSocket messages
func (ws *WSClient) readMessages() {
	defer close(ws.msgChan)

	for {
		select {
		case <-ws.closeChan:
			return
		default:
			_, message, err := ws.conn.ReadMessage()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					log.Println("WebSocket connection closed")
					return
				}
				ws.errChan <- err
				continue
			}

			// Send message to channel for processing
			select {
			case ws.msgChan <- message:
			default:
				log.Println("Message channel full, dropping message")
			}
		}
	}
}

// handlePing manages WebSocket heartbeat
func (ws *WSClient) handlePing() {
	ticker := time.NewTicker(25 * time.Second) // Send ping every 25 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ws.closeChan:
			return
		case <-ticker.C:
			if err := ws.conn.WriteMessage(websocket.PingMessage, []byte("ping")); err != nil {
				ws.errChan <- fmt.Errorf("failed to send ping: %w", err)
				return
			}
		}
	}
}

// GetMessageChan returns the message channel for reading incoming messages
func (ws *WSClient) GetMessageChan() <-chan []byte {
	return ws.msgChan
}

// GetErrorChan returns the error channel for reading errors
func (ws *WSClient) GetErrorChan() <-chan error {
	return ws.errChan
}

// IsAuthenticated returns authentication status
func (ws *WSClient) IsAuthenticated() bool {
	return ws.isAuth
}

// Close closes the WebSocket connection
func (ws *WSClient) Close() error {
	close(ws.closeChan)

	if ws.conn != nil {
		// Send close message
		err := ws.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		if err != nil {
			log.Printf("Error sending close message: %v", err)
		}

		// Close connection
		return ws.conn.Close()
	}

	return nil
}

// Helper methods for common subscriptions

// SubscribeTickers subscribes to ticker data
func (ws *WSClient) SubscribeTickers(instIds []string) error {
	channels := make([]SubscriptionChannel, len(instIds))
	for i, instId := range instIds {
		channels[i] = SubscriptionChannel{
			Channel: "tickers",
			InstId:  instId,
		}
	}
	return ws.Subscribe(channels)
}

// SubscribeOrderBooks subscribes to order book data
func (ws *WSClient) SubscribeOrderBooks(instIds []string) error {
	channels := make([]SubscriptionChannel, len(instIds))
	for i, instId := range instIds {
		channels[i] = SubscriptionChannel{
			Channel: "books",
			InstId:  instId,
		}
	}
	return ws.Subscribe(channels)
}

// SubscribeTrades subscribes to trade data
func (ws *WSClient) SubscribeTrades(instIds []string) error {
	channels := make([]SubscriptionChannel, len(instIds))
	for i, instId := range instIds {
		channels[i] = SubscriptionChannel{
			Channel: "trades",
			InstId:  instId,
		}
	}
	return ws.Subscribe(channels)
}

// SubscribeAccount subscribes to account updates (requires authentication)
func (ws *WSClient) SubscribeAccount() error {
	channels := []SubscriptionChannel{{
		Channel: "account",
	}}
	return ws.Subscribe(channels)
}

// SubscribePositions subscribes to position updates (requires authentication)
func (ws *WSClient) SubscribePositions() error {
	channels := []SubscriptionChannel{{
		Channel: "positions",
	}}
	return ws.Subscribe(channels)
}

// SubscribeOrders subscribes to order updates (requires authentication)
func (ws *WSClient) SubscribeOrders() error {
	channels := []SubscriptionChannel{{
		Channel: "orders",
	}}
	return ws.Subscribe(channels)
}
