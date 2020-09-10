package upholdapi

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/brave-intl/bat-go/utils/altcurrency"
	appctx "github.com/brave-intl/bat-go/utils/context"
	"github.com/brave-intl/bat-go/utils/digest"
	"github.com/brave-intl/bat-go/utils/httpsignature"
	"github.com/brave-intl/bat-go/utils/logging"
	"github.com/brave-intl/bat-go/utils/requestutils"
	"github.com/brave-intl/bat-go/utils/validators"
	walletutils "github.com/brave-intl/bat-go/utils/wallet"
	"github.com/rs/zerolog"
	"github.com/shopspring/decimal"
)

// getLogger - helper to get logger from context
func getLogger(ctx context.Context) *zerolog.Logger {
	// get logger
	logger, err := appctx.GetLogger(ctx)
	if err != nil {
		// no logger, setup
		_, logger = logging.SetupLogger(ctx)
	}
	return logger
}

func newRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, upholdAPIBase+path, body)
	if err == nil {
		req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(accessToken+":X-OAuth-Basic")))
	}
	return req, err
}

func submit(logger *zerolog.Logger, req *http.Request) ([]byte, *http.Response, error) {
	req.Header.Add("content-type", "application/json")

	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		panic(err)
	}
	dump = authLogFilter.ReplaceAll(dump, []byte("Authorization: Basic <token>\n"))

	if logger != nil {
		logger.Debug().
			Str("path", "github.com/brave-intl/bat-go/wallet/provider/uphold").
			Str("type", "http.Request").
			Msg(string(dump))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, resp, err
	}

	headers := map[string][]string(resp.Header)
	jsonHeaders, err := json.MarshalIndent(headers, "", "    ")
	if err != nil {
		return nil, resp, err
	}

	body, err := requestutils.Read(resp.Body)
	if err != nil {
		return nil, resp, err
	}

	if logger != nil {
		logger.Debug().
			Str("path", "github.com/brave-intl/bat-go/wallet/provider/uphold").
			Str("type", "http.Response").
			Int("status", resp.StatusCode).
			Str("headers", string(jsonHeaders)).
			Msg(string(body))
	}

	if resp.StatusCode/100 != 2 {
		var uhErr upholdError
		if json.Unmarshal(body, &uhErr) != nil {
			return nil, resp, fmt.Errorf("Error %d, %s", resp.StatusCode, body)
		}
		return nil, resp, uhErr
	}
	return body, resp, nil
}

type createCardRequest struct {
	Label       string                   `json:"label"`
	AltCurrency *altcurrency.AltCurrency `json:"currency"`
	PublicKey   string                   `json:"publicKey"`
}

// sign registration for this wallet with Uphold with label
func (w *Wallet) signRegistration(label string) (*http.Request, error) {
	reqPayload := createCardRequest{Label: label, AltCurrency: w.Info.AltCurrency, PublicKey: w.PubKey.String()}
	payload, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, err
	}

	req, err := newRequest("POST", "/v0/me/cards", bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	var s httpsignature.Signature
	s.Algorithm = httpsignature.ED25519
	s.KeyID = "primary"
	s.Headers = []string{"digest"}

	err = s.Sign(w.PrivKey, crypto.Hash(0), req)
	return req, err
}

func (w *Wallet) decodeTransaction(transactionB64 string) (*transactionRequest, error) {
	b, err := base64.StdEncoding.DecodeString(transactionB64)
	if err != nil {
		return nil, err
	}

	var signedTx HTTPSignedRequest
	err = json.Unmarshal(b, &signedTx)
	if err != nil {
		return nil, err
	}

	_, err = govalidator.ValidateStruct(signedTx)
	if err != nil {
		return nil, err
	}

	digestHeader, exists := signedTx.Headers["digest"]
	if !exists {
		return nil, errors.New("A transaction signature must cover the request body via digest")
	}

	var digestInst digest.Instance
	err = digestInst.UnmarshalText([]byte(digestHeader))
	if err != nil {
		return nil, err
	}

	if !digestInst.Verify([]byte(signedTx.Body)) {
		return nil, errors.New("The digest header does not match the included body")
	}

	var req http.Request
	sig, err := signedTx.extract(&req)
	if err != nil {
		return nil, err
	}

	exists = false
	for _, header := range sig.Headers {
		if header == "digest" {
			exists = true
		}
	}
	if !exists {
		return nil, errors.New("A transaction signature must cover the request body via digest")
	}

	valid, err := sig.Verify(w.PubKey, crypto.Hash(0), &req)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, errors.New("The signature is invalid")
	}

	var transactionRecode transactionRequestRecode
	err = json.Unmarshal([]byte(signedTx.Body), &transactionRecode)
	if err != nil {
		return nil, err
	}

	if !govalidator.IsEmail(transactionRecode.Destination) {
		if !validators.IsUUID(transactionRecode.Destination) {
			if !validators.IsBTCAddress(transactionRecode.Destination) {
				if !validators.IsETHAddressNoChecksum(transactionRecode.Destination) {
					return nil, fmt.Errorf("%s is not a valid destination", transactionRecode.Destination)
				}
			}
		}
	}

	// NOTE we are effectively stuck using two different JSON parsers on the same data as our parser
	// is different than Uphold's. this has the unfortunate effect of opening us to attacks
	// that exploit differences between parsers. to mitigate this we will be extremely strict
	// in parsing, requiring that the remarshalled struct is equivalent. this means the order
	// of fields must be identical as well as numeric serialization. for encoding/json, note
	// that struct keys are serialized in the order they are defined

	remarshalledBody, err := json.Marshal(&transactionRecode)
	if err != nil {
		return nil, err
	}
	if string(remarshalledBody) != signedTx.Body {
		return nil, errors.New("The remarshalled body must be identical")
	}

	var transaction transactionRequest
	err = json.Unmarshal([]byte(signedTx.Body), &transaction)
	if err != nil {
		return nil, err
	}
	return &transaction, nil
}

type denomination struct {
	Amount   decimal.Decimal          `json:"amount"`
	Currency *altcurrency.AltCurrency `json:"currency"`
}

type transactionRequest struct {
	Denomination denomination `json:"denomination"`
	Destination  string       `json:"destination"`
	Message      string       `json:"message,omitempty"`
}

// denominationRecode type was used in this case to maintain trailing zeros so that the validation performed
// on the transaction being checked does not fail
// in order to maintain the zeros, the transaction can be checked using a string
// when using decimal.Decimal, and the transaction is re-serialized the trailing zeros are dropped
type denominationRecode struct {
	Amount   string                   `json:"amount"`
	Currency *altcurrency.AltCurrency `json:"currency"`
}

type transactionRequestRecode struct {
	Denomination denominationRecode `json:"denomination"`
	Destination  string             `json:"destination"`
	Message      string             `json:"message,omitempty"`
}

func (w *Wallet) signTransfer(altc altcurrency.AltCurrency, probi decimal.Decimal, destination string, message string) (*http.Request, error) {
	transferReq := transactionRequest{Denomination: denomination{Amount: altc.FromProbi(probi), Currency: &altc}, Destination: destination, Message: message}
	unsignedTransaction, err := json.Marshal(&transferReq)
	if err != nil {
		return nil, err
	}

	req, err := newRequest("POST", "/v0/me/cards/"+w.ProviderID+"/transactions?commit=true", bytes.NewBuffer(unsignedTransaction))
	if err != nil {
		return nil, err
	}

	var s httpsignature.Signature
	s.Algorithm = httpsignature.ED25519
	s.KeyID = "primary"
	s.Headers = []string{"digest"}

	err = s.Sign(w.PrivKey, crypto.Hash(0), req)
	return req, err
}

type upholdTransactionResponseDestinationNodeUser struct {
	ID string `json:"id"`
}

type upholdTransactionResponseDestinationNode struct {
	Type string                                       `json:"type"`
	ID   string                                       `json:"id"`
	User upholdTransactionResponseDestinationNodeUser `json:"user"`
}

type upholdTransactionResponseDestination struct {
	Type        string                                   `json:"type"`
	CardID      string                                   `json:"CardId,omitempty"`
	Node        upholdTransactionResponseDestinationNode `json:"node,omitempty"`
	Currency    string                                   `json:"currency"`
	Amount      decimal.Decimal                          `json:"amount"`
	ExchangeFee decimal.Decimal                          `json:"commission"`
	TransferFee decimal.Decimal                          `json:"fee"`
	IsMember    bool                                     `json:"isMember"`
}

type upholdTransactionResponseParams struct {
	TTL int64 `json:"ttl"`
}

type upholdTransactionResponse struct {
	Status       string                               `json:"status"`
	ID           string                               `json:"id"`
	Denomination denomination                         `json:"denomination"`
	Destination  upholdTransactionResponseDestination `json:"destination"`
	Origin       upholdTransactionResponseDestination `json:"origin"`
	Params       upholdTransactionResponseParams      `json:"params"`
	CreatedAt    string                               `json:"createdAt"`
	Message      string                               `json:"message"`
}

func (resp upholdTransactionResponse) ToTransactionInfo() *walletutils.TransactionInfo {
	var txInfo walletutils.TransactionInfo
	txInfo.Probi = resp.Denomination.Currency.ToProbi(resp.Denomination.Amount)
	{
		tmp := *resp.Denomination.Currency
		txInfo.AltCurrency = &tmp
	}
	destination := resp.Destination
	destinationNode := destination.Node
	txInfo.UserID = destinationNode.User.ID
	if len(destination.CardID) > 0 {
		txInfo.Destination = destination.CardID
	} else if len(destinationNode.ID) > 0 {
		txInfo.Destination = destinationNode.ID
	}

	if len(resp.Origin.CardID) > 0 {
		txInfo.Source = resp.Origin.CardID
	} else if len(resp.Origin.Node.ID) > 0 {
		txInfo.Source = resp.Origin.Node.ID
	}

	var err error
	txInfo.Time, err = time.Parse(dateFormat, resp.CreatedAt)
	if err != nil {
		log.Fatalf("%s is not a valid ISO 8601 datetime\n", resp.CreatedAt)
	}

	txInfo.DestCurrency = destination.Currency
	txInfo.DestAmount = destination.Amount
	txInfo.TransferFee = destination.TransferFee
	txInfo.ExchangeFee = destination.ExchangeFee
	txInfo.Status = resp.Status
	if txInfo.Status == "pending" {
		txInfo.ValidUntil = time.Now().UTC().Add(time.Duration(resp.Params.TTL) * time.Millisecond)
	}
	txInfo.ID = resp.ID
	txInfo.Note = resp.Message
	txInfo.KYC = destination.IsMember

	return &txInfo
}

type createCardAddressRequest struct {
	Network string `json:"network"`
}

type createCardAddressResponse struct {
	ID string `json:"id"`
}
