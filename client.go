package upholdapi

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/brave-intl/bat-go/middleware"
	"github.com/brave-intl/bat-go/utils/altcurrency"
	"github.com/brave-intl/bat-go/utils/httpsignature"
	walletutils "github.com/brave-intl/bat-go/utils/wallet"
	"github.com/brave-intl/bat-go/wallet"
	uuid "github.com/satori/go.uuid"
	"github.com/shopspring/decimal"
)

// Client - This is the uphold Client interface.  Any Uphold client must
// implement these public methods
type Client interface {
	IsUserKYC(context.Context, string) (string, bool, error)
	Register(context.Context, string) error
	PrepareRegistration(context.Context, string) (string, error)
	SubmitRegistration(context.Context, string) error
	GetCardDetails(context.Context, string) (*CardDetails, error)
	VerifyTransaction(transactionB64 string) (*walletutils.TransactionInfo, error)
	VerifyAnonCardTransaction(transactionB64 string, requiredDestination string) (*walletutils.TransactionInfo, error)
	SubmitTransaction(transactionB64 string, confirm bool) (*walletutils.TransactionInfo, error)
	ConfirmTransaction(id string) (*walletutils.TransactionInfo, error)
	GetTransaction(id string) (*walletutils.TransactionInfo, error)
	ListTransactions(limit int, startDate time.Time) ([]walletutils.TransactionInfo, error)
	GetBalance(refresh bool) (*wallet.Balance, error)
	CreateCardAddress(network string) (string, error)
	FundWallet(destWallet *Wallet, amount decimal.Decimal) (decimal.Decimal, error)
}

type proxy func(*http.Request) (*url.URL, error)

type client struct {
	opts *Opts
	c    *http.Client
}

func (c *client) IsUserKYC(context.Context, string) (string, bool, error) {
	// get logger
	logger := getLogger(ctx)

	// in order to get the isMember status of the wallet, we need to start
	// a transaction of 0 BAT to the wallet "w" from "grant_wallet" but never commit
	gwPublicKey, err := hex.DecodeString(grantWalletPublicKey)
	if err != nil {
		logger.Error().Err(err).Msg("invalid system public key")
		return "", false, fmt.Errorf("invalid system public key: %w", err)
	}
	gwPrivateKey, err := hex.DecodeString(grantWalletPrivateKey)
	if err != nil {
		logger.Error().Err(err).Msg("invalid system private key")
		return "", false, fmt.Errorf("invalid system private key: %w", err)
	}

	grantWallet := Wallet{
		Info: walletutils.Info{
			ProviderID: grantWalletCardID,
			Provider:   "uphold",
			PublicKey:  grantWalletPublicKey,
		},
		PrivKey: ed25519.PrivateKey([]byte(gwPrivateKey)),
		PubKey:  httpsignature.Ed25519PubKey([]byte(gwPublicKey)),
	}

	// prepare a transaction by creating a payload
	transactionB64, err := grantWallet.PrepareTransaction(altcurrency.BAT, decimal.New(0, 1), destination, "")
	if err != nil {
		logger.Error().Err(err).Msg("failed to prepare transaction")
		return "", false, fmt.Errorf("failed to prepare transaction: %w", err)
	}

	// submit the transaction the payload
	uhResp, err := grantWallet.SubmitTransaction(transactionB64, false)
	if err != nil {
		logger.Error().Err(err).Msg("failed to submit transaction")
		return "", false, fmt.Errorf("failed to submit transaction: %w", err)
	}

	return uhResp.UserID, uhResp.KYC, nil
}

func (c *client) Register(context.Context, string) error {
	return errors.New("unimplemented")
}

func (c *client) PrepareRegistration(context.Context, string) (string, error) {
	return "", errors.New("unimplemented")
}

func (c *client) SubmitRegistration(context.Context, string) error {
	return errors.New("unimplemented")
}

// CardSettings contains settings corresponding to the Uphold card
type CardSettings struct {
	Protected bool `json:"protected,omitempty"`
}

// CardDetails contains details corresponding to the Uphold card
type CardDetails struct {
	AvailableBalance decimal.Decimal         `json:"available"`
	Balance          decimal.Decimal         `json:"balance"`
	Currency         altcurrency.AltCurrency `json:"currency"`
	ID               uuid.UUID               `json:"id"`
	Settings         CardSettings            `json:"settings"`
}

func (c *client) GetCardDetails(ctx context.Context, cardID string) (*CardDetails, error) {
	return nil, errors.New("unimplemented")
}
func (c *client) VerifyTransaction(transactionB64 string) (*walletutils.TransactionInfo, error) {
	return nil, errors.New("unimplemented")
}
func (c *client) VerifyAnonCardTransaction(transactionB64 string, requiredDestination string) (*walletutils.TransactionInfo, error) {
	return nil, errors.New("unimplemented")
}
func (c *client) SubmitTransaction(transactionB64 string, confirm bool) (*walletutils.TransactionInfo, error) {
	return nil, errors.New("unimplemented")
}
func (c *client) ConfirmTransaction(id string) (*walletutils.TransactionInfo, error) {
	return nil, errors.New("unimplemented")
}
func (c *client) GetTransaction(id string) (*walletutils.TransactionInfo, error) {
	return nil, errors.New("unimplemented")
}
func (c *client) ListTransactions(limit int, startDate time.Time) ([]walletutils.TransactionInfo, error) {
	return nil, errors.New("unimplemented")
}
func (c *client) GetBalance(refresh bool) (*wallet.Balance, error) {
	return nil, errors.New("unimplemented")
}
func (c *client) CreateCardAddress(network string) (string, error) {
	return "", errors.New("unimplemented")
}
func (c *client) FundWallet(destWallet *Wallet, amount decimal.Decimal) (decimal.Decimal, error) {
	return decimal.Zero, errors.New("unimplemented")
}

// Opts - This is the uphold Client Opts (options) which determine the
// configuration of the client.
type Opts struct {
	CertPinFingerprint        string
	BatSettlementAddress      string
	AnonCardSettlementAddress string
	UpholdSettlementAddress   string
	UpholdAccessToken         string
	UpholdEnvironment         string
	UpholdHTTPProxy           string
	UpholdBaseURI             string
}

// New - This will create a new Uphold Client configured with the Opts
// provided as a parameter.
func New(ctx context.Context, opts *Opts) (*Client, error) {
	if opts == nil {
		// invalid, we need to have opts to configure
		return nil, ErrInvalidOpts
	}
	if opts.BatSettlementAddress == "" {
		// invalid, we need a bat settlement address
		return nil, ErrInvalidOptsBatSettlement
	}
	// Default back to BAT_SETTLEMENT_ADDRESS
	if opts.AnonCardSettlementAddress == "" {
		opts.AnonCardSettlementAddress = opts.BatSettlementAddress
	}
	if opts.UpholdSettlementAddress == "" {
		opts.UpholdSettlementAddress = opts.BatSettlementAddress
	}

	var p proxy
	if opts.UpholdHTTPProxy != "" {
		// if there is a configured Proxy URL use create a proxy
		proxyURL, err := url.Parse(opts.UpholdHTTPProxy)
		if err != nil {
			return nil, ErrInvalidOptsProxyURL
		}
		p = http.ProxyURL(proxyURL)
	} else {
		p = nil
	}

	c = &http.Client{
		Timeout: time.Second * 60,
		Transport: middleware.InstrumentRoundTripper(
			&http.Transport{
				Proxy:          p,
				DialTLSContext: pindialer.MakeContextDialer(opts.CertPinFingerprint),
			}, "uphold"),
	}
	return client{
		opts:   Opts,
		client: c,
	}, nil
}
