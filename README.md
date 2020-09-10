# Uphold API Client

This repository allows for API integration with Uphold for wallet and transaction processing.

## Create a New Client

In order to create a new client you must call the New function, and pass in a context
as well as the client options that you wish to set.  Below is an example:

```go
    var client = upholdapi.New(ctx, &upholdapi.Opts{
        CertPinFingerprint: "...",
        BatSettlementAddress: "...",
        AnonCardSettlementAddress: "...",
        UpholdSettlementAddress: "...",
        UpholdAccessToken: "...",
        UpholdEnvironment: "...",
        UpholdHTTPProxy: "...",
        UpholdBaseURI: "...",
    })
```

## Use the Client

Below is the interface definition of this upholdapi.Client:

```go
type Client interface {
	IsUserKYC(context.Context, string) (string, bool, error)
	Register(context.Context, string) error
	PrepareRegistration(context.Context, string) (string, error)
	SubmitRegistration(context.Context, string) error
	GetCardDetails(context.Context, string) (*upholdapi.CardDetails, error)
}
```

