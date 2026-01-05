package pqcwrap

import (
	"encoding/json"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/types/known/structpb"
)

type Option func(*options)

func getOpts(opt ...wrapping.Option) (*options, error) {
	// First, separate out options into local and global
	opts := getDefaultOptions()
	var wrappingOptions []wrapping.Option
	var localOptions []OptionFunc
	for _, o := range opt {
		if o == nil {
			continue
		}
		iface := o()
		switch to := iface.(type) {
		case wrapping.OptionFunc:
			wrappingOptions = append(wrappingOptions, o)
		case OptionFunc:
			localOptions = append(localOptions, to)
		}
	}

	// Parse the global options
	var err error
	opts.Options, err = wrapping.GetOpts(wrappingOptions...)
	if err != nil {
		return nil, err
	}

	// Don't ever return blank options
	if opts.Options == nil {
		opts.Options = new(wrapping.Options)
	}
	if opts.WithConfigMap != nil {
		return nil, fmt.Errorf("WithConfigMap not supported")
	}

	// Now run the local options functions. This may overwrite options set by
	// the options above.
	for _, o := range localOptions {
		if o != nil {
			if err := o(&opts); err != nil {
				return nil, err
			}
		}
	}

	return &opts, nil
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

// options = how options are represented
type options struct {
	*wrapping.Options
	withKeyName    string
	withPublicKey  string
	withPrivateKey string
	withDebug      bool
	withKMSKey     bool
	withClientData *structpb.Struct
}

func getDefaultOptions() options {
	return options{}
}

// WithKeyName provides a way to set the passphrase on the hierarchy (if any)
func WithKeyName(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKeyName = with
			return nil
		})
	}
}

// WithPublicKey provides a way to chose the user agent
func WithPublicKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withPublicKey = with
			return nil
		})
	}
}

// WithPrivateKey provides a way to set the passphrase on the hierarchy (if any)
func WithPrivateKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withPrivateKey = with
			return nil
		})
	}
}

func WithDebug(with bool) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withDebug = with
			return nil
		})
	}
}

// WithKMSKey boolean flag to signal if the KMS based key should be used to decrypt
func WithKMSKey(with bool) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKMSKey = with
			return nil
		})
	}
}

// WithClientData unencrypted json string to attach to the encoded key.  These values are not used in encryption or validation.  For that use wrapping.WithAad().
func WithClientData(with string) wrapping.Option {
	if with == "" {
		return nil
	}
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			var dataMap map[string]interface{}
			err := json.Unmarshal([]byte(with), &dataMap)
			if err != nil {
				return err
			}
			protoStruct, err := structpb.NewStruct(dataMap)
			if err != nil {
				return err
			}
			o.withClientData = protoStruct
			return nil
		})
	}
}
