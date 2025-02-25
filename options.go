package pqcwrap

import (
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// getOpts iterates the inbound Options and returns a struct
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

	// Local options can be provided either via the WithConfigMap field
	// (for over the plugin barrier or embedding) or via local option functions
	// (for embedding). First pull from the option.
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "user_agent":
				opts.withUserAgent = v
			case KeyName:
				opts.withKeyName = v
			case PublicKey:
				opts.withPublicKey = v
			case PrivateKey:
				opts.withPrivateKey = v
			}
		}
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
	withUserAgent  string
	withKeyName    string
	withPublicKey  string
	withPrivateKey string
	withDebug      bool
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

// WithUserAgent provides a way to chose the user agent
func WithUserAgent(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withUserAgent = with
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
