package age

import (
	"filippo.io/age"
)

// Types aliased from the real age package. The documentation is copied as-is from
// the real package to help users using fancy IDE's to see inline documentation.
type (
	// An Identity is passed to Decrypt to unwrap an opaque file key from a
	// recipient stanza. It can be for example a secret key like X25519Identity, a
	// plugin, or a custom implementation.
	//
	// Unwrap must return an error wrapping ErrIncorrectIdentity if none of the
	// recipient stanzas match the identity, any other error will be considered
	// fatal.
	//
	// Most age API users won't need to interact with this directly, and should
	// instead pass Recipient implementations to Encrypt and Identity
	// implementations to Decrypt.
	Identity = age.Identity

	// NoIdentityMatchError is returned by Decrypt when none of the supplied
	// identities match the encrypted file.
	NoIdentityMatchError = age.NoIdentityMatchError

	// A Recipient is passed to Encrypt to wrap an opaque file key to one or more
	// recipient stanza(s). It can be for example a public key like X25519Recipient,
	// a plugin, or a custom implementation.
	//
	// Most age API users won't need to interact with this directly, and should
	// instead pass Recipient implementations to Encrypt and Identity
	// implementations to Decrypt.
	Recipient = age.Recipient

	// RecipientWithLabels can be optionally implemented by a Recipient, in which
	// case Encrypt will use WrapWithLabels instead of Wrap.
	//
	// Encrypt will succeed only if the labels returned by all the recipients
	// (assuming the empty set for those that don't implement RecipientWithLabels)
	// are the same.
	//
	// This can be used to ensure a recipient is only used with other recipients
	// with equivalent properties (for example by setting a "postquantum" label) or
	// to ensure a recipient is always used alone (by returning a random label, for
	// example to preserve its authentication properties).
	RecipientWithLabels = age.RecipientWithLabels

	// ScryptIdentity is a password-based identity.
	ScryptIdentity = age.ScryptIdentity

	// ScryptRecipient is a password-based recipient. Anyone with the password can
	// decrypt the message.
	//
	// If a ScryptRecipient is used, it must be the only recipient for the file: it
	// can't be mixed with other recipient types and can't be used multiple times
	// for the same file.
	//
	// Its use is not recommended for automated systems, which should prefer
	// X25519Recipient.
	ScryptRecipient = age.ScryptRecipient

	// A Stanza is a section of the age header that encapsulates the file key as
	// encrypted to a specific recipient.
	//
	// Most age API users won't need to interact with this directly, and should
	// instead pass Recipient implementations to Encrypt and Identity
	// implementations to Decrypt.
	Stanza = age.Stanza

	// X25519Identity is the standard age private key, which can decrypt messages
	// encrypted to the corresponding X25519Recipient.
	X25519Identity = age.X25519Identity

	// X25519Recipient is the standard age public key. Messages encrypted to this
	// recipient can be decrypted with the corresponding X25519Identity.
	//
	// This recipient is anonymous, in the sense that an attacker can't tell from
	// the message alone if it is encrypted to a certain recipient.
	X25519Recipient = age.X25519Recipient
)

// Functions and documentation from the real age package.
var (
	// ParseIdentities parses a file with one or more private key encodings, one per
	// line. Empty lines and lines starting with "#" are ignored.
	//
	// This is the same syntax as the private key files accepted by the CLI, except
	// the CLI also accepts SSH private keys, which are not recommended for the
	// average application.
	//
	// Currently, all returned values are of type *X25519Identity, but different
	// types might be returned in the future.
	ParseIdentities = age.ParseIdentities

	// ParseRecipients parses a file with one or more public key encodings, one per
	// line. Empty lines and lines starting with "#" are ignored.
	//
	// This is the same syntax as the recipients files accepted by the CLI, except
	// the CLI also accepts SSH recipients, which are not recommended for the
	// average application.
	//
	// Currently, all returned values are of type *X25519Recipient, but different
	// types might be returned in the future.
	ParseRecipients = age.ParseRecipients

	// NewScryptIdentity returns a new ScryptIdentity with the provided password.
	NewScryptIdentity = age.NewScryptIdentity

	// NewScryptRecipient returns a new ScryptRecipient with the provided password.
	NewScryptRecipient = age.NewScryptRecipient

	// GenerateX25519Identity randomly generates a new X25519Identity.
	GenerateX25519Identity = age.GenerateX25519Identity

	// ParseX25519Identity returns a new X25519Identity from a Bech32 private key
	// encoding with the "AGE-SECRET-KEY-1" prefix.
	ParseX25519Identity = age.ParseX25519Identity

	// ParseX25519Recipient returns a new X25519Recipient from a Bech32 public key
	// encoding with the "age1" prefix.
	ParseX25519Recipient = age.ParseX25519Recipient
)

// Exported errors from the real age package.
var (
	ErrIncorrectIdentity = age.ErrIncorrectIdentity
)
