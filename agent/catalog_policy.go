package agent

import (
	"context"

	"github.com/Autumn-27/artex/locale"
	"github.com/Autumn-27/norma/llm"
)

const catalogBlockedMessage = "Catalog-only tool operations were blocked by local host policy; no tagged tool was executed. Change the request before continuing."
const catalogHistoryMessage = "Local host policy could not safely resolve catalog history or tool authorization; execution was stopped."
const catalogResumeMessage = "Transcript resume failed; continuing with the SDK's fresh session."

type catalogPolicyError struct {
	message string
	cause   error
	usage   llm.Usage // Complete's SDK error path otherwise discards returned usage.
}

func (e *catalogPolicyError) Error() string { return e.message }
func (e *catalogPolicyError) Unwrap() error { return e.cause }

func catalogHistoryError(ctx context.Context, cause error) error {
	return &catalogPolicyError{message: locale.Text(locale.FromContext(ctx), catalogHistoryMessage), cause: cause}
}
