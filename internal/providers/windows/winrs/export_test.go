package winrs

import "context"

// RunProgram runs any program the codec accepts, without Run's helperCall check: the real tests' stdinhash calls.
func (c *Client) RunProgram(ctx context.Context, call Call) (Result, error) { return c.runCall(ctx, call) }
