package replace

import ()

// Replace defines mutations to simply replace the current map value with the
// contents of the mutation.
type Replace struct{}

func New() *Replace {
	return &Replace{}
}

// CheckMutation verifies that this is a valid mutation for this item.
func (r *Replace) CheckMutation(value, mutation []byte) error {
	return nil
}

// Mutate applies mutation to value
func (r *Replace) Mutate(value, mutation []byte) ([]byte, error) {
	return mutation, nil
}
