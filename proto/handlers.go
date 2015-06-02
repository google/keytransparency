package google_security_e2ekeys_v1

import (
	"encoding/json"
	"net/http"

	context "golang.org/x/net/context"
)

// TODO: I wish this could be code generated.
func GetUser_Handler(srv interface{}, ctx context.Context, w http.ResponseWriter, r *http.Request) {
	// Json -> Proto.
	// TODO: insert url params.
	in := new(GetUserRequest)
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&in)
	if err != nil {
		http.Error(w, "Error", http.StatusInternalServerError)
	}

	resp, err := srv.(E2EKeyProxyServer).GetUser(ctx, in)
	if err != nil {
		// TODO: Convert error into HTTP status code.
		http.Error(w, "Error", http.StatusInternalServerError)
		return
	}
	// proto -> json
	encoder := json.NewEncoder(w)
	encoder.Encode(resp)
}
