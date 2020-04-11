package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

func requestHandler(w http.ResponseWriter, r *http.Request) {
	info := server.GetClientInfo()

	data, err := json.Marshal(info)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		e := fmt.Sprintf("Error on unmarshall item %s", err)
		w.Write([]byte(e))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func initAPIServer(addr string) {

	r := mux.NewRouter()

	r.HandleFunc("/api/clients/list", requestHandler).Methods(http.MethodGet)

	// Wrap our server with our gzip handler to gzip compress all responses.
	err := http.ListenAndServe(addr, handlers.LoggingHandler(os.Stdout, r))
	if err != nil {
		logger.Log(
			"level", 1,
			"action", "can not listen on",
			"addr", addr,
		)

		os.Exit(1)
	}
	return
}
