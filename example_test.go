package clamav_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	clamav "github.com/PyYoshi/go-clamav"
)

// The canonical fail-closed usage: any error means the file must not be
// accepted — an unreachable or overloaded scanner never lets a file through.
func ExampleClient_Scan() {
	client, err := clamav.New("unix:///run/clamav/clamd.sock",
		clamav.WithMaxStreamSize(25<<20), // keep equal to clamd's StreamMaxLength
	)
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.Open("/uploads/pending/document.pdf")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result, err := client.Scan(ctx, f)
	switch {
	case err != nil:
		// UNKNOWN verdict: reject or retry (see IsRetryable). Never accept.
		fmt.Println("scan failed, rejecting upload:", err)
	case result.Infected():
		fmt.Println("malware detected, quarantining:", result.Signature)
	default:
		fmt.Println("clean, accepting upload")
	}
}

// Ping doubles as a readiness probe for the scanning dependency.
func ExampleClient_Ping() {
	client, err := clamav.New("tcp://127.0.0.1:3310")
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx); err != nil {
		fmt.Println("clamd not ready:", err)
	}
}
