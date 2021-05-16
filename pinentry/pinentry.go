package pinentry

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"time"

	assuan "github.com/foxcpp/go-assuan/client"
	"github.com/foxcpp/go-assuan/pinentry"
)

func New() *Pinentry {
	return &Pinentry{}
}

type Pinentry struct {
	mu            sync.Mutex
	activeRequest *request
}

type request struct {
	timeout       time.Duration
	pendingResult chan Result
	extendTimeout chan time.Duration

	challengeParam   [32]byte
	applicationParam [32]byte
}

type Result struct {
	OK    bool
	Error error
}

func (pe *Pinentry) ConfirmPresence(prompt string, challengeParam, applicationParam [32]byte) (chan Result, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	timeout := 2 * time.Second

	if pe.activeRequest != nil {
		if challengeParam != pe.activeRequest.challengeParam || applicationParam != pe.activeRequest.applicationParam {
			return nil, errors.New("other request already in progress")
		}

		pe.activeRequest.extendTimeout <- timeout

		return pe.activeRequest.pendingResult, nil
	}

	pe.activeRequest = &request{
		timeout:          timeout,
		challengeParam:   challengeParam,
		applicationParam: applicationParam,
		pendingResult:    make(chan Result),
		extendTimeout:    make(chan time.Duration),
	}

	go pe.prompt(pe.activeRequest, prompt)

	return pe.activeRequest.pendingResult, nil
}

func (pe *Pinentry) prompt(req *request, prompt string) {

	sendResult := func(r Result) {
		pe.mu.Lock()
		pe.activeRequest = nil
		pe.mu.Unlock()

		req.pendingResult <- r
	}

	childCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := launchPinEntry(childCtx)
	if err != nil {
		sendResult(Result{
			OK:    false,
			Error: fmt.Errorf("failed to start pinentry: %w", err),
		})
		return
	}

	defer p.Shutdown()
	p.SetTitle("TPM-FIDO")
	p.SetPrompt("TPM-FIDO")
	p.SetDesc(prompt)

	promptResult := make(chan bool)

	go func() {
		err := p.Confirm()
		promptResult <- err == nil
	}()

	timer := time.NewTimer(req.timeout)

	for {
		select {
		case ok := <-promptResult:
			sendResult(Result{
				OK: ok,
			})
			return
		case <-timer.C:
			sendResult(Result{
				OK:    false,
				Error: errors.New("request timed out"),
			})
			return
		case d := <-req.extendTimeout:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(d)
		}
	}
}

func launchPinEntry(ctx context.Context) (*pinentry.Client, error) {
	cmd := exec.CommandContext(ctx, "pinentry")

	var c pinentry.Client
	var err error
	c.Session, err = assuan.InitCmd(cmd)
	if err != nil {
		return nil, err
	}
	return &c, nil
}
