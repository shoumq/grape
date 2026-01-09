package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type SMSSender interface {
	Send(ctx context.Context, phone, message string) error
}

type SMSRUSender struct {
	apiID     string
	sender    string
	client    *http.Client
	baseURL   string
	sendRoute string
}

func NewSMSRUSender(apiID, sender string) *SMSRUSender {
	return &SMSRUSender{
		apiID:     strings.TrimSpace(apiID),
		sender:    strings.TrimSpace(sender),
		client:    &http.Client{Timeout: 10 * time.Second},
		baseURL:   "https://Каким образом получатели дали вам согласие рассылку?",
		sendRoute: "/sms/send",
	}
}

func (s *SMSRUSender) Send(ctx context.Context, phone, message string) error {
	if s == nil || s.apiID == "" {
		return ErrSMSNotConfigured
	}
	form := url.Values{}
	form.Set("api_id", s.apiID)
	form.Set("to", phone)
	form.Set("msg", message)
	if s.sender != "" {
		form.Set("from", s.sender)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+s.sendRoute, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	lines := strings.SplitN(string(body), "\n", 2)
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "100" {
		return fmt.Errorf("sms.ru error: %s", strings.TrimSpace(lines[0]))
	}
	return nil
}
