package chat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"threatlens/internal/models"
)

const openRouterURL = "https://openrouter.ai/api/v1/chat/completions"

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Request struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Stream   bool      `json:"stream"`
}

type Response struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
}

type Chat struct {
	apiKey  string
	model   string
	history []Message
}

func New(apiKey, model string) *Chat {
	return &Chat{
		apiKey: apiKey,
		model:  model,
		history: []Message{
			{
				Role: "system",
				Content: `You are a cybersecurity analyst assistant. 
You will be given detection logs from a Windows host security scanner.
Answer questions about the logs in plain English for non-technical users.
Be concise, clear, and highlight what matters most.`,
			},
		},
	}
}

func (c *Chat) LoadContext(detections []models.Detection) {
	if len(detections) == 0 {
		return
	}

	var buf bytes.Buffer
	buf.WriteString("Here are the security scan results:\n\n")
	for _, d := range detections {
		buf.WriteString(fmt.Sprintf("[%s] %s (Severity: %d)\n", d.Timestamp, d.Title, d.Severity))
		buf.WriteString(fmt.Sprintf("  MITRE: %s\n", d.MitreID))
		buf.WriteString(fmt.Sprintf("  Evidence: %s\n\n", d.Evidence))
	}

	c.history = append(c.history, Message{
		Role:    "user",
		Content: buf.String(),
	})

	c.history = append(c.history, Message{
		Role:    "assistant",
		Content: "I've reviewed the scan results. What would you like to know?",
	})
}

func (c *Chat) Ask(question string) (string, error) {
	c.history = append(c.history, Message{
		Role:    "user",
		Content: question,
	})

	reqBody, err := json.Marshal(Request{
		Model:    c.model,
		Messages: c.history,
		Stream:   false,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", openRouterURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	fmt.Println("DEBUG:", string(body))

	var result Response
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("no response from model")
	}

	answer := result.Choices[0].Message.Content
	c.history = append(c.history, Message{
		Role:    "assistant",
		Content: answer,
	})

	return answer, nil
}
