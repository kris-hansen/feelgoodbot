// Package mdscanner provides AI-assisted analysis of potentially malicious skills.
package mdscanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// AIAnalysisResult contains the AI's assessment of a skill
type AIAnalysisResult struct {
	RiskLevel       string   `json:"risk_level"`      // critical, high, medium, low, safe
	Summary         string   `json:"summary"`         // Brief description of what the skill does
	Concerns        []string `json:"concerns"`        // List of specific security concerns
	Recommendations []string `json:"recommendations"` // Suggested actions
	Explanation     string   `json:"explanation"`     // Detailed analysis
	Confidence      float64  `json:"confidence"`      // 0-1 confidence in assessment
}

// AIAnalyzer performs LLM-based analysis of skills
type AIAnalyzer struct {
	apiKey     string
	apiURL     string
	model      string
	httpClient *http.Client
}

// AIAnalyzerConfig configures the AI analyzer
type AIAnalyzerConfig struct {
	APIKey  string // Anthropic API key (defaults to ANTHROPIC_API_KEY env)
	APIURL  string // API URL (defaults to Anthropic)
	Model   string // Model to use (defaults to claude-3-haiku)
	Timeout time.Duration
}

// NewAIAnalyzer creates an AI analyzer
func NewAIAnalyzer(cfg *AIAnalyzerConfig) (*AIAnalyzer, error) {
	if cfg == nil {
		cfg = &AIAnalyzerConfig{}
	}

	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	apiURL := cfg.APIURL
	if apiURL == "" {
		apiURL = "https://api.anthropic.com/v1/messages"
	}

	model := cfg.Model
	if model == "" {
		model = "claude-3-haiku-20240307"
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	return &AIAnalyzer{
		apiKey: apiKey,
		apiURL: apiURL,
		model:  model,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// AnalyzeSkill performs AI analysis on a skill directory's contents
func (a *AIAnalyzer) AnalyzeSkill(ctx context.Context, skillContent map[string]string, staticFindings *SkillScanResult) (*AIAnalysisResult, error) {
	// Build the prompt
	prompt := buildAnalysisPrompt(skillContent, staticFindings)

	// Call the API
	response, err := a.callAPI(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("API call failed: %w", err)
	}

	// Parse the response
	result, err := parseAnalysisResponse(response)
	if err != nil {
		// If parsing fails, return a basic result with the raw response
		return &AIAnalysisResult{
			RiskLevel:   "unknown",
			Summary:     "AI analysis completed but response parsing failed",
			Explanation: response,
			Confidence:  0.5,
		}, nil
	}

	return result, nil
}

func buildAnalysisPrompt(skillContent map[string]string, staticFindings *SkillScanResult) string {
	var sb strings.Builder

	sb.WriteString(`You are a security analyst reviewing an AI agent skill for potential threats.

Analyze the following skill files and provide a security assessment. Consider:
1. What does this skill actually do?
2. Does it access sensitive data (credentials, keys, personal files)?
3. Does it make network requests to suspicious destinations?
4. Does it execute shell commands or download executables?
5. Does it use social engineering to trick users into dangerous actions?
6. Are there any obfuscation techniques (base64, unicode tricks, hidden text)?

`)

	// Add static findings if any
	if staticFindings != nil && !staticFindings.Clean {
		sb.WriteString("## Static Analysis Findings\n\n")
		sb.WriteString(fmt.Sprintf("The automated scanner found %d issues:\n\n", staticFindings.TotalIssues))

		for path, fileResult := range staticFindings.Files {
			if fileResult.Clean {
				continue
			}
			sb.WriteString(fmt.Sprintf("### %s\n", path))
			for _, f := range fileResult.Findings {
				sb.WriteString(fmt.Sprintf("- [%s] Line %d: %s\n", f.Severity, f.Line, f.Message))
				if f.Content != "" {
					sb.WriteString(fmt.Sprintf("  Content: `%s`\n", f.Content))
				}
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString("## Skill Files\n\n")

	// Add file contents
	for path, content := range skillContent {
		sb.WriteString(fmt.Sprintf("### File: %s\n\n```\n%s\n```\n\n", path, truncateForPrompt(content, 8000)))
	}

	sb.WriteString(`## Required Response Format

Respond with a JSON object (no markdown code blocks, just raw JSON):

{
  "risk_level": "critical|high|medium|low|safe",
  "summary": "One sentence describing what this skill does",
  "concerns": ["List", "of", "specific", "security", "concerns"],
  "recommendations": ["List", "of", "recommended", "actions"],
  "explanation": "Detailed paragraph explaining your assessment",
  "confidence": 0.85
}

Be concise but thorough. If the skill appears safe, say so. If it's dangerous, explain exactly why.`)

	return sb.String()
}

func truncateForPrompt(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... [truncated]"
}

func (a *AIAnalyzer) callAPI(ctx context.Context, prompt string) (string, error) {
	reqBody := map[string]interface{}{
		"model":      a.model,
		"max_tokens": 2048,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse Anthropic response
	var apiResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(apiResp.Content) == 0 {
		return "", fmt.Errorf("empty response from API")
	}

	return apiResp.Content[0].Text, nil
}

func parseAnalysisResponse(response string) (*AIAnalysisResult, error) {
	// Clean up the response - remove any markdown code blocks if present
	response = strings.TrimSpace(response)
	response = strings.TrimPrefix(response, "```json")
	response = strings.TrimPrefix(response, "```")
	response = strings.TrimSuffix(response, "```")
	response = strings.TrimSpace(response)

	var result AIAnalysisResult
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Validate
	validLevels := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "safe": true,
	}
	if !validLevels[result.RiskLevel] {
		result.RiskLevel = "unknown"
	}

	if result.Confidence < 0 || result.Confidence > 1 {
		result.Confidence = 0.5
	}

	return &result, nil
}

// FormatAIResult returns a human-readable version of the AI analysis
func FormatAIResult(r *AIAnalysisResult) string {
	var sb strings.Builder

	// Risk level with emoji
	emoji := "❓"
	switch r.RiskLevel {
	case "critical":
		emoji = "🚨"
	case "high":
		emoji = "🔴"
	case "medium":
		emoji = "🟡"
	case "low":
		emoji = "🟢"
	case "safe":
		emoji = "✅"
	}

	sb.WriteString(fmt.Sprintf("\n%s AI Risk Assessment: %s (confidence: %.0f%%)\n\n",
		emoji, strings.ToUpper(r.RiskLevel), r.Confidence*100))

	sb.WriteString(fmt.Sprintf("**Summary:** %s\n\n", r.Summary))

	if len(r.Concerns) > 0 {
		sb.WriteString("**Security Concerns:**\n")
		for _, c := range r.Concerns {
			sb.WriteString(fmt.Sprintf("  • %s\n", c))
		}
		sb.WriteString("\n")
	}

	if len(r.Recommendations) > 0 {
		sb.WriteString("**Recommendations:**\n")
		for _, rec := range r.Recommendations {
			sb.WriteString(fmt.Sprintf("  → %s\n", rec))
		}
		sb.WriteString("\n")
	}

	if r.Explanation != "" {
		sb.WriteString(fmt.Sprintf("**Analysis:**\n%s\n", r.Explanation))
	}

	return sb.String()
}

// ReadSkillFiles reads all relevant files from a skill directory for AI analysis
func ReadSkillFiles(skillPath string, maxTotalSize int64) (map[string]string, error) {
	files := make(map[string]string)
	var totalSize int64

	// Walk the directory
	entries, err := os.ReadDir(skillPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Only read relevant files
		if !isRelevantFile(name) {
			continue
		}

		path := skillPath + "/" + name
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Skip files that are too large
		if info.Size() > 100*1024 { // 100KB per file max
			continue
		}

		// Check total size limit
		if totalSize+info.Size() > maxTotalSize {
			break
		}

		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		files[name] = string(content)
		totalSize += info.Size()
	}

	return files, nil
}

func isRelevantFile(name string) bool {
	relevantFiles := []string{
		"SKILL.md", "README.md", "INSTALL.md", "SETUP.md",
	}
	for _, rf := range relevantFiles {
		if strings.EqualFold(name, rf) {
			return true
		}
	}

	relevantExts := []string{
		".md", ".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".rb", ".pl",
	}
	for _, ext := range relevantExts {
		if strings.HasSuffix(strings.ToLower(name), ext) {
			return true
		}
	}

	return false
}
