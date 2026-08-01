package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writePanelFixture(t *testing.T) (*PanelConfigService, string) {
	t.Helper()
	dir := t.TempDir()
	workDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(workDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "basepath"), []byte("Safe_Path-123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "password"), []byte("secret-password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(dir, "panel.env")
	env := "WEB_PORT=24567\nMAX_EXITS=12\nPANEL_DOMAIN=hy2.example.com\n"
	if err := os.WriteFile(envFile, []byte(env), 0600); err != nil {
		t.Fatal(err)
	}
	return NewPanelConfigService(workDir, envFile, filepath.Join(dir, "unused"), "unused"), workDir
}

func TestPanelConfigLoadDoesNotExposePassword(t *testing.T) {
	service, _ := writePanelFixture(t)
	config, err := service.Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.Domain != "hy2.example.com" || config.Port != 24567 || config.MaxExits != 12 || config.Path != "Safe_Path-123" {
		t.Fatalf("unexpected panel config: %#v", config)
	}
	if !config.PasswordConfigured || config.NewPassword != "" {
		t.Fatalf("password state leaked or missing: %#v", config)
	}
}

func TestPanelConfigRejectsInvalidValuesBeforeWriting(t *testing.T) {
	service, workDir := writePanelFixture(t)
	for name, config := range map[string]PanelConfig{
		"low port":  {Port: 443, Path: "valid-path", MaxExits: 12},
		"bad path":  {Port: 24567, Path: "../../etc", MaxExits: 12},
		"max exits": {Port: 24567, Path: "valid-path", MaxExits: 201},
		"password":  {Port: 24567, Path: "valid-path", MaxExits: 12, NewPassword: "short"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.Apply(config); err == nil {
				t.Fatal("invalid panel configuration was accepted")
			}
		})
	}
	data, err := os.ReadFile(filepath.Join(workDir, "basepath"))
	if err != nil || string(data) != "Safe_Path-123\n" {
		t.Fatalf("invalid request modified state: %q, %v", data, err)
	}
}
