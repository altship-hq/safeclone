package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseMaven(t *testing.T) {
	dir := t.TempDir()
	pom := `<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.20</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>`
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pom), 0644); err != nil {
		t.Fatal(err)
	}
	entries := parseMaven(dir)
	if len(entries) != 1 {
		t.Fatalf("want 1 entry (test scope excluded), got %d: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.name != "org.springframework:spring-core" {
		t.Errorf("unexpected name: %q", e.name)
	}
	if e.version != "5.3.20" {
		t.Errorf("unexpected version: %q", e.version)
	}
	if e.ecosystem != "Maven" {
		t.Errorf("unexpected ecosystem: %q", e.ecosystem)
	}
}

func TestParseGemfileLock(t *testing.T) {
	dir := t.TempDir()
	lock := `GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.4)
      actionpack (= 7.0.4)
      activesupport (= 7.0.4)
    actionpack (7.0.4)
      actionview (= 7.0.4)

PLATFORMS
  ruby
`
	if err := os.WriteFile(filepath.Join(dir, "Gemfile.lock"), []byte(lock), 0644); err != nil {
		t.Fatal(err)
	}
	entries := parseGemfileLock(dir)
	if len(entries) != 2 {
		t.Fatalf("want 2 top-level gems, got %d: %+v", len(entries), entries)
	}
	byName := map[string]depEntry{}
	for _, e := range entries {
		byName[e.name] = e
	}
	if e := byName["rails"]; e.version != "7.0.4" || e.ecosystem != "RubyGems" {
		t.Errorf("unexpected rails entry: %+v", e)
	}
	if e := byName["actionpack"]; e.version != "7.0.4" {
		t.Errorf("unexpected actionpack version: %q", e.version)
	}
}

func TestParseComposer(t *testing.T) {
	dir := t.TempDir()
	composer := `{
  "require": {
    "php": "^8.0",
    "ext-json": "*",
    "laravel/framework": "^9.0"
  },
  "require-dev": {
    "phpunit/phpunit": "^9.5"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "composer.json"), []byte(composer), 0644); err != nil {
		t.Fatal(err)
	}
	entries := parseComposer(dir)
	if len(entries) != 2 {
		t.Fatalf("want 2 entries (php and ext-json skipped), got %d: %+v", len(entries), entries)
	}
	byName := map[string]depEntry{}
	for _, e := range entries {
		byName[e.name] = e
	}
	if e := byName["laravel/framework"]; e.version != "9.0" || e.ecosystem != "Packagist" {
		t.Errorf("unexpected laravel entry: %+v", e)
	}
	if e := byName["phpunit/phpunit"]; e.version != "9.5" {
		t.Errorf("unexpected phpunit version: %q", e.version)
	}
}

func TestParseNuGet_packagesConfig(t *testing.T) {
	dir := t.TempDir()
	config := `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net472" />
  <package id="log4net" version="2.0.14" targetFramework="net472" />
</packages>`
	if err := os.WriteFile(filepath.Join(dir, "packages.config"), []byte(config), 0644); err != nil {
		t.Fatal(err)
	}
	entries := parseNuGet(dir)
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d: %+v", len(entries), entries)
	}
	byName := map[string]depEntry{}
	for _, e := range entries {
		byName[e.name] = e
	}
	if e := byName["Newtonsoft.Json"]; e.version != "13.0.1" || e.ecosystem != "NuGet" {
		t.Errorf("unexpected Newtonsoft.Json entry: %+v", e)
	}
}

func TestParseNuGet_csproj(t *testing.T) {
	dir := t.TempDir()
	csproj := `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog" Version="2.12.0" />
  </ItemGroup>
</Project>`
	if err := os.WriteFile(filepath.Join(dir, "MyApp.csproj"), []byte(csproj), 0644); err != nil {
		t.Fatal(err)
	}
	entries := parseNuGet(dir)
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d: %+v", len(entries), entries)
	}
	byName := map[string]depEntry{}
	for _, e := range entries {
		byName[e.name] = e
	}
	if e := byName["Serilog"]; e.version != "2.12.0" || e.ecosystem != "NuGet" {
		t.Errorf("unexpected Serilog entry: %+v", e)
	}
}

func TestParsePubspec(t *testing.T) {
	dir := t.TempDir()
	pubspec := `name: myapp
version: 1.0.0

dependencies:
  flutter:
    sdk: flutter
  http: ^0.13.4
  provider: ^6.0.0

dev_dependencies:
  flutter_test:
    sdk: flutter
  mockito: ^5.0.0
`
	if err := os.WriteFile(filepath.Join(dir, "pubspec.yaml"), []byte(pubspec), 0644); err != nil {
		t.Fatal(err)
	}
	entries := parsePubspec(dir)
	if len(entries) != 3 {
		t.Fatalf("want 3 entries (sdk refs skipped), got %d: %+v", len(entries), entries)
	}
	byName := map[string]depEntry{}
	for _, e := range entries {
		byName[e.name] = e
	}
	if e := byName["http"]; e.version != "0.13.4" || e.ecosystem != "Pub" {
		t.Errorf("unexpected http entry: %+v", e)
	}
	if e := byName["mockito"]; e.version != "5.0.0" {
		t.Errorf("unexpected mockito version: %q", e.version)
	}
}

func TestParseMixExs(t *testing.T) {
	dir := t.TempDir()
	mix := `defmodule MyApp.MixProject do
  use Mix.Project

  defp deps do
    [
      {:phoenix, "~> 1.6.0"},
      {:ecto_sql, "~> 3.6"},
      {:postgrex, ">= 0.0.0"},
      {:jason, "~> 1.2"}
    ]
  end
end`
	if err := os.WriteFile(filepath.Join(dir, "mix.exs"), []byte(mix), 0644); err != nil {
		t.Fatal(err)
	}
	entries := parseMixExs(dir)
	if len(entries) != 4 {
		t.Fatalf("want 4 entries, got %d: %+v", len(entries), entries)
	}
	byName := map[string]depEntry{}
	for _, e := range entries {
		byName[e.name] = e
	}
	if e := byName["phoenix"]; e.version != "1.6.0" || e.ecosystem != "Hex" {
		t.Errorf("unexpected phoenix entry: %+v", e)
	}
	if e := byName["postgrex"]; e.version != "0.0.0" {
		t.Errorf("unexpected postgrex version: %q", e.version)
	}
}
