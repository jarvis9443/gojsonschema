package gojsonschema

import (
	"strings"
	"testing"
)

func isSecretRef(value interface{}, schemaType string) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	if !strings.HasPrefix(s, "$secret://") && !strings.HasPrefix(s, "$env://") {
		return false
	}
	if schemaType != "" && schemaType != "string" {
		return false
	}
	return true
}

func TestSkipValidation_StringEnumBypass(t *testing.T) {
	schema := `{
"type": "object",
"properties": {
"scheme": {"type": "string", "enum": ["http", "https"]}
}
}`
	sl := NewSchemaLoader()
	sl.SkipValidation = isSecretRef
	s, err := sl.Compile(NewStringLoader(schema))
	if err != nil {
		t.Fatal(err)
	}

	result, err := s.Validate(NewGoLoader(map[string]interface{}{"scheme": "$secret://vault/scheme"}))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid() {
		t.Errorf("expected valid, got errors: %v", result.Errors())
	}

	result, err = s.Validate(NewGoLoader(map[string]interface{}{"scheme": "ftp"}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid() {
		t.Error("expected invalid for non-secret bad enum value")
	}
}

func TestSkipValidation_IntegerFieldNotBypassed(t *testing.T) {
	schema := `{
"type": "object",
"properties": {
"port": {"type": "integer"}
}
}`
	sl := NewSchemaLoader()
	sl.SkipValidation = isSecretRef
	s, err := sl.Compile(NewStringLoader(schema))
	if err != nil {
		t.Fatal(err)
	}

	result, err := s.Validate(NewGoLoader(map[string]interface{}{"port": "$secret://vault/port"}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid() {
		t.Error("expected invalid: secret ref in integer field should not bypass")
	}
}

func TestSkipValidation_StringPatternBypass(t *testing.T) {
	schema := `{
"type": "object",
"properties": {
"host": {"type": "string", "pattern": "^[a-z]+\\.com$"}
}
}`
	sl := NewSchemaLoader()
	sl.SkipValidation = isSecretRef
	s, err := sl.Compile(NewStringLoader(schema))
	if err != nil {
		t.Fatal(err)
	}

	result, err := s.Validate(NewGoLoader(map[string]interface{}{"host": "$secret://vault/host"}))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid() {
		t.Errorf("expected valid, got errors: %v", result.Errors())
	}
}

func TestSkipValidation_NestedObject(t *testing.T) {
	schema := `{
"type": "object",
"properties": {
"upstream": {
"type": "object",
"properties": {
"host": {"type": "string", "pattern": "^[a-z0-9.-]+$"},
"port": {"type": "string", "pattern": "^[0-9]+$"}
},
"required": ["host"]
}
}
}`
	sl := NewSchemaLoader()
	sl.SkipValidation = isSecretRef
	s, err := sl.Compile(NewStringLoader(schema))
	if err != nil {
		t.Fatal(err)
	}

	result, err := s.Validate(NewGoLoader(map[string]interface{}{
		"upstream": map[string]interface{}{
			"host": "$secret://vault/host",
			"port": "$env://PORT",
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid() {
		t.Errorf("expected valid, got errors: %v", result.Errors())
	}

	// Without hook, the pattern would reject secret refs
	s2, err := NewSchema(NewStringLoader(schema))
	if err != nil {
		t.Fatal(err)
	}
	result, err = s2.Validate(NewGoLoader(map[string]interface{}{
		"upstream": map[string]interface{}{
			"host": "$secret://vault/host",
			"port": "$env://PORT",
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid() {
		t.Error("expected invalid without skip_validation: pattern should reject secret refs")
	}
}

func TestSkipValidation_NotConfigured(t *testing.T) {
	schema := `{
"type": "object",
"properties": {
"port": {"type": "integer"}
}
}`
	s, err := NewSchema(NewStringLoader(schema))
	if err != nil {
		t.Fatal(err)
	}

	result, err := s.Validate(NewGoLoader(map[string]interface{}{"port": "$secret://vault/port"}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid() {
		t.Error("expected invalid without skip_validation configured")
	}
}

func TestSkipValidation_UntypedFieldWithConstraint(t *testing.T) {
	// An untyped field with format constraint — secret ref should bypass
	schema := `{
"type": "object",
"properties": {
"config": {"format": "ipv4"}
}
}`
	sl := NewSchemaLoader()
	sl.SkipValidation = isSecretRef
	s, err := sl.Compile(NewStringLoader(schema))
	if err != nil {
		t.Fatal(err)
	}

	result, err := s.Validate(NewGoLoader(map[string]interface{}{"config": "$secret://vault/config"}))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid() {
		t.Errorf("expected valid for untyped field with secret ref, got errors: %v", result.Errors())
	}

	// Without the hook, the format check would reject the secret ref
	s2, err := NewSchema(NewStringLoader(schema))
	if err != nil {
		t.Fatal(err)
	}
	result, err = s2.Validate(NewGoLoader(map[string]interface{}{"config": "$secret://vault/config"}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid() {
		t.Error("expected invalid without skip_validation: format check should reject non-ipv4")
	}
}

func TestSkipValidation_MultiTypeField(t *testing.T) {
	// Multi-type field ["string", "integer"] — schemaType will be "string,integer"
	// Our hook checks schemaType != "string", so multi-type is NOT bypassed (conservative)
	schema := `{
"type": "object",
"properties": {
"value": {"type": ["string", "integer"], "enum": [1, 2, "a"]}
}
}`
	sl := NewSchemaLoader()
	sl.SkipValidation = isSecretRef
	s, err := sl.Compile(NewStringLoader(schema))
	if err != nil {
		t.Fatal(err)
	}

	result, err := s.Validate(NewGoLoader(map[string]interface{}{"value": "$secret://vault/val"}))
	if err != nil {
		t.Fatal(err)
	}
	// Multi-type "string,integer" != "string", so hook returns false, enum check fires
	if result.Valid() {
		t.Error("expected invalid: multi-type field should not bypass with simple schemaType check")
	}
}
