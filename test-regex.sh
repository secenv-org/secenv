#!/bin/bash
test_match() {
  echo "$1" | grep -E '(^|/)\.env($|\.)' | grep -vE '\.(example|sample|template)$' > /dev/null
  if [ $? -eq 0 ]; then echo "MATCHED: $1"; else echo "ALLOWED: $1"; fi
}
test_match ".env"
test_match "foo/.env"
test_match ".env.local"
test_match "foo/.env.development"
test_match ".secenvs"
test_match "api.env.ts"
test_match "config/api.env.ts"
test_match ".env.example"
test_match ".env.sample"
test_match ".envrc"
test_match "my app/.env"
test_match ".env.test"
