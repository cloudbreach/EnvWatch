# Scan everything (default)
go run envwatch.go

# Only .env files
go run envwatch.go --env

# Only YAML
go run envwatch.go --yaml

# Only keys
go run envwatch.go --keys

# Only AWS
go run envwatch.go --aws

# Skip filesystem (only env + aws)
go run envwatch.go --no-system

# Show secrets
go run envwatch.go --show-secrets