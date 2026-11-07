# Contributing to Atlas

Thanks for helping improve Atlas.

## Workflow
1. Create a focused branch from `main`.
2. Keep changes small and explain their purpose in the pull request.
3. Add or update tests for behavior changes.
4. Run the checks below before opening a pull request.

## Required checks
```sh
go test ./...
go test -cover ./...
go vet ./...
```

Pull requests should describe the behavior changed, note any API or configuration impact, and include relevant test results. Do not include credentials, customer data, or generated build artifacts.
