# Main
cmd/kube-apiserver/apiserver.go

```go
func main() {
	rand.Seed(time.Now().UnixNano())
	
	// 
	command := app.NewAPIServerCommand()
	logs.InitLogs()
	// make sure logs are always recorded even apiserver crash
	defer logs.FlushLogs()

	if err := command.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
```