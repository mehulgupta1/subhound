package main

// Exercises the real chunked pushResults against the live cloud with a fake
// alive.json of N hosts. Run:
//   PUSH_URL=.../ingest PUSH_KEY=sh_... PUSH_DOM=pt.example.com N=10000 \
//     go test -run TestPushChunked -v
import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPushChunked(t *testing.T) {
	url, key, dom := os.Getenv("PUSH_URL"), os.Getenv("PUSH_KEY"), os.Getenv("PUSH_DOM")
	if url == "" || key == "" || dom == "" {
		t.Skip("set PUSH_URL/PUSH_KEY/PUSH_DOM to run")
	}
	n := 10000
	if v := os.Getenv("N"); v != "" {
		fmt.Sscanf(v, "%d", &n)
	}

	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "alive.json"))
	if err != nil {
		t.Fatal(err)
	}
	statuses := []int{200, 301, 302, 403, 404}
	techs := [][]string{{"nginx", "PHP"}, {"HSTS", "Varnish"}, {"React", "AWS"}}
	for i := 0; i < n; i++ {
		host := fmt.Sprintf("h%06d.%s", i, dom)
		rec := map[string]any{
			"input": host, "host": host,
			"status_code": statuses[i%5], "title": fmt.Sprintf("Host %d", i),
			"tech": techs[i%3], "a": []string{fmt.Sprintf("10.%d.%d.1", i%256, (i/256)%256)},
			"webserver": "nginx", "scheme": "https", "port": "443",
		}
		b, _ := json.Marshal(rec)
		f.Write(b)
		f.Write([]byte("\n"))
	}
	f.Close()

	t0 := time.Now()
	ok := pushResults(config{}, dom, dir, url, key)
	dt := time.Since(t0)
	if !ok {
		t.Fatalf("push of %d hosts FAILED", n)
	}
	fmt.Printf("RESULT: pushed %d hosts in %.2fs (%.0f hosts/s, %d chunks)\n",
		n, dt.Seconds(), float64(n)/dt.Seconds(), (n+pushChunk-1)/pushChunk)
}
