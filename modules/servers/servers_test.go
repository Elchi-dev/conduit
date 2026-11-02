package servers

import "testing"

func TestParsers(t *testing.T) {
	st := parseStatus("hostname=web-2\nuptime=7200.5\nload=0.10 0.20 0.30\ncpus=4\nmemTotalKB=8388608\nmemAvailKB=4194304\ndisk=/,104857600,52428800\n")
	if st["hostname"] != "web-2" || st["uptimeHours"] != 2.0 || st["cpus"] != 4 {
		t.Fatalf("status = %+v", st)
	}
	mem := st["memory"].(map[string]any)
	if mem["percent"] != 50.0 || mem["totalGB"] != 8.0 {
		t.Fatalf("memory = %+v", mem)
	}
	units := parseUnits("nginx.service loaded active running A high performance web server\n● bad.service loaded failed failed Broken thing\n")
	if len(units) != 2 || units[0].Name != "nginx" || units[1].Active != "failed" || units[0].Description != "A high performance web server" {
		t.Fatalf("units = %+v", units)
	}
	ls := parseLS("total 8\ndrwxr-xr-x 2 root root 4096 2026-11-03T01:00 .\n-rw-r--r-- 1 root root 12 2026-11-03T01:00 my file.txt\n")
	if len(ls) != 1 || ls[0].Name != "my file.txt" || ls[0].Size != 12 || ls[0].Type != "file" {
		t.Fatalf("ls = %+v", ls)
	}
	if !unitRe.MatchString("nginx.service") || unitRe.MatchString("x; rm -rf /") {
		t.Fatal("unit name validation")
	}
}
