package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseGlobalOptions(t *testing.T) {
	o, err := parse([]string{"--path", "/removesky", "--shared-path=", "--admin", "run", "--", "python", "-m", "x"})
	if err != nil {
		t.Fatal(err)
	}
	if o.path != "/removesky" || o.sharedPath == nil || *o.sharedPath != "" || !o.admin || o.command != "run" {
		t.Fatalf("%+v", o)
	}
	if !reflect.DeepEqual(o.args, []string{"--", "python", "-m", "x"}) {
		t.Fatal(o.args)
	}
	if o, _ := parse([]string{"get", "X"}); o.sharedPath != nil {
		t.Fatal("shared path should be unset (use config)")
	}
	for _, bad := range [][]string{{}, {"--bogus", "list"}, {"--path"}} {
		if _, err := parse(bad); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}

func TestMergeEnvSecretsWinWithoutDuplicates(t *testing.T) {
	got := mergeEnv([]string{"PATH=/bin", "TOKEN=old", "X=1"}, map[string]string{"TOKEN": "new", "B": "2"})
	want := []string{"PATH=/bin", "X=1", "B=2", "TOKEN=new"}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}

func TestMissingBootstrapExitsTwo(t *testing.T) {
	t.Setenv("INFISICAL_ADDR", "")
	var out strings.Builder
	if code := run([]string{"list"}, strings.NewReader(""), &out); code != 2 {
		t.Fatal(code)
	}
}
