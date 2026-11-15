package bench

import (
	"context"
	"testing"

	"github.com/redfilade/redfilade/internal/pg"
	"github.com/redfilade/redfilade/internal/pg/pgtest"
)

func TestMigrationsAndTenancy(t *testing.T) {
	ctx := context.Background()
	c, err := pg.Connect(ctx, pgtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	applied, err := Migrate(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) < 2 || applied[0] != "0001_tenancy" || applied[1] != "0002_bench" {
		t.Fatalf("applied %v", applied)
	}
	again, err := Migrate(ctx, c)
	if err != nil || len(again) != 0 {
		t.Fatalf("second run applied %v (%v)", again, err)
	}
	if err := TenancyTest(ctx, c); err != nil {
		t.Fatalf("tenancy test: %v", err)
	}
}
